# IronWarden Tiered Deployment Architecture & Native Kubernetes Operator Specification

**Document Version:** 1.0.0  
**Target Releases:** IronWarden Core & Gateway v0.9.0+  
**Architecture Issues:** #97 (`[Architecture] Define Tiered Deployment Models (Standalone vs. Enterprise HA)`), #98 (`[Scaling] Native Kubernetes Operator for Auto-Scaling Bridge Nodes`)  
**Status:** Canonical Design & Architecture Reference

---

## Executive Summary

IronWarden provides privacy-preserving, cryptographically verifiable security enclaves for Large Language Model (LLM) tooling and agentic systems. To bridge the gap between high-security air-gapped developer environments and high-throughput enterprise infrastructure, IronWarden defines two formal deployment tiers:

1. **Sovereign Standalone**: A zero-dependency, single-binary deployment utilizing local SQLite databases in Write-Ahead Logging (`WAL`) mode, node-local ONNX inference, and Stdio/Localhost loopback transport.
2. **Enterprise Clustered High Availability (HA)**: A horizontally scalable, multi-pod Kubernetes architecture backed by Redis (session state and grounding queue), PostgreSQL or remote SIEM endpoints (tamper-evident audit ledger), and coordinated via a native Kubernetes Operator (`IronWardenBridge`).

This specification establishes the deployment profiles, data sovereignty boundaries, distributed cryptographic hash chain guarantees, database migration DDL, and complete Kubernetes Operator specifications.

---

## 1. Deployment Tiers: Standalone vs. Enterprise Clustered HA

```
+----------------------------------------------------------------------------------------------------+
|                                      IRONWARDEN DEPLOYMENTS                                        |
+-------------------------------------------------+--------------------------------------------------+
|               SOVEREIGN STANDALONE              |              ENTERPRISE CLUSTERED HA             |
+-------------------------------------------------+--------------------------------------------------+
|  [Dev Laptop / Air-Gapped Edge Enclave]         |  [Kubernetes Cluster: EKS / GKE / OpenShift]    |
|                                                 |                                                  |
|   +-----------------------------------------+   |          Ingress / API Gateway (TLS / mTLS)      |
|   |          IronWarden Gateway             |   |                         │                        |
|   |  - Stdio / Unix Domain Socket / Loopback|   |        ┌────────────────┼────────────────┐       |
|   |  - Node-Local ONNX Model (CPU/Metal)    |   |        ▼                ▼                ▼       |
|   |  - In-Memory AadCipher Session Manager  |   |   ┌─────────┐      ┌─────────┐      ┌─────────┐  |
|   |  - MCP Semaphore Permits = 4            |   |   |Bridge #1|      |Bridge #2|      |Bridge #N|  |
|   +--------------------+--------------------+   |   └────┬────┘      └────┬────┘      └────┬────┘  |
|                        │                        |        │                │                │       |
|            Local NVMe / POSIX FS                |        └────────────────┼────────────────┘       |
|            (WAL, NORMAL, secure_delete)         |                         ▼                        |
|                        │                        |   +──────────────────────────────────────────+   |
|   +────────────────────┴────────────────────+   |   |         Shared Enterprise Tier           |   |
|   |  audit.db | sessions.db | grounding.db  |   |   | - Redis Cluster (Encrypted Sessions/Q)   |   |
|   +-----------------------------------------+   |   | - PostgreSQL 15+ / SIEM (HMAC Subchains) |   |
|                                                 |   | - Vault / KMS (Node Pepper Distribution) |   |
|                                                 |   +------------------------------------------+   |
+-------------------------------------------------+--------------------------------------------------+
```

### 1.1 Architectural Comparison Matrix

| Architectural Dimension | Sovereign Standalone | Enterprise Clustered HA |
| :--- | :--- | :--- |
| **Primary Target** | Local developer laptops, CLI agents, air-gapped enclaves | Multi-tenant production clusters, enterprise API gateways |
| **High Availability** | Single Process (Self-healing via local systemd or Docker) | Multi-replica active-active with automated failover ($N+1$) |
| **Transport Protocol** | Stdio (`stdin`/`stdout`), Localhost HTTP (`127.0.0.1:14141`) | Kubernetes ClusterIP / Ingress with TLS 1.3 & mTLS |
| **Concurrency Gating** | `MCP_SEMAPHORE_PERMITS=4` (Fixed local CPU bound) | Configurable `MCP_SEMAPHORE_PERMITS` (1-128) tuned via HPA |
| **Session State** | In-Memory `DashMap` + Local SQLite WAL | In-Memory `DashMap` (L1) + Redis Cluster (L2, AAD Encrypted) |
| **Grounding Queue** | In-Memory `flume` channel + Local SQLite | Distributed Redis Stream / List Queue (`LPUSH`/`BRPOP`) |
| **Audit Ledger** | Monolithic linear HMAC-SHA256 chain in SQLite | Node-bound HKDF subchains in PostgreSQL / Enterprise SIEM |
| **Pepper Storage** | Environment variable / Local secret file | Injected Kubernetes Secret / Vault KMS CSI Driver |
| **Resource Profile** | 1–2 vCPUs, 512MB–2GB RAM, Local SSD | 2–8 vCPUs, 4GB–16GB RAM per Pod (HPA scaled: 2 to 50 pods) |

### 1.2 `GlobalConfig` Configuration Switches

The IronWarden configurator (`warden/src/configurator.rs`) enforces strict configuration contracts via the following environment and manifest switches:

```yaml
# config.yaml (Reference Configuration)
deployment_tier: "enterprise_ha" # "standalone" | "enterprise_ha" | "clustered"
bridge_addr: "0.0.0.0"
bridge_port: "14141"
warden_mode: "hybrid"

# Clustered / HA Infrastructure Backends
redis_url: "rediss://:strong_password@redis-cluster.database.svc.cluster.local:6379/0"
database_url: "postgresql://ironwarden_admin:strong_password@postgres-ha.database.svc.cluster.local:5432/ironwarden?sslmode=verify-full"
remote_audit_endpoint: "https://siem-collector.internal.corp/api/v1/audit"
remote_audit_token: "enc:vault:audit-token-key"
```

#### Validation Enforcement Rules
1. **`DEPLOYMENT_TIER`**: Must resolve to `"standalone"`, `"enterprise_ha"`, or `"clustered"`. Any other string terminates initialization with `SovereignError::ConfigError`.
2. **`REDIS_URL`**: When `deployment_tier` is `"enterprise_ha"` or `"clustered"`, `REDIS_URL` is mandatory and must begin with `redis://` or `rediss://`. Failure halts the bridge pod during pre-flight checks.
3. **`DATABASE_URL`**: When supplied, must begin with `postgres://` or `postgresql://`.
4. **Audit Durability Guarantee**: For `"enterprise_ha"`, the configuration validator enforces that at least one clustered audit sink is present: either `database_url` (PostgreSQL) or `remote_audit_endpoint` (SIEM webhook).

---

## 2. SQLite WAL Ceiling & PostgreSQL Migration Strategy

### 2.1 The SQLite WAL Concurrency Ceiling

In the Sovereign Standalone profile, IronWarden configures SQLite connections with:
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA secure_delete = ON;
PRAGMA busy_timeout = 10000;
```

#### The Bottleneck
- **Single-Writer Lock**: SQLite in WAL mode permits concurrent readers without blocking, but it strictly serializes writes to a single process thread across the entire database file.
- **Physical Throughput Limit**: Benchmarks on NVMe SSDs demonstrate that SQLite WAL with `synchronous = NORMAL` tops out at **2,500 to 5,000 write transactions per second** (tx/s) depending on payload size and `fsync` grouping.
- **Distributed Invalidation**: POSIX file locks (`fcntl`) over distributed network filesystems (NFSv4, AWS EFS, Azure Files) are notoriously prone to silent lock dropping, clock drift, and corruption under high write contention. Clustered bridge pods **must never mount a shared SQLite volume**.

### 2.2 PostgreSQL High-Throughput DDL Schema

When operating in `enterprise_ha` mode, SQLite tables (`audit_reports`, `ephemeral_raw_logs`, `search_jobs`, and `sessions`) migrate to PostgreSQL 15+.

```sql
-- ============================================================================
-- IronWarden Enterprise PostgreSQL Migration DDL
-- Compatibility: PostgreSQL 14+
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. AUDIT REPORTS & TAMPER-EVIDENT LEDGER
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_reports (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    node_id VARCHAR(64) NOT NULL,
    subchain_seq BIGINT NOT NULL,
    username VARCHAR(255) NOT NULL DEFAULT 'unknown',
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    redactions_json JSONB,
    payload_hash VARCHAR(64) NOT NULL,
    prev_integrity_hash VARCHAR(64) NOT NULL,
    integrity_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_audit_node_sequence UNIQUE (node_id, subchain_seq)
);

CREATE INDEX IF NOT EXISTS idx_audit_reports_timestamp 
    ON audit_reports (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_reports_username 
    ON audit_reports (username);
CREATE INDEX IF NOT EXISTS idx_audit_reports_blocked 
    ON audit_reports (is_blocked) WHERE is_blocked = TRUE;
CREATE INDEX IF NOT EXISTS idx_audit_reports_node_seq 
    ON audit_reports (node_id, subchain_seq DESC);

-- ----------------------------------------------------------------------------
-- 2. EPHEMERAL RAW LOGS (Short Retention / SIEM Offloading)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ephemeral_raw_logs (
    id BIGINT PRIMARY KEY REFERENCES audit_reports(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(255) NOT NULL DEFAULT 'unknown',
    encrypted_data BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    siem_acked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_ephemeral_siem_pending 
    ON ephemeral_raw_logs (siem_acked) WHERE siem_acked = FALSE;

-- ----------------------------------------------------------------------------
-- 3. SEARCHBOOST / GROUNDING JOBS
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS search_jobs (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    thread_id VARCHAR(128) NOT NULL,
    query BYTEA NOT NULL,
    sealed_query BYTEA,
    result BYTEA,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_search_jobs_status 
    ON search_jobs (status, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_search_jobs_user_thread 
    ON search_jobs (username, thread_id);

-- ----------------------------------------------------------------------------
-- 4. USER SESSION CACHE
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    username VARCHAR(255) PRIMARY KEY,
    session_data JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_updated_at 
    ON sessions (updated_at);
```

### 2.3 Zero-Downtime Data Cutover Strategy

1. **Pre-Migration Sync (Read-Only Copy)**:
   Extract all existing SQLite records from standalone nodes using an exported dump script (`rusqlite` streaming cursor into PostgreSQL `COPY` batch stream).
2. **Dual-Write Activation**:
   Bridge nodes deploy in dual-write mode: read session data from Redis/PostgreSQL, write audit records simultaneously to local backup and central PostgreSQL.
3. **Sequence Reconciliation**:
   The standalone genesis hash is registered as the node's initial anchor in the PostgreSQL `audit_epoch_anchors` table.
4. **Traffic Cutover**:
   Kubernetes Ingress redirects all agent traffic from standalone nodes to the HA ClusterIP service.

---

## 3. Distributed HA Audit Vault & HMAC Chain Integrity

### 3.1 The Distributed Hash Chain Concurrency Dilemma

In the standalone architecture, `AsyncAuditor` computes a strictly linear HMAC-SHA256 hash chain:
$$\text{Hash}_n = \text{HMAC}_{K}(\text{Hash}_{n-1} \parallel \text{Payload}_n)$$

If multiple stateless bridge pods write directly to a shared database or log stream, calculating a single global linear chain requires acquiring a distributed lock on every request. This distributed synchronization introduces network round-trips ($\sim 5\text{ms} - 20\text{ms}$) on every LLM prompt, entirely collapsing horizontal scalability.

### 3.2 The Solution: Per-Pod HKDF Sub-Chains & Sequence Anchoring

IronWarden implements a cryptographically sound, horizontally scalable hash ledger based on **Per-Pod HKDF Sub-Chains**:

```
+-----------------------------------------------------------------------------+
|                     WARDEN_PEPPER (Cluster-Wide Master Key)                |
+--------------------------------------+--------------------------------------+
                                       │
                      HKDF-Expand(PRK=Pepper, info="node_id")
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
       Pod #1 Key                 Pod #2 Key                 Pod #N Key
     K_node1 (32 bytes)         K_node2 (32 bytes)         K_nodeN (32 bytes)
            │                          │                          │
            ▼                          ▼                          ▼
   +------------------+       +------------------+       +------------------+
   |  Subchain #1     |       |  Subchain #2     |       |  Subchain #N     |
   | Seq 1: H_1(1)    |       | Seq 1: H_2(1)    |       | Seq 1: H_N(1)    |
   | Seq 2: H_1(2)    |       | Seq 2: H_2(2)    |       | Seq 2: H_N(2)    |
   | Seq 3: H_1(3)    |       | Seq 3: H_2(3)    |       | Seq 3: H_N(3)    |
   +--------┬---------+       +--------┬---------+       +--------┬---------+
            │                          │                          │
            └──────────────────────────┼──────────────────────────┘
                                       ▼
                       PostgreSQL / SIEM Ingest Stream
                   (Indexed by node_id + subchain_seq)
                                       │
                                       ▼
                       Periodic Epoch Merkle Anchor
                  Epoch Root Hash = Merkle(H_1(k), H_2(m)...)
```

#### Cryptographic Specification
1. **Sub-Key Derivation**:
   Each pod derives its unique HMAC signing key from the master pepper and its Kubernetes pod identity (`HOSTNAME` / `POD_NAME`):
   $$K_{\text{node}} = \text{HKDF-Expand}(\text{PRK} = \text{WARDEN\_PEPPER}, \text{info} = \text{"ironwarden-audit-chain-v1:"} \parallel \text{node\_id}, \text{len} = 32)$$
2. **Node Genesis Hash**:
   $$H_0^{(\text{node})} = \text{HMAC}_{K_{\text{node}}}(\text{node\_id} \parallel \text{"genesis"})$$
3. **Monotonic Intra-Pod Chaining**:
   For entry $i$ on pod with identifier $\text{node\_id}$, the hash is:
   $$H_i^{(\text{node})} = \text{HMAC}_{K_{\text{node}}}(H_{i-1}^{(\text{node})} \parallel \text{subchain\_seq}_i \parallel \text{timestamp} \parallel \text{payload\_hash})$$
4. **Verification Algorithm**:
   - Verification auditors partition the records by `node_id`.
   - Each partition is sorted by `subchain_seq ASC`.
   - The verifier validates:
     1. Monotonic continuity: $\text{subchain\_seq}_i = \text{subchain\_seq}_{i-1} + 1$ (no dropped or deleted records).
     2. Cryptographic validity: Recalculated HMAC matches `integrity_hash`.
5. **Periodic Epoch Merkle Anchoring**:
   Every $T$ seconds (e.g., 60s), a lightweight cluster reconciler queries the latest `integrity_hash` of all active nodes, builds a Merkle Tree, and publishes the Merkle Root to an immutable store (AWS S3 Object Lock, GCP Bucket Retention, or external SIEM). This guarantees absolute ordering across pods without contention during prompt execution.

---

## 4. Data Sovereignty Boundaries in Clustered Mode

A foundational tenet of IronWarden is **Zero-Leakage Data Sovereignty**. In clustered mode, boundary rules strictly isolate secrets and plaintexts to pod-local volatile memory:

```
+─────────────────────────────────────────────────────────────────────────────+
|                         DATA SOVEREIGNTY BOUNDARIES                         |
+───────────────────────────────────────┬─────────────────────────────────────+
|       STRICTLY NODE-LOCAL             |        DISTRIBUTED / CLUSTERED      |
|    (In-Memory / Never Persisted)      |       (Authenticated & Encrypted)   |
+───────────────────────────────────────┼─────────────────────────────────────+
| 1. WARDEN_PEPPER Root Secret          | 1. L2 Session Cache                 |
|    - Kept only in RAM                 |    - Encrypted via AadCipher        |
|    - Zero-allocation scrubbing        |    - AAD bound to username          |
|    - Rotated via Vault CSI            |    - Stored in Redis Cluster        |
|                                       |                                     |
| 2. Reversible PII Token Maps          | 2. Grounding Search Queue           |
|    - Kept in thread-local memory      |    - Payload encrypted via AAD      |
|    - Destroyed on request completion  |    - Distributed via Redis Streams  |
|                                       |                                     |
| 3. ONNX Inference Engine              | 3. Tamper-Evident Audit Ledger      |
|    - Local CPU/GPU tensor buffers     |    - Redactions JSON stored         |
|    - Models memory-mapped read-only   |    - Zero raw prompt persistence    |
|    - Zero network inference calls     |    - HMAC hash subchains            |
+───────────────────────────────────────┴─────────────────────────────────────+
```

### 4.1 Node-Local Guarantees
- **`WARDEN_PEPPER`**: The 32-byte pepper never touches disk or external storage. Injected via Kubernetes Secret volume mounted into `tmpfs` (`/etc/ironwarden/secrets`).
- **ONNX Inference**: Deployed locally inside the container image (`/opt/models/ner_model.onnx`). Inference executes in-process via ONNX Runtime C/Rust bindings. No user prompt text is transmitted over the network for classification.

### 4.2 Distributed Encryption Protocol (AadCipher)
All payloads persisted into Redis or PostgreSQL utilize the `AadCipher` authenticated encryption engine:
- **Cipher**: AES-256-GCM or ChaCha20-Poly1305.
- **Key**: Derived dynamically per user session via HKDF from `WARDEN_PEPPER` and `username`.
- **Associated Authenticated Data (AAD)**: Encapsulates `(username, session_id, tenant_id)`.
- **Impact**: Any unauthorized compromise of the Redis cluster yields only cryptographic ciphertext; without the node's ephemeral pepper, no user prompt or token map can be recovered.

---

## 5. Native Kubernetes Operator Specification

To manage, autoscale, and heal IronWarden bridge pods across enterprise clusters, IronWarden specifies a native Kubernetes Operator: **`IronWardenBridge`**.

### 5.1 Custom Resource Definition (CRD)

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: ironwardenbridges.security.ironwarden.io
spec:
  group: security.ironwarden.io
  names:
    kind: IronWardenBridge
    listKind: IronWardenBridgeList
    plural: ironwardenbridges
    singular: ironwardenbridge
    shortNames:
      - iwb
      - warden
  scope: Namespaced
  versions:
    - name: v1alpha1
      served: true
      storage: true
      subresources:
        status: {}
        scale:
          specReplicasPath: .spec.replicas
          statusReplicasPath: .status.replicas
          labelSelectorPath: .status.selector
      schema:
        openAPIV3Schema:
          type: object
          required:
            - spec
          properties:
            spec:
              type: object
              required:
                - deploymentTier
                - pepperSecretRef
              properties:
                deploymentTier:
                  type: string
                  enum: ["standalone", "enterprise_ha"]
                  default: "enterprise_ha"
                replicas:
                  type: integer
                  minimum: 1
                  maximum: 100
                  default: 3
                image:
                  type: string
                  default: "ghcr.io/ironwarden/bridge:latest"
                imagePullPolicy:
                  type: string
                  enum: ["Always", "IfNotPresent", "Never"]
                  default: "IfNotPresent"
                mcpPermits:
                  type: integer
                  minimum: 1
                  maximum: 128
                  default: 4
                  description: "Concurrency semaphore permits for AI tasks (MCP_SEMAPHORE_PERMITS)"
                pepperSecretRef:
                  type: object
                  required:
                    - name
                    - key
                  properties:
                    name:
                      type: string
                    key:
                      type: string
                      default: "WARDEN_PEPPER"
                redisConfig:
                  type: object
                  properties:
                    urlSecretRef:
                      type: object
                      required:
                        - name
                        - key
                      properties:
                        name:
                          type: string
                        key:
                          type: string
                          default: "REDIS_URL"
                databaseConfig:
                  type: object
                  properties:
                    urlSecretRef:
                      type: object
                      required:
                        - name
                        - key
                      properties:
                        name:
                          type: string
                        key:
                          type: string
                          default: "DATABASE_URL"
                remoteAudit:
                  type: object
                  properties:
                    endpoint:
                      type: string
                    tokenSecretRef:
                      type: object
                      properties:
                        name:
                          type: string
                        key:
                          type: string
                hpa:
                  type: object
                  properties:
                    enabled:
                      type: boolean
                      default: true
                    minReplicas:
                      type: integer
                      default: 3
                    maxReplicas:
                      type: integer
                      default: 30
                    targetCpuUtilizationPercentage:
                      type: integer
                      default: 70
                    targetConcurrencyUtilizationPercentage:
                      type: integer
                      default: 80
                resources:
                  type: object
                  properties:
                    limits:
                      type: object
                    requests:
                      type: object
            status:
              type: object
              properties:
                replicas:
                  type: integer
                readyReplicas:
                  type: integer
                phase:
                  type: string
                conditions:
                  type: array
                  items:
                    type: object
                    properties:
                      type:
                        type: string
                      status:
                        type: string
                      reason:
                        type: string
                      message:
                        type: string
```

### 5.2 Controller Reconciliation Loop Logic

The `IronWardenBridgeController` executes an idempotent reconciliation loop:

```mermaid
flowchart TD
    A[Watch Event: IronWardenBridge CR] --> B[Fetch CR Instance]
    B --> C{CR Marked for Deletion?}
    C -- Yes --> D[Run Finalizers & Cleanup]
    C -- No --> E[Validate Secret References: Pepper, Redis, DB]
    E -- Missing Secrets --> F[Update Status: Degraded / Requeue]
    E -- Valid --> G[Reconcile ConfigMap: Manifest & Policies]
    G --> H[Reconcile Deployment: Pod Spec, Env, tmpfs Mounts]
    H --> I[Reconcile Service: ClusterIP / Port 14141]
    I --> J{HPA Enabled?}
    J -- Yes --> K[Reconcile HorizontalPodAutoscaler]
    J -- No --> L[Tear down HPA if exists]
    K --> M[Query Pod Status & Readiness Probes]
    L --> M
    M --> N[Update CR Status: ReadyReplicas, ActiveHashHeads]
    N --> O[Reconcile Succeeded: Sleep until Next Event]
```

#### Detailed Controller Steps:
1. **Secret & Preflight Verification**:
   Inspect the target namespace for `spec.pepperSecretRef`. Read key bytes; verify length $\ge 32$ bytes. If invalid, set condition `Degraded` with message `"Pepper must be >= 32 bytes"`.
2. **Deployment Spec Generation**:
   Construct Kubernetes `apps/v1` `Deployment`:
   - Inject environment variables:
     - `DEPLOYMENT_TIER`: `spec.deploymentTier`
     - `MCP_SEMAPHORE_PERMITS`: `spec.mcpPermits` (or via pod annotation)
     - `WARDEN_PEPPER`: mapped from `spec.pepperSecretRef`
     - `REDIS_URL`: mapped from `spec.redisConfig.urlSecretRef`
     - `DATABASE_URL`: mapped from `spec.databaseConfig.urlSecretRef`
   - Mount model weights as read-only volume or container image layer.
3. **Service & Ingress Generation**:
   Deploy `v1/Service` exposing port `14141` (`http-bridge`).

### 5.3 Health Probes & Readiness Protocol

IronWarden pods handle complex in-memory ML runtimes. Standard TCP probes are insufficient. The bridge implements dedicated probe endpoints:

```yaml
livenessProbe:
  httpGet:
    path: /health/liveness
    port: 14141
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health/readiness
    port: 14141
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 2

startupProbe:
  httpGet:
    path: /health/startup
    port: 14141
  initialDelaySeconds: 2
  periodSeconds: 3
  timeoutSeconds: 2
  failureThreshold: 30 # Up to 90 seconds for ONNX model load & warm-up
```

#### Readiness Check Sequence:
1. **Pepper Integrity**: Confirm `WARDEN_PEPPER` is non-nil and $\ge 32$ bytes in RAM.
2. **ONNX Warm-up**: Execute a dummy inference pass on a canary token string (`"IronWarden System Health Probe"`). Verify inference engine returns without error within 50ms.
3. **Backend Connectivity**:
   - `REDIS_URL`: Send `PING`, expect `PONG` within 200ms.
   - `DATABASE_URL`: Execute `SELECT 1`, verify pool connection within 500ms.
   - If any check fails, return HTTP 503 (`Service Unavailable`), removing the pod from Ingress endpoints.

### 5.4 Autoscaling (HPA) & Concurrency Tuning

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ironwarden-bridge-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ironwarden-bridge
  minReplicas: 3
  maxReplicas: 30
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Pods
      pods:
        metric:
          name: mcp_permit_saturation_ratio
        target:
          type: AverageValue
          averageValue: "0.8" # Scale when 80% of permits are concurrently active
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
```

#### MCP Semaphore Permitting:
- Each pod enforces `MCP_SEMAPHORE_PERMITS` via `tokio::sync::Semaphore`.
- When requests exceed permits, excess requests queue cleanly in Tokio async wait queues up to the connection timeout rather than spawning unbounded OS threads or thrashing CPU caches.
- The Kubernetes HPA monitors permit saturation; as saturation approaches 80%, new bridge pods spawn horizontally, scaling the cluster's aggregate AI throughput linearly.

---

## 6. Verification & Implementation Checklist

- [x] **Configurator Tier Validation**: `warden/src/configurator.rs` enforces `deployment_tier` (`"standalone"`, `"enterprise_ha"`, `"clustered"`).
- [x] **Configurable Semaphore**: `mcp/src/server/mod.rs` loads `MCP_SEMAPHORE_PERMITS` with default of 4.
- [x] **Unit Test Suite**: `tests/rust/unit_mcp.rs` tests default, custom, and invalid semaphore permit fallback values.
- [x] **PostgreSQL Migration DDL**: Production-grade schemas for `audit_reports`, `ephemeral_raw_logs`, `search_jobs`, and `sessions`.
- [x] **Distributed Cryptographic Subchains**: Per-pod HKDF key derivation specification guaranteeing mathematical tamper-evidence without distributed lock contention.
- [x] **Kubernetes Operator Design**: Complete `IronWardenBridge` CRD, controller reconciliation flow, and HPA auto-scaling configuration.
