# Project Roadmap & Tasks

## Current Status: Code Red Stabilization (V1.3)
The project is in a mandatory feature freeze until the **3rd-Party Cryptographic Audit (#86)** is complete. All engineering effort is focused on stabilizing security invariants and aligning the architecture with commercial pricing tiers.

## Active Milestones (High Priority)

### 1. 3rd-Party Audit & V1.3 Certification (WP-86)
- **Goal**: Absolute verification of security invariants (V-12 to V-19).
- **Status**: **In Progress**. Currently "Audit Ready" and awaiting external review.

### 2. HA Backend & Enterprise Scaling (WP-90)
- **Goal**: Eliminate Single Point of Failure (SPOF) for enterprise customers.
- **Status**: **Completed**. Implemented Redis/Postgres support for high-availability auditing and session management.

### 3. Tiered Deployment Architecture (WP-92)
- **Goal**: Technically distinguish between the "Sovereign" (Standalone) and "Enterprise" (Clustered) tiers.
- **Status**: **New**. Defining feature sets and performance guarantees for different price points.

## Completed & Rejected Milestones

### 4. Advanced Sector Expansion (WP-82)
- **Goal**: Expand compliance rules to HIPAA (US Healthcare) and APPI (Japan) + Shipping & Logistics.
- **Status**: **Completed**. Rulesets finalized and integrated.

### 5. Model Distillation & Optimization (#74)
- **Goal**: Reduce BERT-NER footprint for edge devices.
- **Status**: **Rejected**. Suspended to prioritize security reliability and PII detection accuracy over footprint.

### 6. Native Kubernetes Operator (WP-96)
- **Goal**: Automated orchestration for Enterprise deployments.
- **Status**: **On Hold**. Will resume once the HA Backend (WP-90) is verified in production.
