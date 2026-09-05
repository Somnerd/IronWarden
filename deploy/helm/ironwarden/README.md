# IronWarden Kubernetes Helm Chart

Official Helm chart for deploying **IronWarden** — the high-performance Sovereign AI Reverse Proxy and Privacy Firewall — on Kubernetes.

## Features
- **Auto-Scaling**: Ready-to-go HPA scaling from 2 to 10+ replicas based on CPU/memory load.
- **Prometheus Scrapes**: Native pod annotations for automatic scraping of `/metrics`.
- **Zero-Trust Secrets**: Supports injecting `WARDEN_PEPPER` via Kubernetes Secrets or HashiCorp Vault.
- **Micro-Footprint**: Optimized for edge, bare metal, or cloud Kubernetes clusters (EKS, GKE, AKS, k3s).

## Quickstart

### 1. Install Chart Locally
```bash
helm install ironwarden ./deploy/helm/ironwarden \
  --set secrets.wardenPepper="your-64-char-hex-pepper" \
  --set secrets.openaiApiKey="sk-..."
```

### 2. Verify Deployment
```bash
kubectl get pods -l app.kubernetes.io/name=ironwarden
kubectl logs -l app.kubernetes.io/name=ironwarden -f
```

### 3. Port Forward for Local Testing
```bash
kubectl port-forward svc/ironwarden 14141:14141
curl http://localhost:14141/health
```
