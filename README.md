# fqdn-filter-tester

A lightweight CLI tool to validate FQDN-based egress filtering rules in Managed Kubernetes environments.

Designed for **Private Kubernetes Clusters** using a **Hub-and-Spoke** network topology, where all egress traffic passes through a centralized firewall (e.g., Azure Firewall, AWS Network Firewall, Palo Alto) with FQDN-based allow/deny policies.

## Problem

When operating private Kubernetes clusters with strict egress controls, it's common to face issues like:

- Container images failing to pull due to blocked registry FQDNs
- Helm chart repositories being unreachable
- Application dependencies (APIs, packages, OS updates) silently blocked
- Difficult-to-debug DNS resolution failures behind firewalls
- TLS handshake failures caused by firewall SSL inspection or SNI-based filtering

Manually verifying each FQDN is tedious and error-prone. **fqdn-filter-tester** automates this process.

## Features

- **DNS Resolution Test** — Verify that each FQDN resolves correctly from within the cluster
- **TCP Handshake Test** — Confirm that a TCP connection can be established to the target host:port
- **TLS Handshake Test** — Validate TLS negotiation succeeds (certificate verification, SNI)
- **HTTP(S) Reachability Test** — Optionally send HTTP requests and check response status codes
- **Parallel Execution** — Test multiple FQDNs concurrently for fast validation
- **Environment Variable Input** — Accept FQDN lists via environment variables for easy integration with K8s manifests
- **Structured Output** — Results in JSON/table format for easy parsing and reporting
- **Exit Code Contract** — Non-zero exit code on any failure for CI/CD pipeline integration

## Quick Start

### As a Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: fqdn-filter-test
spec:
  template:
    spec:
      containers:
        - name: tester
          image: ghcr.io/cheolhuikim/fqdn-filter-tester:latest
          env:
            - name: FQDN_LIST
              value: "mcr.microsoft.com:443,registry.k8s.io:443,production-api.example.com:443"
      restartPolicy: Never
  backoffLimit: 0
```

### CLI

```bash
# Provide FQDNs via environment variable
export FQDN_LIST="mcr.microsoft.com:443,registry.k8s.io:443,packages.ubuntu.com:80"
fqdn-filter-tester

# Or pass directly as arguments
fqdn-filter-tester --fqdns "mcr.microsoft.com:443,registry.k8s.io:443"

# Load from file
fqdn-filter-tester --file fqdn-list.txt

# JSON output
fqdn-filter-tester --output json
```

## Configuration

| Environment Variable | Description                                       | Example                                     |
| -------------------- | ------------------------------------------------- | ------------------------------------------- |
| `FQDN_LIST`          | Comma-separated list of `host:port` pairs         | `mcr.microsoft.com:443,registry.k8s.io:443` |
| `FQDN_FILE`          | Path to a file containing FQDNs (one per line)    | `/config/fqdn-list.txt`                     |
| `TEST_TIMEOUT`       | Timeout per test in seconds (default: `5`)        | `10`                                        |
| `PARALLEL`           | Number of concurrent tests (default: `10`)        | `20`                                        |
| `OUTPUT_FORMAT`      | Output format: `table`, `json` (default: `table`) | `json`                                      |
| `DNS_SERVER`         | Custom DNS server to use for resolution           | `10.0.0.10:53`                              |
| `SKIP_TLS`           | Skip TLS handshake test (default: `false`)        | `true`                                      |

## Sample Output

```
┌──────────────────────────┬──────┬──────────┬───────────┬───────────┬────────┐
│ FQDN                     │ PORT │ DNS      │ TCP       │ TLS       │ RESULT │
├──────────────────────────┼──────┼──────────┼───────────┼───────────┼────────┤
│ mcr.microsoft.com        │ 443  │ ✅ 12ms  │ ✅ 25ms   │ ✅ 45ms   │ PASS   │
│ registry.k8s.io          │ 443  │ ✅ 8ms   │ ✅ 30ms   │ ✅ 52ms   │ PASS   │
│ blocked.example.com      │ 443  │ ✅ 5ms   │ ❌ timeout│ —         │ FAIL   │
│ unknown.example.com      │ 443  │ ❌ NXDOMAIN│ —       │ —         │ FAIL   │
└──────────────────────────┴──────┴──────────┴───────────┴───────────┴────────┘

Results: 2/4 passed | 2/4 failed
```

## Use Cases

- **Cluster Bootstrapping** — Validate all required FQDNs are reachable before deploying workloads
- **Firewall Rule Verification** — Confirm that firewall FQDN rules match expected allow/deny policies
- **CI/CD Gate** — Block deployments if critical egress paths are not available
- **Incident Diagnosis** — Quickly identify which FQDNs are blocked during outages
- **Compliance Audit** — Document which external endpoints a cluster can reach

## Architecture

```
┌─────────────────────────────────────────────────────┐
│ Private Kubernetes Cluster                          │
│                                                     │
│  ┌─────────────────────┐                            │
│  │ fqdn-filter-tester  │                            │
│  │ (Pod/Job)           │                            │
│  └────────┬────────────┘                            │
│           │                                         │
└───────────┼─────────────────────────────────────────┘
            │ egress traffic
            ▼
┌───────────────────────┐
│ Hub Firewall          │
│ (FQDN-based policies) │
│                       │
│ ALLOW: *.microsoft.com│
│ ALLOW: registry.k8s.io│
│ DENY:  *              │
└───────────┬───────────┘
            │
            ▼
        Internet
```

## Roadmap

- [ ] Core DNS / TCP / TLS testing engine
- [ ] CLI with environment variable and file input
- [ ] Structured output (table, JSON)
- [ ] Container image (distroless/static)
- [ ] Helm chart for easy deployment
- [ ] Prometheus metrics endpoint
- [ ] Pre-built FQDN lists for popular cloud services (AKS, EKS, GKE)
- [ ] Webhook mode for continuous monitoring

## License

MIT
