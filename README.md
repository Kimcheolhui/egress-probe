# egress-probe

A lightweight, zero-dependency CLI tool that validates FQDN-based egress firewall rules from inside a Kubernetes cluster.

Drop it as a **Job**, specify which domains should be **allowed** and which should be **denied**, and get a clear **DNS → TCP → TLS/SNI** report in seconds. The job succeeds only when every target behaves as expected.

## Why

Private Kubernetes clusters often route all egress traffic through a centralized firewall (Azure Firewall, AWS Network Firewall, Palo Alto, etc.) that allows or denies traffic based on FQDN.  
When something breaks — image pulls fail, APIs time out, packages won't install — figuring out _which_ domain is blocked is slow and manual. Conversely, you also need to confirm that domains that _should_ be blocked actually are.

**egress-probe** automates both directions.

## How It Works

Each target goes through a 3-phase validation pipeline:

| Phase       | What it checks                                     | Typical failure reason                          |
| ----------- | -------------------------------------------------- | ----------------------------------------------- |
| **DNS**     | Can the domain be resolved to an IP?               | DNS policy / NXDOMAIN / ndots misconfiguration  |
| **TCP**     | Can a TCP handshake complete on the target port?   | Network rule blocking the port                  |
| **TLS/SNI** | Does a TLS handshake succeed with the correct SNI? | Application rule denying the FQDN (EOF / reset) |

If a phase fails, subsequent phases are skipped for that target.

## Quick Start

### Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: fqdn-filter-test
spec:
  backoffLimit: 0
  template:
    spec:
      containers:
        - name: tester
          image: ghcr.io/cheolhuikim/egress-probe:latest
          env:
            - name: ALLOW_TARGETS
              value: "https://mcr.microsoft.com,https://github.com"
            - name: DENY_TARGETS
              value: "https://google.com"
      restartPolicy: Never
```

```bash
kubectl apply -f job.yaml
kubectl logs job/fqdn-filter-test
```

### Local / CLI

```bash
ALLOW_TARGETS="mcr.microsoft.com,github.com" DENY_TARGETS="google.com" ./egress-probe
```

### Build from Source

```bash
go build -o egress-probe .
```

### Docker

```bash
docker build -t egress-probe .
docker run -e ALLOW_TARGETS="github.com,mcr.microsoft.com" -e DENY_TARGETS="google.com" egress-probe
```

## Configuration

| Environment Variable | Description                                                    | Default |
| -------------------- | -------------------------------------------------------------- | ------- |
| `ALLOW_TARGETS`      | Comma-separated list of targets that **should be reachable**   | —       |
| `DENY_TARGETS`       | Comma-separated list of targets that **should be blocked**     | —       |
| `TARGETS`            | Legacy fallback — treated as `ALLOW_TARGETS` if neither is set | —       |
| `TIMEOUT`            | Timeout per phase in seconds                                   | `5`     |

At least one of `ALLOW_TARGETS`, `DENY_TARGETS`, or `TARGETS` is required.

### Supported Target Formats

```
mcr.microsoft.com           → mcr.microsoft.com:443
mcr.microsoft.com:443       → mcr.microsoft.com:443
https://mcr.microsoft.com   → mcr.microsoft.com:443
http://example.com          → example.com:80
tcp://1.1.1.1:53            → 1.1.1.1:53
```

Schemes (`https://`, `http://`, `tcp://`) are stripped automatically. Port is inferred from the scheme if omitted.

## Sample Output

```
╔══════════════════════════════════════════════════════════╗
║            Egress Probe — Egress Validation              ║
╚══════════════════════════════════════════════════════════╝

  Targets:  4 (2 allow / 2 deny)
  Timeout:  5s per phase
  Phases:   DNS → TCP → TLS/SNI

┌────────────────────┬───────┬─────────────────┬─────────────────┬─────────────────┬─────────┐
│  FQDN              │  PORT │  DNS            │  TCP            │  TLS/SNI        │  RESULT │
├────────────────────┴───────┴─────────────────┴─────────────────┴─────────────────┴─────────┤
│  ALLOW — should be reachable                                                               │
├────────────────────┬───────┬─────────────────┬─────────────────┬─────────────────┬─────────┤
│  mcr.microsoft.com │  443  │  ✅ 2ms         │  ✅ 10ms        │  ✅ 27ms        │  OK     │
│  github.com        │  443  │  ✅ 18ms        │  ✅ 7ms         │  ✅ 21ms        │  OK     │
├────────────────────┴───────┴─────────────────┴─────────────────┴─────────────────┴─────────┤
│  DENY  — should be blocked                                                                 │
├────────────────────┬───────┬─────────────────┬─────────────────┬─────────────────┬─────────┤
│  google.com        │  443  │  ✅ 5ms         │  ✅ 11ms        │  ❌ EOF         │  OK     │
│  blocked.example   │  443  │  ❌ NXDOMAIN    │  —              │  —              │  OK     │
└────────────────────┴───────┴─────────────────┴─────────────────┴─────────────────┴─────────┘

  Results: 4/4 OK
```

### Exit Code Logic

| Scenario                                              | Exit Code | Meaning                                  |
| ----------------------------------------------------- | --------- | ---------------------------------------- |
| All ALLOW targets reachable, all DENY targets blocked | **0**     | Everything behaves as expected           |
| An ALLOW target is blocked                            | **1**     | Something that should be reachable isn't |
| A DENY target is reachable                            | **1**     | Something that should be blocked isn't   |

## Reading the Results

| Result                     | Meaning                                        |
| -------------------------- | ---------------------------------------------- |
| DNS ✅, TCP ✅, TLS ✅     | FQDN is fully reachable — firewall allows it   |
| DNS ✅, TCP ✅, TLS ❌ EOF | Firewall inspects SNI and **blocks** this FQDN |
| DNS ✅, TCP ❌ timeout     | Network rule blocks the port / IP              |
| DNS ❌ NXDOMAIN            | Domain does not exist                          |
| DNS ❌ timeout             | DNS server unreachable or query blocked        |

## Architecture

```
┌─────────────────────────────────────────┐
│  Private Kubernetes Cluster             │
│                                         │
│  ┌───────────────────┐                  │
│  │ egress-probe│                  │
│  │ (Job / Pod)       │                  │
│  └────────┬──────────┘                  │
└───────────┼─────────────────────────────┘
            │ egress
            ▼
   ┌────────────────────┐
   │  Hub Firewall       │
   │  (FQDN rules)      │
   │                     │
   │  ALLOW: github.com  │
   │  ALLOW: *.mcr.ms... │
   │  DENY:  *           │
   └────────┬────────────┘
            │
            ▼
         Internet
```

## Examples

See the [`examples/`](examples/) directory for ready-to-use manifests:

| File                                                      | Scenario                | When to use                                 |
| --------------------------------------------------------- | ----------------------- | ------------------------------------------- |
| [`job.yaml`](examples/job.yaml)                           | Single Job              | Quick one-off egress test on any node       |
| [`job-per-nodepool.yaml`](examples/job-per-nodepool.yaml) | Job per node pool       | Node pools on different subnets / UDR / NSG |
| [`daemonset.yaml`](examples/daemonset.yaml)               | DaemonSet on every node | Smoke test all nodes regardless of pool     |
| [`cronjob.yaml`](examples/cronjob.yaml)                   | CronJob (every 6h)      | Continuous regression detection             |

> **Tip — Node pool labels by provider:**
>
> | Provider | Label                            |
> | -------- | -------------------------------- |
> | AKS      | `kubernetes.azure.com/agentpool` |
> | EKS      | `eks.amazonaws.com/nodegroup`    |
> | GKE      | `cloud.google.com/gke-nodepool`  |

## Known Behaviors & Limitations

- **DNS is resolved sequentially** to avoid the [Linux conntrack race condition](https://github.com/kubernetes/kubernetes/issues/64924) that causes 5-second delays on concurrent UDP DNS in Kubernetes.
- **Only IPv4 (A records)** are queried. Environments where IPv6 AAAA queries are blocked would otherwise add a 5-second penalty per lookup.
- **FQDN trailing dot** is appended automatically so that Kubernetes `ndots:5` search domains are bypassed.
- **IP address targets** skip the DNS phase entirely and go straight to TCP.
- **TLS verification is strict** (`InsecureSkipVerify: false`). Self-signed certificates will show as `cert: unknown authority`.
- The tool tests **connectivity only** — it does not send HTTP requests or validate response content.

## License

MIT
