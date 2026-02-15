# fqdn-filter-tester

A lightweight, zero-dependency CLI tool that validates FQDN-based egress firewall rules from inside a Kubernetes cluster.

Drop it as a **Job**, point it at a list of domains, and get a clear **DNS → TCP → TLS/SNI** pass/fail report in seconds.

## Why

Private Kubernetes clusters often route all egress traffic through a centralized firewall (Azure Firewall, AWS Network Firewall, Palo Alto, etc.) that allows or denies traffic based on FQDN.  
When something breaks — image pulls fail, APIs time out, packages won't install — figuring out _which_ domain is blocked is slow and manual.

**fqdn-filter-tester** automates that.

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
          image: ghcr.io/cheolhuikim/fqdn-filter-tester:latest
          env:
            - name: TARGETS
              value: "https://mcr.microsoft.com,https://github.com,https://google.com"
      restartPolicy: Never
```

```bash
kubectl apply -f job.yaml
kubectl logs job/fqdn-filter-test
```

### Local / CLI

```bash
TARGETS="mcr.microsoft.com:443,github.com:443" ./fqdn-filter-tester
```

### Build from Source

```bash
go build -o fqdn-filter-tester .
```

### Docker

```bash
docker build -t fqdn-filter-tester .
docker run -e TARGETS="https://github.com,https://mcr.microsoft.com" fqdn-filter-tester
```

## Configuration

| Environment Variable | Description                                         | Default      |
| -------------------- | --------------------------------------------------- | ------------ |
| `TARGETS`            | Comma-separated list of targets (see formats below) | _(required)_ |
| `TIMEOUT`            | Timeout per phase in seconds                        | `5`          |

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
║         FQDN Filter Tester — Egress Validation          ║
╚══════════════════════════════════════════════════════════╝

  Targets:  4
  Timeout:  5s per phase
  Phases:   DNS → TCP → TLS/SNI

┌────────────────────┬───────┬─────────────────┬─────────────────┬─────────────────┬─────────┐
│  FQDN              │  PORT │  DNS            │  TCP            │  TLS/SNI        │  RESULT │
├────────────────────┼───────┼─────────────────┼─────────────────┼─────────────────┼─────────┤
│  mcr.microsoft.com │  443  │  ✅ 2ms         │  ✅ 10ms        │  ✅ 27ms        │  PASS   │
│  github.com        │  443  │  ✅ 18ms        │  ✅ 7ms         │  ✅ 21ms        │  PASS   │
│  google.com        │  443  │  ✅ 5ms         │  ✅ 11ms        │  ❌ EOF         │  FAIL   │
│  blocked.example   │  443  │  ❌ NXDOMAIN    │  —              │  —              │  FAIL   │
└────────────────────┴───────┴─────────────────┴─────────────────┴─────────────────┴─────────┘

  Results: 2/4 passed | 2/4 failed
```

The exit code is **non-zero** if any target fails, making it easy to use as a CI/CD gate.

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
│  │ fqdn-filter-tester│                  │
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

## Known Behaviors & Limitations

- **DNS is resolved sequentially** to avoid the [Linux conntrack race condition](https://github.com/kubernetes/kubernetes/issues/64924) that causes 5-second delays on concurrent UDP DNS in Kubernetes.
- **Only IPv4 (A records)** are queried. Environments where IPv6 AAAA queries are blocked would otherwise add a 5-second penalty per lookup.
- **FQDN trailing dot** is appended automatically so that Kubernetes `ndots:5` search domains are bypassed.
- **IP address targets** skip the DNS phase entirely and go straight to TCP.
- **TLS verification is strict** (`InsecureSkipVerify: false`). Self-signed certificates will show as `cert: unknown authority`.
- The tool tests **connectivity only** — it does not send HTTP requests or validate response content.

## License

MIT
