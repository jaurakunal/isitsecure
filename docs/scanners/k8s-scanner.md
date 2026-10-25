# Kubernetes Scanner

**Type:** SAST | **Severity:** Low–Critical | **Category:** Infrastructure Misconfiguration

## What It Does

Scans Kubernetes manifests for the checks below. A manifest is any `.yaml`/`.yml` file containing `apiVersion:`, plus every YAML file under `k8s/`, `deploy/`, `charts/`, `manifests/`, `helm/`, `kubernetes/` or `kube/`. The checks are regular expressions over the file text (the YAML is not parsed):

1. **Privileged containers** — `securityContext.privileged: true` gives the container full host access (Critical)
2. **Running as root** — `runAsUser: 0` or `runAsNonRoot: false` (High). A manifest that simply omits `runAsNonRoot` is not flagged
3. **Host namespaces** — `hostNetwork: true` and `hostPID: true`, one finding each (High)
4. **ALL capabilities** — `capabilities.add` containing `ALL` (Critical)
5. **Secrets in plaintext** — hardcoded password, API key/secret/token or database URL in container `env` values instead of Kubernetes Secrets (Critical); plaintext secrets in a Helm `values.yaml` (High)
6. **Image tags** — `image: x:latest` (Low), and an untagged image only when it is on the last line of the file
7. **Public load balancers** — `type: LoadBalancer` without an internal-LB annotation for AWS, GCP or Azure (Medium)

Not covered today: resource limits, hostPath mounts, missing `runAsNonRoot`, and network policies.

## Why It Matters

Kubernetes misconfigurations are the #1 attack vector in container environments:

- **Privileged containers** — a compromised container can escape to the host, access other containers, and take over the entire cluster
- **No resource limits** — cryptojacking or DoS from a single compromised pod (not checked by the scanner)
- **HostPath mounts** — direct access to host filesystem bypasses all container isolation (not checked by the scanner)
- **Docker socket mount** — mounting `/var/run/docker.sock` gives the container full control over all containers on the host (not checked by the scanner)

## Real-World Breaches

**Tesla (2018)** — Attackers found an unsecured Kubernetes dashboard (no authentication) on Tesla's AWS infrastructure. They used it to access AWS credentials and deploy cryptocurrency miners on Tesla's cloud resources.

**Docker runc CVE-2019-5736 (2019)** — A container escape vulnerability in runc allowed malicious containers to overwrite the host binary and gain root access. Privileged containers made exploitation trivial.

## How to Fix

```yaml
# GOOD: Secure pod security context
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: app
          securityContext:
            privileged: false
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              cpu: "500m"
              memory: "512Mi"
            requests:
              cpu: "100m"
              memory: "128Mi"
```
