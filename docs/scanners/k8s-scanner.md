# Kubernetes Scanner

**Type:** SAST | **Severity:** High–Critical | **Category:** Infrastructure Misconfiguration

## What It Does

Scans Kubernetes manifests (`deployment.yaml`, `pod.yaml`, `*.k8s.yaml`) for:

1. **Privileged containers** — `securityContext.privileged: true` gives the container full host access
2. **No resource limits** — missing CPU/memory limits allow a compromised container to consume all host resources (DoS)
3. **HostPath mounts** — mounting host filesystem paths into containers (especially `/`, `/etc`, `/var/run/docker.sock`)
4. **Running as root** — `runAsUser: 0` or missing `runAsNonRoot: true`
5. **Missing network policies** — no network segmentation between pods
6. **Secrets in plaintext** — hardcoded secrets in manifests instead of Kubernetes Secrets

## Why It Matters

Kubernetes misconfigurations are the #1 attack vector in container environments:

- **Privileged containers** — a compromised container can escape to the host, access other containers, and take over the entire cluster
- **No resource limits** — cryptojacking or DoS from a single compromised pod
- **HostPath mounts** — direct access to host filesystem bypasses all container isolation
- **Docker socket mount** — mounting `/var/run/docker.sock` gives the container full control over all containers on the host

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
