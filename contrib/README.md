# CosaCI deployment artifacts

This directory holds the third-party-friendly ways to run CosaCI on
infrastructure you already have. Three tracks, three audiences:

| Track  | Path                                  | Audience                                   |
|--------|---------------------------------------|--------------------------------------------|
| OCI    | `docker/Dockerfile.coordinator`, `docker/Dockerfile.agent` | k8s, ECS, Nomad, plain `docker run`       |
| Compose| `docker-compose.yml`                  | local dev / smoke testing on a laptop      |
| systemd| `systemd/cosaci-{coordinator,agent@}.service` | bare-metal Linux, debian/ubuntu/RHEL fleets|

None of these are mutually exclusive. The OCI images are what the
Compose stack uses; you can also run the same image under Kubernetes
or systemd-as-portable-service.

---

## OCI images

```bash
# Build for your host arch:
docker build \
  -f contrib/docker/Dockerfile.coordinator \
  -t cosaci-coordinator:dev .
docker build \
  -f contrib/docker/Dockerfile.agent \
  -t cosaci-agent:dev .

# Multi-arch (amd64 + arm64) requires buildx:
docker buildx create --name cosaci --use
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f contrib/docker/Dockerfile.coordinator \
  -t cosaci-coordinator:dev . --load
```

Both Dockerfiles:

- Build on `rust:1.94-slim-bookworm`, run on `debian:bookworm-slim`.
- Run as a non-root `cosaci` user.
- Expect mTLS certs at `/etc/cosaci/{ca,server,agent}.pem` (bind-mount or k8s Secret).
- Persist coordinator state at `/var/lib/cosaci/` (use a volume).

The coordinator exposes `7878` (mTLS for agents) and `7879` (read-API
for auditors, when `--read-addr` lands).

## Compose

```bash
# Brings up: bootstrap → coordinator → 5 agents.
docker compose -f contrib/docker-compose.yml up --build
```

The `bootstrap` service generates a demo CA + server cert + 5 agent
certs into a shared Docker volume on first run; subsequent `up`s
reuse them. **These certs are for the Compose demo only — they live
in a Docker volume, never leave it, and are not for production.**
Production deployments use the operator's existing PKI.

To start clean: `docker compose down -v` (removes the certs volume).

## systemd

```bash
# Build release binaries:
cargo build --release -p cosaci-coordinator -p cosaci-agent

# Install + enable:
sudo install -Dm0755 target/release/coordinator /usr/local/bin/cosaci-coordinator
sudo install -Dm0755 target/release/agent       /usr/local/bin/cosaci-agent
sudo install -Dm0644 contrib/systemd/cosaci-coordinator.service \
    /etc/systemd/system/cosaci-coordinator.service
sudo install -Dm0644 contrib/systemd/cosaci-agent@.service \
    /etc/systemd/system/cosaci-agent@.service
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/cosaci cosaci
sudo install -d -o cosaci -g cosaci /var/lib/cosaci /etc/cosaci

# Drop your CA + cert + key into /etc/cosaci/, then:
sudo systemctl daemon-reload
sudo systemctl enable --now cosaci-coordinator
sudo systemctl enable --now cosaci-agent@0 cosaci-agent@1 ...
```

The agent unit is templated by runner_id: `cosaci-agent@7` runs the
agent with `--id 7`. Override per-instance settings in
`/etc/cosaci/agent-7.env`; the unit reads `agent.env` (shared) then
`agent-%i.env` (per-instance).

Hardening flags applied by default (per
`man systemd.exec`): `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, `PrivateUsers`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
`RestrictNamespaces`, `LockPersonality`. `MemoryDenyWriteExecute=no`
is the documented exception — wasmtime needs JIT codegen, which
requires write-then-execute on the same mapping.

## What's NOT in this directory

- A Helm chart. CosaCI doesn't need one for v0.3 — the Dockerfile +
  a stock `Deployment` + `Service` get you there. A chart lands when
  the configuration surface stabilizes.
- A `cosaci-admin` enrollment CLI (issue #53). Until that lands,
  operators write the enrollment file by hand (see issue #45).
- Observability sidecars (issue #47). The systemd unit pipes to
  journald; production deployments want OTLP exporters once #47
  lands.
