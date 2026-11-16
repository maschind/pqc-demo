# pqc-demo Dev Spaces workspace image

Bespoke UBI9 image used by [`../devfile.yaml`](../devfile.yaml). It contains only what this
project needs:

| Tool | Version | Why |
|---|---|---|
| OpenJDK (devel) | 17 (Red Hat build, from UBI repos) | build/run the Spring Boot 2.7 app |
| Maven | 3.9 (`maven:3.9` module, openjdk17 profile) | build |
| OpenSSL, curl, git, jq | UBI9 | `scripts/client-demo.sh` |
| opencode CLI | `OPENCODE_VERSION` | AI tooling |
| Claude Code CLI | `CLAUDE_CODE_VERSION` | AI tooling |
| opencode / Claude Code VS Code extensions | `*_EXT_VERSION` | installed by Che Code through `DEFAULT_EXTENSIONS`, so they work even when the cluster's Open VSX registry doesn't have them |

The image supports the arbitrary UID that OpenShift assigns (GID 0, `entrypoint.sh` adds a
`/etc/passwd` entry). Nothing is stored under `$HOME`, because Dev Spaces may mount a
persistent volume there.

## Build and push

The cluster is `amd64`; `arm64` is included so the image also runs natively on Apple Silicon.

```bash
TAG=1.0.0
IMG=quay.io/maschind/pqc-demo-devspaces
podman build --platform linux/amd64,linux/arm64 --manifest $IMG:$TAG devspaces-image/
podman manifest push --all $IMG:$TAG docker://$IMG:$TAG
```

The quay.io repository must be **public** (or every user namespace needs a pull secret).

## Updating

1. Bump the version `ARG`s in `Containerfile` (or rebuild unchanged to pick up UBI security fixes).
2. Build and push with a **new tag**.
3. Update `image:` in `../devfile.yaml` to the new tag and commit. New workspaces use the new image.

## Test locally (like OpenShift: random UID, GID 0)

```bash
podman run --rm -it --user 1000900000:0 -v "$PWD:/projects/pqc-demo:Z" \
  -w /projects/pqc-demo quay.io/maschind/pqc-demo-devspaces:1.0.0 \
  bash -c 'mvn -B -ntp package && java -version && opencode --version && claude --version'
```
