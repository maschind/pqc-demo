#!/bin/bash
# OpenShift runs workspace containers with an arbitrary UID (GID 0).
# Give that UID a passwd entry (needed by git, ssh, whoami) and make sure $HOME exists.

if ! whoami &>/dev/null && [ -w /etc/passwd ]; then
  echo "user:x:$(id -u):0:Dev Spaces user:${HOME:-/home/user}:/bin/bash" >> /etc/passwd
fi

mkdir -p "${HOME:-/home/user}" 2>/dev/null || true

exec "$@"
