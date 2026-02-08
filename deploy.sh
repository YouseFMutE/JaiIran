#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
  curl https://sh.rustup.rs -sSf | sh -s -- -y
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

cargo build --release

if command -v sudo >/dev/null 2>&1; then
  sudo install -m 0755 target/release/aegis-relay /usr/local/bin/aegis-relay
else
  install -m 0755 target/release/aegis-relay /usr/local/bin/aegis-relay
fi

echo "Installed to /usr/local/bin/aegis-relay"
