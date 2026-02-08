#!/usr/bin/env bash
set -euo pipefail

install_deps() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y \
      git curl build-essential pkg-config cmake \
      clang libclang-dev llvm-dev \
      libc6-dev linux-libc-dev
    return 0
  fi

  if command -v dnf >/dev/null 2>&1; then
    dnf install -y \
      git curl gcc gcc-c++ make pkgconfig cmake \
      clang clang-devel llvm-devel \
      glibc-devel
    return 0
  fi

  if command -v yum >/dev/null 2>&1; then
    yum install -y \
      git curl gcc gcc-c++ make pkgconfig cmake \
      clang clang-devel llvm-devel \
      glibc-devel
    return 0
  fi

  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache \
      git curl build-base pkgconfig cmake \
      clang llvm-dev libc-dev
    return 0
  fi

  echo "No supported package manager found. Install build deps manually." >&2
  return 1
}

if command -v sudo >/dev/null 2>&1; then
  sudo bash -c "$(declare -f install_deps); install_deps"
else
  install_deps
fi

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
