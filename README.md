# Aegis Relay System

A TCP-only, HTTP/2-over-TLS 1.3 tunneling system for hostile or unstable networks. It multiplexes many TCP sessions over a single TLS backbone, with connection cycling and traffic normalization controls.

## Features
- TCP-only transport, no UDP usage
- HTTP/2 multiplexing over TLS 1.3
- Connection cycling by time or bytes
- TLS fingerprint profiles (Chrome/Firefox/Rustls)
- Optional TLS record fragmentation for traffic shaping
- Dual-mode binary: Bridge and Destination

## Requirements
- Linux or macOS
- `whiptail` or `dialog` for the TUI (optional)
- Rust toolchain (installed by `deploy.sh`)

## Build
```bash
cargo build --release
```

## Deploy Script
```bash
./deploy.sh
```
This installs Rust if missing, builds `--release`, and installs `aegis-relay` to `/usr/local/bin`.

## TUI
```bash
./scripts/tui.sh
```
The TUI configures:
- Node Role (Bridge or Destination)
- Local listen IP and port
- Remote IP and port
- TLS SNI (Handshake Domain)
- Rotation interval (minutes)

## Bridge Mode
Example:
```bash
aegis-relay bridge \
  --listen 127.0.0.1:8080 \
  --remote 203.0.113.10:9443 \
  --sni edge.example.com \
  --rotate-mins 15 \
  --rotate-mb 512 \
  --tls-profile chrome
```

Key flags:
- `--listen` local TCP bind address for incoming clients.
- `--remote` Destination address to connect to.
- `--sni` TLS handshake domain.
- `--rotate-mins` and `--rotate-mb` for connection cycling.
- `--tls-profile` selects Chrome, Firefox, or Rustls client fingerprinting.
- `--tls-fragment` sets TLS record fragment size (0 disables).

## Destination Mode
Example:
```bash
aegis-relay destination \
  --listen 0.0.0.0:9443 \
  --forward 127.0.0.1:80 \
  --cert /etc/aegis/tls.crt \
  --key /etc/aegis/tls.key
```

Key flags:
- `--listen` TLS listener address for inbound Bridge connections.
- `--forward` upstream TCP target to connect to per stream.
- `--cert` and `--key` TLS server certificate and key.
- `--tls-fragment` sets TLS record fragment size (0 disables).

## TLS Certificates
Self-signed for testing:
```bash
mkdir -p /etc/aegis
openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 365 \
  -keyout /etc/aegis/tls.key \
  -out /etc/aegis/tls.crt \
  -subj "/CN=edge.example.com"
```

## Systemd
Two example services are below. Adjust paths and flags to fit your environment.

Bridge unit example:
```ini
[Unit]
Description=Aegis Relay Bridge
After=network.target

[Service]
Type=simple
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/aegis-relay bridge \
  --listen 127.0.0.1:8080 \
  --remote 203.0.113.10:9443 \
  --sni edge.example.com \
  --rotate-mins 15 \
  --rotate-mb 512 \
  --tls-profile chrome
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

Destination unit example:
```ini
[Unit]
Description=Aegis Relay Destination
After=network.target

[Service]
Type=simple
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/aegis-relay destination \
  --listen 0.0.0.0:9443 \
  --forward 127.0.0.1:80 \
  --cert /etc/aegis/tls.crt \
  --key /etc/aegis/tls.key
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-bridge.service
sudo systemctl enable --now aegis-destination.service
```

## Operational Notes
- Connection cycling only replaces the backbone for new streams; existing streams drain normally.
- For strict TLS fingerprinting, prefer `--tls-profile chrome` or `--tls-profile firefox` on the Bridge.
- All transport is TCP-based, no UDP paths are used.
