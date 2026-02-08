#!/usr/bin/env bash
set -euo pipefail

UI=""
if command -v whiptail >/dev/null 2>&1; then
  UI="whiptail"
elif command -v dialog >/dev/null 2>&1; then
  UI="dialog"
else
  echo "whiptail or dialog is required"
  exit 1
fi

menu() {
  $UI --title "Aegis Relay" --menu "$1" 15 70 4 "$2" "$3" "$4" "$5" 3>&1 1>&2 2>&3
}

input() {
  $UI --title "Aegis Relay" --inputbox "$1" 10 70 "$2" 3>&1 1>&2 2>&3
}

yesno() {
  $UI --title "Aegis Relay" --yesno "$1" 12 70
}

role=$(menu "Select node role" "bridge" "Bridge Node" "destination" "Destination Node") || exit 1

if [[ "$role" == "bridge" ]]; then
  listen=$(input "Local listen address" "127.0.0.1:8080") || exit 1
  remote=$(input "Destination address" "203.0.113.10:9443") || exit 1
  sni=$(input "Handshake domain (SNI)" "edge.example.com") || exit 1
  rotate=$(input "Rotation interval (minutes)" "15") || exit 1
  rotate_mb=$(input "Rotation limit (MB)" "512") || exit 1
  profile=$(menu "TLS fingerprint profile" "chrome" "Chrome" "firefox" "Firefox") || exit 1

  cmd=(aegis-relay bridge --listen "$listen" --remote "$remote" --sni "$sni" \
    --rotate-mins "$rotate" --rotate-mb "$rotate_mb" --tls-profile "$profile")
else
  listen=$(input "TLS listen address" "0.0.0.0:9443") || exit 1
  forward=$(input "Forward target address" "127.0.0.1:80") || exit 1
  cert=$(input "TLS cert path" "/etc/aegis/tls.crt") || exit 1
  key=$(input "TLS key path" "/etc/aegis/tls.key") || exit 1

  cmd=(aegis-relay destination --listen "$listen" --forward "$forward" --cert "$cert" --key "$key")
fi

summary="${cmd[*]}"
if yesno "Run this command?\n\n$summary"; then
  exec "${cmd[@]}"
fi
