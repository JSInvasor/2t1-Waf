#!/usr/bin/env bash
# 2t1-Waf — VPS install script. Run as root on a fresh Debian/Ubuntu VPS.
#
#   curl -fsSL https://raw.githubusercontent.com/<you>/2t1-waf/main/deploy/install.sh | bash
#
# Or after `git clone && cd 2t1-waf`:  sudo ./deploy/install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "must be root" >&2; exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/target/release/waf-proxy"

if [[ ! -x "$BIN" ]]; then
  echo "Building release binary…"
  apt-get update -y
  apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev curl ca-certificates

  # Make sure rustup + cargo are usable for the user we're running as (root,
  # under sudo). Anything in $HOME/.cargo/bin only counts for the current user
  # — if the operator ran "rustup default stable" as their non-root user, root
  # still has no default. The script must set up its own.
  export PATH="$HOME/.cargo/bin:$PATH"

  if ! cargo --version >/dev/null 2>&1; then
    echo "Installing rustup (stable, minimal profile) for $USER…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable --profile minimal --no-modify-path
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi

  # rustup may exist already with no default toolchain (the exact error the
  # user reported). `rustup default stable` is idempotent.
  if command -v rustup >/dev/null 2>&1; then
    rustup toolchain install stable >/dev/null 2>&1 || true
    rustup default stable
  fi

  cargo --version || { echo "cargo still not usable; aborting"; exit 1; }
  (cd "$REPO_ROOT" && cargo build --release -p waf-proxy)
fi

echo "Creating system user 2t1waf…"
id -u 2t1waf >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin 2t1waf

echo "Installing binary to /usr/local/bin…"
install -m 0755 "$BIN" /usr/local/bin/waf-proxy

echo "Installing config to /etc/2t1-waf/…"
mkdir -p /etc/2t1-waf
if [[ ! -f /etc/2t1-waf/waf.toml ]]; then
  install -m 0640 -o 2t1waf -g 2t1waf "$REPO_ROOT/config/waf.toml" /etc/2t1-waf/waf.toml
  echo "  → /etc/2t1-waf/waf.toml installed"
  echo "  ! REMEMBER to edit it: set [server].listen_tls, tls_cert/tls_key, redirect_to_https_port,"
  echo "    [upstream].address, and most importantly [challenge].hmac_secret."
else
  echo "  → /etc/2t1-waf/waf.toml already exists, leaving alone"
fi
chown -R 2t1waf:2t1waf /etc/2t1-waf

echo "Installing systemd unit…"
install -m 0644 "$REPO_ROOT/deploy/2t1-waf.service" /etc/systemd/system/2t1-waf.service
systemctl daemon-reload
systemctl enable 2t1-waf

echo
echo "Done."
echo "Edit /etc/2t1-waf/waf.toml, then:"
echo "  systemctl start 2t1-waf"
echo "  systemctl status 2t1-waf"
echo "  journalctl -u 2t1-waf -f"
echo
echo "Dashboard token (admin only): tail the logs after start —"
echo "  journalctl -u 2t1-waf -o cat | grep 'admin token'"
