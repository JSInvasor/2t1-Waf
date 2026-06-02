#!/usr/bin/env bash
# 2t1-Waf — WAF'ı GÜVENLİ KAPATMA / yoldan çıkarma.
#
# Neden script gerekiyor: WAF şu an :443'te TLS'i KENDİSİ sonlandırıyor
# (Cloudflare → WAF:443 → nginx:8082 → site). Sadece "systemctl stop 2t1-waf"
# dersen 443'ü kimse dinlemez ve SİTE KOMPLE DÜŞER. Bu script WAF'ı durdurur
# VE 443'ü tekrar nginx'e TLS'le verir, böylece site ayakta kalır:
#
#     ÖNCE:  Cloudflare → WAF(:443) → nginx(127.0.0.1:8082) → site
#     SONRA: Cloudflare → nginx(:443, TLS)               → site
#
# Geri almak için (WAF'ı yeniden aç):  bkz. en alttaki "GERİ ALMA" notu.
#
# Kullanım (sunucuda, root):   sudo ./deploy/disable-waf.sh
#
# Ortam değişkenleriyle override edebilirsin:
#   WEBROOT=/var/www/2t1.online/html  SERVER_NAMES="2t1.online www.2t1.online" \
#   CERT_SRC=/etc/2t1-waf/tls  sudo -E ./deploy/disable-waf.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "bu script root gerektirir (sudo)"; exit 1; fi

WEBROOT="${WEBROOT:-/var/www/2t1.online/html}"
SERVER_NAMES="${SERVER_NAMES:-2t1.online www.2t1.online}"
CERT_SRC="${CERT_SRC:-/etc/2t1-waf/tls}"     # WAF'ın kullandığı Cloudflare Origin cert
CERT_DST="/etc/ssl/2t1.online"
SERVICE="2t1-waf"

say(){ printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m[!] %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
say "1/5  WAF servisini durduruyorum ve açılışta başlamasını kapatıyorum"
if systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE}.service"; then
  systemctl disable --now "${SERVICE}" || true
  echo "    ${SERVICE} durduruldu + disable edildi."
else
  warn "${SERVICE}.service bulunamadı (zaten kaldırılmış olabilir) — devam."
fi

# ---------------------------------------------------------------------------
say "2/5  Cloudflare Origin sertifikasını nginx'in okuyabileceği yere koyuyorum"
mkdir -p "${CERT_DST}"
if [[ -f "${CERT_SRC}/origin.pem" && -f "${CERT_SRC}/origin.key" ]]; then
  install -m 0644 "${CERT_SRC}/origin.pem" "${CERT_DST}/origin.pem"
  install -m 0600 "${CERT_SRC}/origin.key" "${CERT_DST}/origin.key"
  echo "    ${CERT_SRC}/origin.{pem,key}  →  ${CERT_DST}/"
else
  warn "Cloudflare Origin cert ${CERT_SRC}/origin.{pem,key} altında bulunamadı."
  warn "nginx 443'te TLS sunamaz. Cloudflare panel → SSL/TLS → Origin Server'dan"
  warn "üretip ${CERT_DST}/origin.pem ve ${CERT_DST}/origin.key olarak koy, sonra tekrar çalıştır."
fi

# ---------------------------------------------------------------------------
say "3/5  Cloudflare gerçek-IP aralıklarını nginx'e tanıtıyorum (best-effort)"
CF_CONF="/etc/nginx/conf.d/cloudflare-realip.conf"
if command -v curl >/dev/null 2>&1 && \
   v4=$(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v4 2>/dev/null) && \
   v6=$(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v6 2>/dev/null); then
  {
    echo "# Cloudflare → nginx doğrudan: gerçek ziyaretçi IP'si CF-Connecting-IP'den."
    echo "# disable-waf.sh tarafından üretildi."
    for ip in $v4 $v6; do echo "set_real_ip_from ${ip};"; done
    echo "real_ip_header CF-Connecting-IP;"
    echo "real_ip_recursive on;"
  } > "${CF_CONF}"
  echo "    ${CF_CONF} yazıldı ($(grep -c set_real_ip_from "${CF_CONF}") CF aralığı)."
else
  warn "Cloudflare IP listesi çekilemedi (ağ?). Log'larda CF edge IP görünebilir — güvenlik etkisi yok."
fi

# ---------------------------------------------------------------------------
say "4/5  nginx vhost'u kuruyorum (Cloudflare → nginx:443 → site)"
read -r -d '' VHOST <<EOF || true
server {
    listen 80;
    listen [::]:80;
    server_name ${SERVER_NAMES};
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name ${SERVER_NAMES};

    ssl_certificate     ${CERT_DST}/origin.pem;
    ssl_certificate_key ${CERT_DST}/origin.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    root  ${WEBROOT};
    index index.html index.htm;
    client_max_body_size 1m;

    access_log /var/log/nginx/2t1.access.log;
    error_log  /var/log/nginx/2t1.error.log;

    location / { try_files \$uri \$uri/ =404; }
}
EOF

if [[ -d /etc/nginx/sites-available ]]; then
  printf '%s\n' "$VHOST" > /etc/nginx/sites-available/2t1.online-direct.conf
  ln -sf /etc/nginx/sites-available/2t1.online-direct.conf /etc/nginx/sites-enabled/2t1.online-direct.conf
  # WAF arkasındaki iç vhost'u (8082 düz HTTP) devre dışı bırak — çakışma olmasın.
  rm -f /etc/nginx/sites-enabled/2t1-internal.conf
  echo "    /etc/nginx/sites-available/2t1.online-direct.conf kuruldu ve enable edildi."
else
  printf '%s\n' "$VHOST" > /etc/nginx/conf.d/2t1.online-direct.conf
  echo "    /etc/nginx/conf.d/2t1.online-direct.conf kuruldu."
fi
warn "Eski 443/TLS server bloğun (WAF öncesi) hâlâ duruyorsa onu da kaldır — port çakışması yapar."

# ---------------------------------------------------------------------------
say "5/5  nginx config testi + reload, sonra doğrulama"
if nginx -t; then
  systemctl reload nginx 2>/dev/null || systemctl restart nginx
  echo "    nginx reload edildi."
else
  warn "nginx -t BAŞARISIZ. Yukarıdaki hatayı düzelt; reload YAPILMADI (site mevcut haliyle ayakta)."
  exit 1
fi

echo
say "DOĞRULAMA"
echo "  443 dinleniyor mu:"; ss -ltn 2>/dev/null | grep -E ':443\b' || warn "443 dinleyen yok!"
code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 https://127.0.0.1/ -H "Host: ${SERVER_NAMES%% *}" || echo "ERR")
echo "  local https istek kodu: ${code}  (200/301/302 beklenir)"

cat <<'NOTE'

============================================================================
 BİTTİ — WAF artık yolda DEĞİL. Akış:  Cloudflare → nginx:443 → site
============================================================================
 Cloudflare tarafı (panel) — ÖNEMLİ:
   • SSL/TLS modu "Full (strict)" kalabilir (Origin cert sunuyoruz).
   • WAF'ın yaptığı bot/DDoS challenge'ı artık YOK. İstersen Cloudflare
     "Bot Fight Mode" ve gerekirse "Under Attack Mode"u panelden aç.
   • SQLi/XSS gibi uygulama-katmanı taraması da artık YOK (CF ücretsiz planda yok).

 GERİ ALMA (WAF'ı yeniden aç):
   rm -f /etc/nginx/sites-enabled/2t1.online-direct.conf
   ln -sf /etc/nginx/sites-available/2t1-internal.conf /etc/nginx/sites-enabled/  # WAF-arkası iç vhost
   nginx -t && systemctl reload nginx
   systemctl enable --now 2t1-waf
============================================================================
NOTE
