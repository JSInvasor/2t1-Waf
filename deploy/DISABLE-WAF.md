# WAF'ı kapatma — 2t1.online

WAF'ı tamamen yoldan çıkarıp **Cloudflare → nginx:443 → site** akışına dönmek için.

## Neden tek komutla "stop" yetmez
WAF şu an `:443`'te TLS'i kendisi sonlandırıyor. Sadece `systemctl stop 2t1-waf`
dersen 443'ü kimse dinlemez ve **site komple düşer**. Bu yüzden 443'ü aynı anda
nginx'e geri vermek gerekir — `disable-waf.sh` bunu güvenli yapar.

## Yapılacak (sunucuda, root)
```bash
sudo ./deploy/disable-waf.sh
```
Script sırayla:
1. `2t1-waf` servisini durdurur + açılışta başlamasını kapatır.
2. Cloudflare Origin sertifikasını (`/etc/2t1-waf/tls/origin.*`) nginx'in
   okuyabileceği `/etc/ssl/2t1.online/`'a kopyalar.
3. Cloudflare IP aralıklarını nginx'e tanıtır (gerçek ziyaretçi IP'si için).
4. `:443`'te TLS sonlandıran nginx vhost'unu kurar (statik site; proxy için
   şablon içinde not var).
5. `nginx -t` + reload eder, sonra 443'ü ve local HTTPS isteğini doğrular.

`nginx -t` başarısız olursa reload **yapılmaz** — site mevcut haliyle ayakta kalır.

## Sonrası (Cloudflare panel)
- SSL/TLS modu **Full (strict)** kalabilir (Origin cert sunuyoruz).
- WAF'ın bot/DDoS challenge'ı ve SQLi/XSS taraması artık **yok**. İstersen
  Cloudflare **Bot Fight Mode** / gerekirse **Under Attack Mode** panelden aç.

## Geri alma (WAF'ı yeniden aç)
```bash
rm -f /etc/nginx/sites-enabled/2t1.online-direct.conf
# WAF-arkası iç vhost'u (127.0.0.1:8082 düz HTTP) tekrar enable et:
ln -sf /etc/nginx/sites-available/2t1-internal.conf /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
systemctl enable --now 2t1-waf
```
