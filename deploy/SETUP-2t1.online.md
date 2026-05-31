# 2t1.online — Kurulum Rehberi (Cloudflare → WAF → nginx → app)

Bu rehber 2t1.online'ı 2t1-Waf ile korumaya alır. Mimari:

```
İnternet → Cloudflare (proxy/turuncu bulut)
         → 2t1-Waf  (origin sunucu :443, TLS'i burada sonlandırır)
         → nginx    (127.0.0.1:8080, düz HTTP)
         → uygulaman
```

WAF en öne (origin'in en dış katmanına) girer çünkü ziyaretçiyi ancak
oradayken gerçekten süzebilir. nginx bir iç katmana iner ve artık 443
dinlemez — onu WAF aldı.

---

## 1) Cloudflare tarafı (panelden)

1. **DNS**: `2t1.online` (ve `www`) A kaydı sunucunun IP'sine baksın,
   **proxy AÇIK** (turuncu bulut).
2. **SSL/TLS → Overview**: modu **Full (strict)** yap.
   (WAF gerçek bir sertifika sunacağı için "Flexible" KULLANMA.)
3. **SSL/TLS → Origin Server → Create Certificate**:
   - Hostlar: `2t1.online`, `*.2t1.online`
   - Üretilen **certificate**'i sunucuda `/etc/2t1-waf/tls/origin.pem`,
     **private key**'i `/etc/2t1-waf/tls/origin.key` olarak kaydet.
4. **(Önerilir) Cloudflare WAF/Security**:
   - Security → Settings: Bot Fight Mode açık.
   - DDoS korumaları zaten otomatik; "Under Attack Mode"u sadece aktif
     saldırıda elle açarsın (bizim WAF'taki UAM'in CF eşdeğeri).
5. **(Önemli) Origin'i kilitle**: Sunucunun firewall'ında 80/443'e
   **sadece Cloudflare IP aralıklarından** gelişe izin ver, gerisini
   kapat. Aksi halde saldırgan Cloudflare'i atlayıp doğrudan IP'ne
   vurur. CF IP listesi: https://www.cloudflare.com/ips/
   ```bash
   # örnek (ufw): sadece CF'den 443'e izin
   for ip in $(curl -s https://www.cloudflare.com/ips-v4); do ufw allow from $ip to any port 443 proto tcp; done
   for ip in $(curl -s https://www.cloudflare.com/ips-v6); do ufw allow from $ip to any port 443 proto tcp; done
   ```

---

## 2) nginx'i iç katmana indir

Şu an nginx muhtemelen 443'te TLS sonlandırıyor. Onu **127.0.0.1:8080
düz HTTP**'ye çek (443'ü WAF'a bırak):

1. `deploy/nginx-behind-waf.conf.example` dosyasını örnek al,
   `upstream app_2t1` içine **kendi uygulamanın portunu** yaz.
2. Eski 443/ssl `server { ... }` bloğunu devre dışı bırak (artık WAF yapıyor).
3. ```bash
   cp deploy/nginx-behind-waf.conf.example /etc/nginx/sites-available/2t1-internal.conf
   ln -sf /etc/nginx/sites-available/2t1-internal.conf /etc/nginx/sites-enabled/
   nginx -t && systemctl reload nginx
   ```

---

## 3) WAF'ı kur

```bash
git clone <repo> 2t1-waf && cd 2t1-waf
git checkout claude/nifty-lamport-jBZnL     # site-crash fix'li branch

# config'i yerleştir
sudo mkdir -p /etc/2t1-waf/tls
sudo cp config/waf.prod.2t1.online.toml /etc/2t1-waf/waf.toml

# ZORUNLU: HMAC secret üret
SECRET=$(openssl rand -base64 48)
sudo sed -i "s#CHANGE-ME-openssl-rand-base64-48#$SECRET#" /etc/2t1-waf/waf.toml

# Cloudflare Origin sertifikalarını yerleştir (adım 1.3)
#   /etc/2t1-waf/tls/origin.pem  ve  /etc/2t1-waf/tls/origin.key

# derle + systemd kur (install.sh release binary'yi build eder)
sudo ./deploy/install.sh
sudo chown -R 2t1waf:2t1waf /etc/2t1-waf
sudo chmod 0640 /etc/2t1-waf/tls/origin.key

sudo systemctl start 2t1-waf
sudo systemctl status 2t1-waf
journalctl -u 2t1-waf -f
```

> Not: `install.sh` config'i `/etc/2t1-waf/waf.toml`'a kopyalarken zaten
> varsa dokunmaz — biz yukarıda prod config'i elle koyduğumuz için sorun
> yok. install.sh'i çalıştırmadan önce config'i koy.

---

## 4) Doğrulama (kritik!)

Cloudflare arkasında **gerçek ziyaretçi IP'sinin** doğru okunduğunu
mutlaka teyit et — yanlışsa tüm rate-limit/ban çöker:

```bash
# Dışarıdan normal ziyaret:
curl -I https://2t1.online/                # 200 dönmeli

# Sunucuda, gerçek IP loglara düşüyor mu? (Cloudflare edge IP'si DEĞİL,
# senin gerçek IP'n görünmeli):
journalctl -u 2t1-waf -o cat | grep '"message":"request"' | tail -3
#   "ip":"<senin-gerçek-IP>"  görmelisin, 173.245.x (CF) değil.
```

Eğer `ip` alanında Cloudflare IP'leri (104.x / 172.x / 173.245.x)
görüyorsan `trusted_proxy_hops` yanlış demektir — bu config'de `1`,
doğrusu bu. Araya başka bir proxy daha koyduysan hop sayısını artır.

---

## 5) Dashboard (yönetim paneli)

Panel sadece localhost'ta (127.0.0.1:9090). Uzaktan erişim için SSH tüneli:

```bash
ssh -L 9090:127.0.0.1:9090 kullanici@2t1.online
# sonra tarayıcıda:  http://127.0.0.1:9090
```

Admin token'ı başlangıç loglarında:
```bash
journalctl -u 2t1-waf -o cat | grep 'admin token'
```

---

## Ayarların anlamı / nereyi ne için değiştirirsin

| Ayar | Dosya | Ne işe yarar |
|---|---|---|
| `trusted_proxy_hops = 1` | waf.toml `[server]` | **CF arkasında zorunlu.** Gerçek IP'yi XFF'den okur. |
| `requests_per_minute` | `[rate_limit]` | Ziyaretçi başına dakikalık tavan. Trafik artarsa yükselt. |
| `[[rate_limit.routes]]` | `[rate_limit]` | Login/giriş uçlarına sıkı brute-force tavanı. |
| `challenge_threshold` / `block_threshold` | `[detection]` | Şüphe skoru eşikleri. Düşürürsen daha agresif. |
| `auto_lockdown` | dashboard (default KAPALI) | Sert "tarayıcı kanıtla" modu. **Bilerek elle aç** — otomatik açılması siteyi kilitliyordu (fix bunu kapattı). |
| Under-Attack (UAM) | dashboard | Aktif saldırıda elle yükselt (Cloudflare "Under Attack Mode" eşdeğeri). |

---

## Saldırı anında ne yaparsın

1. Cloudflare panel → **Security → Under Attack Mode: On** (ilk savunma).
2. WAF dashboard → UAM seviyesini **High** yap (PoW challenge sertleşir).
3. Hâlâ geçiyorsa → dashboard'dan **Lockdown'ı elle aç** (forged tarayıcı
   fingerprintleri 403). Saldırı geçince **geri kapat** — açık unutma,
   bazı meşru istemcileri de zorlar.
