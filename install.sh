#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# ЦВЕТА И ВЫВОД
# ==============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()     { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ==============================================================================
# ПРОВЕРКА ПРАВ
# ==============================================================================
if [[ $EUID -ne 0 ]]; then
   log_err "Этот скрипт должен быть запущен с правами root (sudo)."
fi

# ==============================================================================
# ЗАПРОС И ВАЛИДАЦИЯ ПЕРЕМЕННЫХ
# ==============================================================================
echo -e "\n${GREEN}=== Настройка VK Cloud CDN Моста поверх autoXRAY ===${NC}\n"

read -rp "Введите домен RU VPS (например, ru.jurgenio.xyz): " ORIGIN_DOMAIN
read -rp "Введите домен VK Cloud CDN (например, cdn.jurgenio.xyz): " CDN_HOST
read -rp "Введите путь к потоку xHTTP (по умолчанию: /static/getFile/video/segment.ts): " XHTTP_PATH
XHTTP_PATH=${XHTTP_PATH:-"/static/getFile/video/segment.ts"}

read -rp "Введите локальный порт Xray для VK CDN (по умолчанию: 4443): " LOCAL_PORT
LOCAL_PORT=${LOCAL_PORT:-4443}

read -rp "Введите SSH порт сервера (по умолчанию: 22222): " SSH_PORT
SSH_PORT=${SSH_PORT:-22222}

read -rp "Введите секретный токен подписки (хэш в URL, например: 7JQ1CXnhHeHAGPAYWD2): " SUB_TOKEN

if [[ -z "$ORIGIN_DOMAIN" || -z "$CDN_HOST" || -z "$SUB_TOKEN" ]]; then
    log_err "Все обязательные параметры должны быть заполнены!"
fi

# ==============================================================================
# 1. ТЮНИНГ ЯДРА LINUX (SYSCTL)
# ==============================================================================
log_info "1. Настройка sysctl под высокие нагрузки и BBR..."
cat << 'EOF' > /etc/sysctl.d/99-vless-cdn-bridge.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
fs.file-max = 2097152
EOF
sysctl --system > /dev/null 2>&1
log_success "Параметры sysctl применены."

# ==============================================================================
# 2. ИНТЕГРАЦИЯ VK CDN INBOUND В XRAY
# ==============================================================================
log_info "2. Обновление конфигурации Xray (/usr/local/etc/xray/config.json)..."
XRAY_CONF="/usr/local/etc/xray/config.json"
[[ ! -f "$XRAY_CONF" ]] && log_err "Файл $XRAY_CONF не найден. Убедитесь, что autoXRAY установлен."

python3 - << PYEOF
import json

path = "${XRAY_CONF}"
try:
    with open(path, "r") as f:
        data = json.load(f)

    # Извлекаем UUID из существующего входящего подключения
    users = []
    for inb in data.get("inbounds", []):
        if inb.get("protocol") == "vless":
            users = inb.get("settings", {}).get("clients", [])
            if users:
                break

    if not users:
        users = [{"id": "722ac689-1141-ef19-5a42-7166f89bd485", "encryption": "none"}]

    vk_inbound = {
        "tag": "vk",
        "port": int("${LOCAL_PORT}"),
        "listen": "127.0.0.1",
        "protocol": "vless",
        "settings": {
            "clients": users,
            "decryption": "none"
        },
        "streamSettings": {
            "network": "xhttp",
            "xhttpSettings": {
                "mode": "packet-up",
                "path": "${XHTTP_PATH}",
                "extra": {
                    "uplinkDataPlacement": "cookie",
                    "uplinkDataKey": "x_data",
                    "uplinkHTTPMethod": "GET",
                    "scMaxBufferedPosts": 512
                }
            }
        },
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"]
        }
    }

    # Обновление inbounds
    inbounds = [ib for ib in data.get("inbounds", []) if ib.get("tag") != "vk"]
    inbounds.append(vk_inbound)
    data["inbounds"] = inbounds

    # Обновление routing
    routing = data.get("routing", {})
    rules = routing.get("rules", [])
    
    # Удаляем старое правило vk, если было
    rules = [r for r in rules if not ("vk" in r.get("inboundTag", []))]
    
    # Добавляем маршрутизацию vk в Super_Balancer или первый доступный proxy outbound
    target_outbound = "Super_Balancer"
    out_tags = [o.get("tag") for o in data.get("outbounds", [])]
    if target_outbound not in out_tags and "proxy" in out_tags:
        target_outbound = "proxy"

    rules.insert(0, {
        "type": "field",
        "inboundTag": ["vk"],
        "outboundTag": target_outbound
    })
    
    routing["rules"] = rules
    data["routing"] = routing

    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print("Конфиг Xray успешно обновлен.")
except Exception as e:
    print(f"Ошибка Xray: {e}")
    exit(1)
PYEOF

systemctl restart xray
log_success "Xray перезапущен с поддержкой VK CDN."

# ==============================================================================
# 3. НАСТРОЙКА NGINX ДЛЯ ПРОКСИРОВАНИЯ И ПОДПИСОК
# ==============================================================================
log_info "3. Настройка Nginx (/etc/nginx/sites-available/default)..."
WEB_ROOT="/var/www/${ORIGIN_DOMAIN}"
mkdir -p "$WEB_ROOT"

cat << EOF > /etc/nginx/sites-available/default
server {
    server_name ${ORIGIN_DOMAIN};
    listen unix:/dev/shm/nginx.sock ssl http2 proxy_protocol;
    set_real_ip_from unix:;
    real_ip_header proxy_protocol;

    root ${WEB_ROOT};
    index index.html;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;
    ssl_buffer_size 4k;

    ssl_certificate "/etc/letsencrypt/live/${ORIGIN_DOMAIN}/fullchain.pem";
    ssl_certificate_key "/etc/letsencrypt/live/${ORIGIN_DOMAIN}/privkey.pem";

    # Буферы и таймауты
    keepalive_timeout 300s;
    keepalive_requests 10000;
    send_timeout 3600s;
    client_header_buffer_size 8k;
    large_client_header_buffers 8 16k;
    client_max_body_size 0;
    gzip off;

    # JSON подписка со списком нод
    location = /${SUB_TOKEN}.json {
        default_type application/json;
        add_header Content-Type "application/json; charset=utf-8";
        add_header profile-title "base64:YXV0b1hSQVk=";
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    # Автономный файл config.json
    location = /config.json {
        default_type application/json;
        add_header Content-Type "application/json; charset=utf-8";
        add_header profile-title "base64:8J+HtfCfh7Eg8J+HtfCfh7og0JHQtdC70YvQtSDRgdC/0LjRgdC60Lg=";
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    # HTML страница подписки
    location = /${SUB_TOKEN}.html {
        default_type text/html;
        add_header Content-Type "text/html; charset=utf-8";
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    # XHTTP packet-up проксирование
    location ^~ ${XHTTP_PATH} {
        access_log off;
        error_log /var/log/nginx/xhttp_error.log warn;

        proxy_pass http://127.0.0.1:${LOCAL_PORT};
        proxy_http_version 1.1;

        proxy_set_header Host \$host;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_pass_request_headers on;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_cache off;
        proxy_no_cache 1;
        proxy_cache_bypass 1;
        proxy_next_upstream off;

        proxy_socket_keepalive on;
        proxy_connect_timeout 60s;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        add_header X-Accel-Buffering "no" always;
        add_header Cache-Control "private, no-store, no-cache, max-age=0, must-revalidate" always;
        add_header CDN-Cache-Control "no-store" always;
        add_header Surrogate-Control "no-store" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
    }

    location ~ /\.ht {
        deny all;
    }
}

server {
    listen 80;
    server_name ${ORIGIN_DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF

nginx -t
systemctl restart nginx
log_success "Nginx настроен и перезапущен."

# ==============================================================================
# 4. ГЕНЕРАЦИЯ CONFIG.JSON И ОБНОВЛЕНИЕ JSON-ПОДПИСКИ
# ==============================================================================
log_info "4. Генерация config.json и обновление списка подписки..."

UUID=$(grep -oE '[0-9a-fA-F-]{36}' "$XRAY_CONF" | head -n 1 || echo "722ac689-1141-ef19-5a42-7166f89bd485")

cat << EOF > "${WEB_ROOT}/config.json"
{
  "remarks": "🇳🇱 🇷🇺 Белые списки",
  "_remarks": "🇳🇱 🇷🇺 Белые списки",
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "queryStrategy": "UseIPv4",
    "servers": [
      "1.1.1.1",
      "8.8.8.8",
      {
        "address": "77.88.8.8",
        "domains": [
          "geosite:category-ru"
        ]
      }
    ]
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "port": 10808,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "udp": true,
        "auth": "noauth"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "tag": "http-in",
      "port": 10809,
      "listen": "127.0.0.1",
      "protocol": "http",
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "🇳🇱 🇷🇺 Белые списки",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "${CDN_HOST}",
            "port": 443,
            "users": [
              {
                "id": "${UUID}",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "${CDN_HOST}",
          "alpn": [
            "h2"
          ],
          "fingerprint": "firefox"
        },
        "xhttpSettings": {
          "mode": "packet-up",
          "path": "${XHTTP_PATH}",
          "extra": {
            "xmux": {
              "cMaxReuseTimes": 0,
              "maxConcurrency": "4-8",
              "maxConnections": 0
            },
            "seqKey": "chunk_id",
            "xPaddingKey": "pid",
            "seqPlacement": "query",
            "uplinkDataKey": "x_data",
            "xPaddingBytes": "20-80",
            "xPaddingMethod": "tokenish",
            "uplinkChunkSize": "2048-3072",
            "uplinkHTTPMethod": "GET",
            "xPaddingObfsMode": true,
            "xPaddingPlacement": "query",
            "scMaxEachPostBytes": "4096-8192",
            "uplinkDataPlacement": "cookie",
            "scMinPostsIntervalMs": "10-25"
          }
        }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "domainMatcher": "hybrid",
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "domain:${CDN_HOST}",
          "domain:ya.ru", "domain:yandex.ru", "domain:yandex.net", "domain:yandex.com",
          "domain:yastatic.net", "domain:yandexcloud.net", "full:go.yandex", "domain:kinopoisk.ru",
          "domain:vk.com", "domain:vk.ru", "domain:vkvideo.ru", "domain:okcdn.ru", "domain:ok.ru",
          "domain:userapi.com", "domain:mycdn.me", "domain:cdn-vk.ru", "domain:cdnsix.vk-com.ru",
          "domain:clstorage.net", "domain:mail.ru", "domain:imgsmail.ru", "domain:mrgcdn.ru",
          "domain:max.ru", "domain:oneme.ru", "domain:dzen.ru", "domain:rutube.ru",
          "domain:gosuslugi.ru", "domain:kremlin.ru", "domain:nalog.gov.ru", "domain:cbr.ru",
          "domain:alfabank.ru", "domain:vtb.ru", "domain:psbank.ru", "domain:gazprombank.ru",
          "domain:cdn-tinkoff.ru", "domain:tbank.ru", "domain:tbank-online.com", "domain:sber.ru",
          "domain:sberbank.ru", "domain:ozon.ru", "domain:wildberries.ru", "domain:avito.ru",
          "domain:x5.ru", "domain:x5static.net", "domain:megamarket.ru", "domain:rzd.ru",
          "domain:2gis.ru", "domain:2gis.com", "domain:cian.ru", "domain:hh.ru"
        ]
      },
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": "🇳🇱 🇷🇺 Белые списки"
      }
    ]
  }
}
EOF

# Добавляем в общий файл подписки .json
SUB_JSON_PATH="${WEB_ROOT}/${SUB_TOKEN}.json"
if [[ -f "$SUB_JSON_PATH" ]]; then
python3 - << PYEOF
import json

path = "${SUB_JSON_PATH}"
try:
    with open(path, "r") as f:
        data = json.load(f)

    cdn_profile = {
        "tag": "🇳🇱 🇷🇺 Белые списки",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": "${CDN_HOST}",
                "port": 443,
                "users": [{
                    "id": "${UUID}",
                    "encryption": "none"
                }]
            }]
        },
        "streamSettings": {
            "network": "xhttp",
            "security": "tls",
            "tlsSettings": {
                "serverName": "${CDN_HOST}",
                "alpn": ["h2"],
                "fingerprint": "firefox"
            },
            "xhttpSettings": {
                "mode": "packet-up",
                "path": "${XHTTP_PATH}",
                "extra": {
                    "xmux": {"cMaxReuseTimes": 0, "maxConcurrency": "4-8", "maxConnections": 0},
                    "seqKey": "chunk_id",
                    "xPaddingKey": "pid",
                    "seqPlacement": "query",
                    "uplinkDataKey": "x_data",
                    "xPaddingBytes": "20-80",
                    "xPaddingMethod": "tokenish",
                    "uplinkChunkSize": "2048-3072",
                    "uplinkHTTPMethod": "GET",
                    "xPaddingObfsMode": True,
                    "xPaddingPlacement": "query",
                    "scMaxEachPostBytes": "4096-8192",
                    "uplinkDataPlacement": "cookie",
                    "scMinPostsIntervalMs": "10-25"
                }
            }
        }
    }

    if isinstance(data, list):
        data = [item for item in data if not (isinstance(item, dict) and item.get("tag") == "🇳🇱 🇷🇺 Белые списки")]
        data.insert(0, cdn_profile)
    elif isinstance(data, dict):
        outbounds = data.get("outbounds", [])
        outbounds = [o for o in outbounds if o.get("tag") != "🇳🇱 🇷🇺 Белые списки"]
        outbounds.insert(0, cdn_profile)
        data["outbounds"] = outbounds

    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
except Exception as e:
    print(f"Ошибка добавления в подписку: {e}")
PYEOF
fi

# ==============================================================================
# 5. ОБНОВЛЕНИЕ HTML ПОРТАЛА
# ==============================================================================
log_info "5. Формирование HTML-страницы подписки..."
FULL_JSON_CONTENT=$(cat "${WEB_ROOT}/config.json")

cat << EOF > "${WEB_ROOT}/${SUB_TOKEN}.html"
<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>autoXRAY bridge configs</title>
<link rel="icon" type="image/svg+xml" href='data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMDBCRkZGIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBhdGggZD0iTTIxIDJsLTIgMm0tNy42MSA3LjYxYTUuNSA1LjUgMCAxIDEtNy43NzggNy43NzggNS41IDUuNSAwIDAgMSA3Ljc3Ny03Ljc3N3ptMCAwTDE1LjUgNy41bTAgMGwzIDNMMjIgN2wtMy0zbS0zLjUgMy41TDE5IDQiLz48L3N2Zz4='>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
body{font-family:monospace;background:#121212;color:#e0e0e0;padding:10px;max-width:900px;margin:0 auto}h2{color:#c3e88d;border-top:2px solid #333;padding-top:20px;margin:15px 0 10px;font-size:18px}.config-row{background:#1e1e1e;border:1px solid #333;border-radius:6px;padding:5px;display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:8px}.config-label{background:#2c2c2c;color:#82aaff;padding:6px 10px;border-radius:4px;font-weight:700;font-size:13px;white-space:nowrap;min-width:140px;text-align:center}.config-code{flex:1;white-space:nowrap;overflow-x:auto;padding:8px;background:#121212;border-radius:4px;color:#c3e88d;font-size:12px;scrollbar-width:none}.config-code::-webkit-scrollbar{display:none}.btn-action{border:1px solid #555;padding:6px 12px;border-radius:4px;cursor:pointer;font-weight:700;font-size:12px;transition:all .2s;height:32px;display:flex;align-items:center;justify-content:center;text-decoration:none}.copy-btn{background:#333;color:#e0e0e0;min-width:60px}.copy-btn:hover{background:#c3e88d;color:#121212;border-color:#c3e88d}.qr-btn{background:#333;color:#82aaff;border-color:#82aaff;min-width:40px}.qr-btn:hover{background:#82aaff;color:#121212}.dl-btn{background:#333;color:#ffcb6b;border-color:#ffcb6b;min-width:60px}.dl-btn:hover{background:#ffcb6b;color:#121212}.btn-group{display:flex;gap:10px;margin:10px 0 20px}.btn{flex:1;background:#2c2c2c;color:#c3e88d;border:1px solid #c3e88d;padding:10px;text-align:center;border-radius:6px;text-decoration:none;font-weight:700;font-size:14px}.btn:hover{background:#c3e88d;color:#121212}.btn.download{border-color:#82aaff;color:#82aaff}.btn.download:hover{background:#82aaff;color:#121212}.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.85);z-index:999;justify-content:center;align-items:center;backdrop-filter:blur(3px)}.modal-content{background:#1e1e1e;padding:20px;border-radius:10px;border:1px solid #82aaff;text-align:center}#qrcode{background:#fff;padding:10px;border-radius:6px;margin-bottom:10px}.close-modal-btn{background:#c31e1e;color:#fff;border:none;padding:8px 20px;border-radius:4px;cursor:pointer}@media(max-width:600px){.config-label{width:100%;margin-bottom:2px}.config-code{min-width:100%;order:3}.btn-action{flex:1;order:2}}
</style>
<script>
function copyText(e,t){navigator.clipboard.writeText(document.getElementById(e).textContent).then(()=>{let o=t.innerText;t.innerText="OK",t.style.cssText="background:#c3e88d;color:#121212",setTimeout(()=>{t.innerText=o,t.style.cssText=""},1500)}).catch(e=>console.error(e))}
function showQR(e){let t=document.getElementById(e).textContent,o=document.getElementById("qrModal"),n=document.getElementById("qrcode");n.innerHTML="",new QRCode(n,{text:t,width:256,height:256,colorDark:"#000000",colorLight:"#ffffff",correctLevel:QRCode.CorrectLevel.L}),o.style.display="flex"}
function closeModal(){document.getElementById("qrModal").style.display="none"}
window.onclick=function(e){e.target==document.getElementById("qrModal")&&closeModal()};
</script>
</head><body>

<h2>📂 Ссылка на подписку (список нод)</h2>
<div class="config-row">
    <div class="config-label">Subscription URL</div>
    <div class="config-code" id="subLink">https://${ORIGIN_DOMAIN}/${SUB_TOKEN}.json</div>
    <button class="btn-action copy-btn" onclick="copyText('subLink', this)">Copy</button>
    <button class="btn-action qr-btn" onclick="showQR('subLink')">QR</button>
</div>

<h2>📱 Приложение HAPP (Windows/Android/iOS/MAC/Linux)</h2>
<div class="btn-group">
    <a href="happ://add/https://${ORIGIN_DOMAIN}/${SUB_TOKEN}.json" class="btn">⚡ Add to HAPP</a>
    <a href="https://www.happ.su/main/ru" target="_blank" class="btn download">⬇️ Download App</a>
</div>

<h2>🛡️ Полный JSON-конфиг со встроенными правилами (Goal B)</h2>
<div class="config-row">
    <div class="config-label">🇳🇱 🇷🇺 Full JSON</div>
    <div class="config-code" id="jsonConfigUrl">https://${ORIGIN_DOMAIN}/config.json</div>
    <button class="btn-action copy-btn" onclick="copyText('fullJsonRaw', this)">Copy JSON</button>
    <a href="/config.json" download="config.json" class="btn-action dl-btn">Download</a>
</div>
<div id="fullJsonRaw" style="display:none;">${FULL_JSON_CONTENT}</div>

<div><a style="color:white;margin:40px auto 20px;display:block;text-align:center;" href="https://github.com/xVRVx/autoXRAY">https://github.com/xVRVx/autoXRAY</a></div>

<div id="qrModal" class="modal-overlay"><div class="modal-content"><div id="qrcode"></div><button class="close-modal-btn" onclick="closeModal()">Close</button></div></div>
</body></html>
EOF

chown -R www-data:www-data "$WEB_ROOT"
chmod -R 644 "${WEB_ROOT}"/*
chmod 755 "$WEB_ROOT"

# ==============================================================================
# 6. ФАЕРВОЛ UFW
# ==============================================================================
log_info "6. Конфигурация UFW фаервола..."
ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1

ufw allow "${SSH_PORT}/tcp" comment 'SSH' > /dev/null 2>&1
ufw allow 80/tcp comment 'Certbot HTTP-01 challenge' > /dev/null 2>&1
ufw allow 443/tcp comment 'Xray Reality and CDN ingress' > /dev/null 2>&1

ufw --force enable > /dev/null 2>&1
log_success "Фаервол UFW включен (порты: ${SSH_PORT}, 80, 443)."

# ==============================================================================
# ИТОГОВЫЙ СТАТУС
# ==============================================================================
echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}      Установка и настройка успешно завершены!        ${NC}"
echo -e "${GREEN}======================================================${NC}\n"
echo -e " Веб-портал подписки: ${BLUE}https://${ORIGIN_DOMAIN}/${SUB_TOKEN}.html${NC}"
echo -e " URL подписки для HAPP: ${BLUE}https://${ORIGIN_DOMAIN}/${SUB_TOKEN}.json${NC}"
echo -e " Автономный JSON-файл:  ${BLUE}https://${ORIGIN_DOMAIN}/config.json${NC}\n"
