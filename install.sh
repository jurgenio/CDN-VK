#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# ЦВЕТА И ВЫВОД
# ==============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()     { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ==============================================================================
# ПРОВЕРКА ПРАВ
# ==============================================================================
if [[ $EUID -ne 0 ]]; then
   log_err "Этот скрипт должен запускаться от имени root (sudo)."
fi

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}  VK Cloud CDN Bridge + Smart Routing + Security      ${NC}"
echo -e "${GREEN}======================================================${NC}\n"

# ==============================================================================
# 0. ПРОВЕРКА ЗАВИСИМОСТЕЙ И АВТОСБОР ДАННЫХ ИЗ AUTOXRAY
# ==============================================================================
XRAY_CONF="/usr/local/etc/xray/config.json"
NGINX_CONF="/etc/nginx/sites-available/default"

[[ ! -f "$XRAY_CONF" ]] && log_err "Файл $XRAY_CONF не найден. Сначала установите autoXRAY."
[[ ! -f "$NGINX_CONF" ]] && log_err "Конфигурация Nginx не найдена: $NGINX_CONF."

log_info "Установка базовых утилит (fail2ban, ufw, python3)..."
apt-get update -qq && apt-get install -y -qq fail2ban ufw python3 curl > /dev/null 2>&1

log_info "Автоматическое извлечение параметров autoXRAY..."

# Python-парсер системного окружения autoXRAY
EXTRACTED_VARS=$(python3 - << 'PYEOF'
import json, re, os, glob

xray_path = "/usr/local/etc/xray/config.json"
nginx_path = "/etc/nginx/sites-available/default"

data = {}
try:
    with open(xray_path) as f:
        xray_data = json.load(f)
except:
    xray_data = {}

# 1. UUID
uuid = ""
for ib in xray_data.get("inbounds", []):
    for u in ib.get("settings", {}).get("clients", []):
        if "id" in u:
            uuid = u["id"]
            break
    if uuid: break

# 2. Reality ShortID & PrivateKey
sid = ""
privkey = ""
for ib in xray_data.get("inbounds", []):
    rs = ib.get("streamSettings", {}).get("realitySettings", {})
    if rs:
        privkey = rs.get("privateKey", "")
        sids = rs.get("shortIds", [])
        sid = sids[0] if sids else ""
        break

# 3. EU IP (из outbounds)
eu_ip = ""
for ob in xray_data.get("outbounds", []):
    for vn in ob.get("settings", {}).get("vnext", []):
        addr = vn.get("address", "")
        if addr and not addr.startswith("127.") and not addr.startswith("ru."):
            eu_ip = addr
            break
    if eu_ip: break

# 4. Domain
domain = ""
if os.path.exists(nginx_path):
    with open(nginx_path) as f:
        content = f.read()
        m = re.search(r'server_name\s+([^;\s]+);', content)
        if m: domain = m.group(1)

# 5. Token подписки
token = ""
json_files = glob.glob("/var/www/*/*.json")
for jf in json_files:
    fname = os.path.basename(jf)
    if fname not in ["config.json", "config-abroad.json", "all-in-one.json"]:
        token = fname.replace(".json", "")
        break

# 6. Public Key Reality (из HTML)
pbk = ""
html_files = glob.glob("/var/www/*/*.html")
for hf in html_files:
    try:
        with open(hf) as f:
            c = f.read()
            m = re.search(r'pbk=([a-zA-Z0-9_-]+)', c)
            if m:
                pbk = m.group(1)
                break
    except: pass

print(f"AUTO_UUID='{uuid}'")
print(f"AUTO_DOMAIN='{domain}'")
print(f"AUTO_TOKEN='{token}'")
print(f"AUTO_EU_IP='{eu_ip}'")
print(f"AUTO_SID='{sid}'")
print(f"AUTO_PBK='{pbk}'")
PYEOF
)

eval "$EXTRACTED_VARS"

# Определение текущего SSH порта
AUTO_SSH=$(grep -m1 -E "^Port\s+[0-9]+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)
if [[ -z "$AUTO_SSH" ]]; then
    AUTO_SSH=$(ss -tlpn | grep -E "sshd|ssh" | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1 || true)
fi
AUTO_SSH=${AUTO_SSH:-22222}

# ==============================================================================
# ДИАЛОГ С ПОЛЬЗОВАТЕЛЕМ (С АВТОПОДСТАНОВКОЙ)
# ==============================================================================
echo ""
read -rp "1. Домен VK Cloud CDN (например, cdn.jurgenio.xyz): " CDN_HOST
[[ -z "$CDN_HOST" ]] && log_err "Домен CDN не может быть пустым."

read -rp "2. Домен RU VPS [Определено: ${AUTO_DOMAIN}]: " ORIGIN_DOMAIN
ORIGIN_DOMAIN=${ORIGIN_DOMAIN:-$AUTO_DOMAIN}
[[ -z "$ORIGIN_DOMAIN" ]] && log_err "Домен RU VPS не задан."

read -rp "3. Секретный токен подписки [Определено: ${AUTO_TOKEN}]: " SUB_TOKEN
SUB_TOKEN=${SUB_TOKEN:-$AUTO_TOKEN}
[[ -z "$SUB_TOKEN" ]] && log_err "Токен подписки не задан."

read -rp "4. IP адрес EU VPS [Определено: ${AUTO_EU_IP}]: " EU_IP
EU_IP=${EU_IP:-$AUTO_EU_IP}

read -rp "5. Новый SSH порт сервера [по умолчанию: 22222]: " NEW_SSH_PORT
NEW_SSH_PORT=${NEW_SSH_PORT:-22222}

echo -e "\n${YELLOW}Вставьте ваш публичный SSH-ключ (начинается с ssh-ed25519 или ssh-rsa):${NC}"
echo -e "${YELLOW}(Если ключ уже добавлен на сервер, нажмите Enter)${NC}"
read -rp "SSH Public Key: " SSH_PUB_KEY

if [[ -z "$SSH_PUB_KEY" && ! -s ~/.ssh/authorized_keys ]]; then
    log_err "SSH-ключ не передан, а файл ~/.ssh/authorized_keys пуст! Отключение паролей заблокирует доступ к серверу."
fi

UUID="${AUTO_UUID:-722ac689-1141-ef19-5a42-7166f89bd485}"
PBK="${AUTO_PBK:-hVWQuKYZe14Usj0b_0AN8hGfm5Ju8L63AY9J2f_mOR0}"
SID="${AUTO_SID:-1c9f2ccd2cdb5192}"
XHTTP_PATH="/static/getFile/video/segment.ts"
LOCAL_PORT=4443

# ==============================================================================
# 1. НАСТРОЙКА SSH КЛЮЧЕЙ, ПОРТА И ОТКЛЮЧЕНИЕ ПАРОЛЕЙ
# ==============================================================================
log_info "1/7. Настройка SSH (порт ${NEW_SSH_PORT}, доступ только по ключам)..."

mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

if [[ -n "$SSH_PUB_KEY" ]]; then
    if ! grep -Fxq "$SSH_PUB_KEY" ~/.ssh/authorized_keys; then
        echo "$SSH_PUB_KEY" >> ~/.ssh/authorized_keys
        log_success "SSH-ключ добавлен в ~/.ssh/authorized_keys."
    fi
fi

# Настройка основного sshd_config
sed -i "s/^#\?Port .*/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

# Переопределение парольного входа в дополнительных конфигах Ubuntu (sshd_config.d/*.conf)
if ls /etc/ssh/sshd_config.d/*.conf 1> /dev/null 2>&1; then
    sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
    sed -i 's/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
fi

# Переопределение systemd socket activation (Ubuntu 22.10+ / 24.04 / Debian 12)
if systemctl is-active --quiet ssh.socket 2>/dev/null || systemctl list-unit-files | grep -q "ssh.socket"; then
    mkdir -p /etc/systemd/system/ssh.socket.d
    cat << EOF > /etc/systemd/system/ssh.socket.d/override.conf
[Socket]
ListenStream=
ListenStream=${NEW_SSH_PORT}
EOF
    systemctl daemon-reload
    systemctl restart ssh.socket || true
fi

sshd -t || log_err "Ошибка в конфигурации sshd! Проверьте параметры вручную."
systemctl restart ssh || systemctl restart sshd || true
log_success "Служба SSH перезапущена на порту ${NEW_SSH_PORT}."

# ==============================================================================
# 2. ТЮНИНГ ЯДРА LINUX (SYSCTL)
# ==============================================================================
log_info "2/7. Применение сетевого тюнинга ядра (BBR, буферы)..."
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
# 3. КОНФИГУРАЦИЯ XRAY (INBOUND VK + ДВУСТОРОННИЙ РОУТИНГ)
# ==============================================================================
log_info "3/7. Обновление ядра Xray (VK inbound + RU direct routing)..."

python3 - << PYEOF
import json

path = "${XRAY_CONF}"
with open(path, "r") as f:
    data = json.load(f)

users = [{"id": "${UUID}", "encryption": "none"}]

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

# Обновляем Inbounds
inbounds = [ib for ib in data.get("inbounds", []) if ib.get("tag") != "vk"]
inbounds.append(vk_inbound)
data["inbounds"] = inbounds

# Настройка целевого выхода для моста
target_outbound = "Super_Balancer"
out_tags = [o.get("tag") for o in data.get("outbounds", [])]
if target_outbound not in out_tags:
    target_outbound = "proxy" if "proxy" in out_tags else (out_tags[0] if out_tags else "direct")

routing = data.get("routing", {})
rules = routing.get("rules", [])

# Очистка предыдущих специфических правил
rules = [r for r in rules if not ("vk" in r.get("inboundTag", []))]
rules = [r for r in rules if r.get("domain") != ["geosite:category-ru", "domain:ru", "domain:su", "domain:xn--p1ai"]]

# 1. CDN трафик -> в балансировщик/мост на EU
rules.insert(0, {
    "type": "field",
    "inboundTag": ["vk"],
    "outboundTag": target_outbound
})

# 2. Трафик из-за границы к сервисам РФ -> прямой выход в интернет РФ
rules.insert(1, {
    "type": "field",
    "domain": ["geosite:category-ru", "domain:ru", "domain:su", "domain:xn--p1ai"],
    "outboundTag": "direct"
})
rules.insert(2, {
    "type": "field",
    "ip": ["geoip:ru"],
    "outboundTag": "direct"
})

routing["rules"] = rules
data["routing"] = routing

with open(path, "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
PYEOF

xray run -test -config "$XRAY_CONF" > /dev/null 2>&1 || log_err "Ошибка в сгенерированном конфиге Xray!"
systemctl restart xray
log_success "Xray перезапущен и протестирован."

# ==============================================================================
# 4. НАСТРОЙКА NGINX
# ==============================================================================
log_info "4/7. Настройка Nginx..."
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

    keepalive_timeout 300s;
    keepalive_requests 10000;
    send_timeout 3600s;
    client_header_buffer_size 8k;
    large_client_header_buffers 8 16k;
    client_max_body_size 0;
    gzip off;

    location = /all-in-one.json {
        default_type application/json;
        add_header Content-Type "application/json; charset=utf-8" always;
        add_header profile-title "base64:8J+PhPCfj77igI3imYLvuI8gSnVyZ2VuVlBO" always;
        add_header profile-color "#5C3A86" always;
        add_header subscription-userinfo "upload=0; download=0; total=1099511627776; expire=1999999999" always;
        add_header announce "base64:0JHQtdC70YvQtSDRgdC/0LjRgdC60Lgg4oCUINGC0L7Qu9GM0LrQviDQs9C70YPRiNC40LvQutC4IExURQrQl9Cw0LPRgNCw0L3QuNGG0LAg4oCUINCx0LDQvdC60Lgg0LIg0L/QvtC10LfQtNC60LDRhArQnNC+0YHRgtGLIFJVPkVVIOKAlCDQutCw0YHQutCw0LQg0YfQtdGA0LXQtyDQoNGEIHwgzrA=" always;
        add_header profile-update-interval "12" always;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
    }

    location = /${SUB_TOKEN}.json {
        default_type application/json;
        add_header Content-Type "application/json; charset=utf-8";
        add_header profile-title "base64:YXV0b1hSQVk=";
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    location = /config.json {
        default_type application/json;
        add_header Content-Type "application/json; charset=utf-8";
        add_header profile-title "base64:8J+HtfCfh7Eg8J+HtfCfh7og0JHQtdC70YvQtSDRgdC/0LjRgdC60Lg=";
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    location = /config-abroad.json {
        default_type application/json;
        add_header Content-Type "application/json; charset=utf-8";
        add_header profile-title "base64:8J+HtfCfh7og4pyI77iPINCc0LjRgCAo0KLQvtC70YzQutC+INCg0KQp";
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    location = /${SUB_TOKEN}.html {
        default_type text/html;
        add_header Content-Type "text/html; charset=utf-8";
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

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

nginx -t > /dev/null 2>&1 || log_err "Ошибка конфигурации Nginx!"
systemctl restart nginx
log_success "Nginx перезапущен и работает."

# ==============================================================================
# 5. ГЕНЕРАЦИЯ КЛИЕНТСКИХ JSON
# ==============================================================================
log_info "5/7. Генерация файлов конфигурации (config.json, config-abroad.json, all-in-one.json)..."

# 5.1. РФ -> Мир (Белые списки через CDN)
cat << EOF > "${WEB_ROOT}/config.json"
{
  "remarks": "🇳🇱 🇷🇺 Белые списки",
  "_remarks": "🇳🇱 🇷🇺 Белые списки",
  "log": { "loglevel": "warning" },
  "dns": {
    "queryStrategy": "UseIPv4",
    "servers": [
      "1.1.1.1",
      "8.8.8.8",
      { "address": "77.88.8.8", "domains": [ "geosite:category-ru" ] }
    ]
  },
  "inbounds": [
    { "tag": "socks-in", "port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true, "auth": "noauth" }, "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ] } },
    { "tag": "http-in", "port": 10809, "listen": "127.0.0.1", "protocol": "http", "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ] } }
  ],
  "outbounds": [
    {
      "tag": "🇳🇱 🇷🇺 Белые списки",
      "protocol": "vless",
      "settings": {
        "vnext": [ { "address": "${CDN_HOST}", "port": 443, "users": [ { "id": "${UUID}", "encryption": "none" } ] } ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": { "serverName": "${CDN_HOST}", "alpn": [ "h2" ], "fingerprint": "firefox" },
        "xhttpSettings": {
          "mode": "packet-up",
          "path": "${XHTTP_PATH}",
          "extra": {
            "xmux": { "cMaxReuseTimes": 0, "maxConcurrency": "4-8", "maxConnections": 0 },
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
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "domainMatcher": "hybrid",
    "rules": [
      { "type": "field", "protocol": [ "bittorrent" ], "outboundTag": "block" },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "domain:${CDN_HOST}",
          "domain:ya.ru", "domain:yandex.ru", "domain:yandex.net", "domain:yandex.com", "domain:yastatic.net", "domain:yandexcloud.net", "full:go.yandex", "domain:kinopoisk.ru",
          "domain:vk.com", "domain:vk.ru", "domain:vkvideo.ru", "domain:okcdn.ru", "domain:ok.ru", "domain:userapi.com", "domain:mycdn.me", "domain:cdn-vk.ru", "domain:cdnsix.vk-com.ru",
          "domain:clstorage.net", "domain:mail.ru", "domain:imgsmail.ru", "domain:mrgcdn.ru", "domain:max.ru", "domain:oneme.ru", "domain:dzen.ru", "domain:rutube.ru",
          "domain:gosuslugi.ru", "domain:kremlin.ru", "domain:nalog.gov.ru", "domain:cbr.ru", "domain:alfabank.ru", "domain:vtb.ru", "domain:psbank.ru", "domain:gazprombank.ru",
          "domain:cdn-tinkoff.ru", "domain:tbank.ru", "domain:tbank-online.com", "domain:sber.ru", "domain:sberbank.ru", "domain:ozon.ru", "domain:wildberries.ru", "domain:avito.ru",
          "domain:x5.ru", "domain:x5static.net", "domain:megamarket.ru", "domain:rzd.ru", "domain:2gis.ru", "domain:2gis.com", "domain:cian.ru", "domain:hh.ru"
        ]
      },
      { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "direct" },
      { "type": "field", "network": "tcp,udp", "outboundTag": "🇳🇱 🇷🇺 Белые списки" }
    ]
  }
}
EOF

# 5.2. Заграница -> РФ
cat << EOF > "${WEB_ROOT}/config-abroad.json"
{
  "remarks": "🇷🇺 ✈️ Заграница (Только RU сервисы)",
  "_remarks": "🇷🇺 ✈️ Заграница (Только RU сервисы)",
  "log": { "loglevel": "warning" },
  "dns": {
    "queryStrategy": "UseIPv4",
    "servers": [
      { "address": "77.88.8.8", "domains": [ "geosite:category-ru", "domain:ru", "domain:su", "domain:xn--p1ai" ] },
      "1.1.1.1",
      "8.8.8.8"
    ]
  },
  "inbounds": [
    { "tag": "socks-in", "port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": true, "auth": "noauth" }, "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ] } },
    { "tag": "http-in", "port": 10809, "listen": "127.0.0.1", "protocol": "http", "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ] } }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    {
      "tag": "🇷🇺 RU VPS Exit",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "${ORIGIN_DOMAIN}",
            "port": 443,
            "users": [ { "id": "${UUID}", "flow": "xtls-rprx-vision", "encryption": "none" } ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "fingerprint": "firefox",
          "serverName": "${ORIGIN_DOMAIN}",
          "publicKey": "${PBK}",
          "shortId": "${SID}",
          "spiderX": "/"
        }
      }
    },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "domainMatcher": "hybrid",
    "rules": [
      { "type": "field", "protocol": [ "bittorrent" ], "outboundTag": "block" },
      {
        "type": "field",
        "outboundTag": "🇷🇺 RU VPS Exit",
        "domain": [
          "geosite:category-ru", "domain:ru", "domain:su", "domain:xn--p1ai",
          "domain:ya.ru", "domain:yandex.ru", "domain:yandex.net", "domain:yastatic.net", "domain:yandexcloud.net", "full:go.yandex", "domain:kinopoisk.ru",
          "domain:vk.com", "domain:vk.ru", "domain:vkvideo.ru", "domain:okcdn.ru", "domain:ok.ru", "domain:userapi.com", "domain:mycdn.me", "domain:mail.ru",
          "domain:gosuslugi.ru", "domain:gosuslugi.org", "domain:gosuslugi.net", "domain:kremlin.ru", "domain:nalog.gov.ru", "domain:cbr.ru", "domain:mos.ru", "domain:emias.info",
          "domain:alfabank.ru", "domain:vtb.ru", "domain:psbank.ru", "domain:gazprombank.ru", "domain:tbank.ru", "domain:cdn-tinkoff.ru", "domain:tbank-online.com", "domain:sber.ru", "domain:sberbank.ru", "domain:open.ru", "domain:raiffeisen.ru",
          "domain:ozon.ru", "domain:wildberries.ru", "domain:avito.ru", "domain:megamarket.ru", "domain:rzd.ru", "domain:2gis.ru", "domain:cian.ru", "domain:hh.ru"
        ]
      },
      { "type": "field", "ip": [ "geoip:ru" ], "outboundTag": "🇷🇺 RU VPS Exit" },
      { "type": "field", "network": "tcp,udp", "outboundTag": "direct" }
    ]
  }
}
EOF

# 5.3. Обновляем общий JSON подписки (SUB_TOKEN.json) и формируем all-in-one.json
python3 - << PYEOF
import json

path = "${WEB_ROOT}/${SUB_TOKEN}.json"
data = []
if os.path.exists(path):
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except: pass

cdn_profile = {
    "tag": "🇳🇱 🇷🇺 Белые списки",
    "protocol": "vless",
    "settings": {
        "vnext": [{
            "address": "${CDN_HOST}",
            "port": 443,
            "users": [{"id": "${UUID}", "encryption": "none"}]
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

if data:
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    with open("${WEB_ROOT}/all-in-one.json", "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
PYEOF

# ==============================================================================
# 6. СБОРКА HTML ПОРТАЛА
# ==============================================================================
log_info "6/7. Сборка HTML страницы подписки..."
FULL_JSON_CONTENT=$(cat "${WEB_ROOT}/config.json")
ABROAD_JSON_CONTENT=$(cat "${WEB_ROOT}/config-abroad.json")

cat << EOF > "${WEB_ROOT}/${SUB_TOKEN}.html"
<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>autoXRAY bridge configs</title>
<link rel="icon" type="image/svg+xml" href='data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMDBCRkZGIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBhdGggZD0iTTIxIDJsLTIgMm0tNy42MSA3LjYxYTUuNSA1LjUgMCAxIDEtNy43NzggNy43NzggNS41IDUuNSAwIDAgMSA3Ljc3Ny03Ljc3N3ptMCAwTDE1LjUgNy41bTAgMGwzIDNMMjIgN2wtMy0zbS0zLjUgMy41TDE5IDQiLz48L3N2Zz4='>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
body{font-family:monospace;background:#121212;color:#e0e0e0;padding:10px;max-width:900px;margin:0 auto}h2{color:#c3e88d;border-top:2px solid #333;padding-top:20px;margin:15px 0 10px;font-size:18px}.config-row{background:#1e1e1e;border:1px solid #333;border-radius:6px;padding:5px;display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:8px}.config-label{background:#2c2c2c;color:#82aaff;padding:6px 10px;border-radius:4px;font-weight:700;font-size:13px;white-space:nowrap;min-width:160px;text-align:center}.config-code{flex:1;white-space:nowrap;overflow-x:auto;padding:8px;background:#121212;border-radius:4px;color:#c3e88d;font-size:12px;scrollbar-width:none}.config-code::-webkit-scrollbar{display:none}.btn-action{border:1px solid #555;padding:6px 12px;border-radius:4px;cursor:pointer;font-weight:700;font-size:12px;transition:all .2s;height:32px;display:flex;align-items:center;justify-content:center;text-decoration:none}.copy-btn{background:#333;color:#e0e0e0;min-width:60px}.copy-btn:hover{background:#c3e88d;color:#121212;border-color:#c3e88d}.qr-btn{background:#333;color:#82aaff;border-color:#82aaff;min-width:40px}.qr-btn:hover{background:#82aaff;color:#121212}.dl-btn{background:#333;color:#ffcb6b;border-color:#ffcb6b;min-width:60px}.dl-btn:hover{background:#ffcb6b;color:#121212}.btn-group{display:flex;gap:10px;margin:10px 0 20px}.btn{flex:1;background:#2c2c2c;color:#c3e88d;border:1px solid #c3e88d;padding:10px;text-align:center;border-radius:6px;text-decoration:none;font-weight:700;font-size:14px}.btn:hover{background:#c3e88d;color:#121212}.btn.download{border-color:#82aaff;color:#82aaff}.btn.download:hover{background:#82aaff;color:#121212}.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.85);z-index:999;justify-content:center;align-items:center;backdrop-filter:blur(3px)}.modal-content{background:#1e1e1e;padding:20px;border-radius:10px;border:1px solid #82aaff;text-align:center}#qrcode{background:#fff;padding:10px;border-radius:6px;margin-bottom:10px}.close-modal-btn{background:#c31e1e;color:#fff;border:none;padding:8px 20px;border-radius:4px;cursor:pointer}@media(max-width:600px){.config-label{width:100%;margin-bottom:2px}.config-code{min-width:100%;order:3}.btn-action{flex:1;order:2}}
</style>
<script>
function copyText(e,t){navigator.clipboard.writeText(document.getElementById(e).textContent).then(()=>{let o=t.innerText;t.innerText="OK",t.style.cssText="background:#c3e88d;color:#121212",setTimeout(()=>{t.innerText=o,t.style.cssText=""},1500)}).catch(e=>console.error(e))}
function showQR(e){let t=document.getElementById(e).textContent,o=document.getElementById("qrModal"),n=document.getElementById("qrcode");n.innerHTML="",new QRCode(n,{text:t,width:256,height:256,colorDark:"#000000",colorLight:"#ffffff",correctLevel:QRCode.CorrectLevel.L}),o.style.display="flex"}
function closeModal(){document.getElementById("qrModal").style.display="none"}
window.onclick=function(e){e.target==document.getElementById("qrModal")&&closeModal()};
</script>
</head><body>

<h2>🚀 Единая подписка (All-in-One)</h2>
<div class="config-row" style="border: 1px solid #5C3A86;">
    <div class="config-label" style="background:#5C3A86;color:#fff;">JurgenVPN Master</div>
    <div class="config-code" id="masterLink">https://${ORIGIN_DOMAIN}/all-in-one.json</div>
    <button class="btn-action copy-btn" onclick="copyText('masterLink', this)">Copy</button>
    <button class="btn-action qr-btn" onclick="showQR('masterLink')">QR</button>
</div>

<h2>📂 Ссылка на подписку (autoXRAY)</h2>
<div class="config-row">
    <div class="config-label">Subscription URL</div>
    <div class="config-code" id="subLink">https://${ORIGIN_DOMAIN}/${SUB_TOKEN}.json</div>
    <button class="btn-action copy-btn" onclick="copyText('subLink', this)">Copy</button>
    <button class="btn-action qr-btn" onclick="showQR('subLink')">QR</button>
</div>

<h2>📱 Приложения</h2>
<div class="btn-group">
    <a href="happ://add/https://${ORIGIN_DOMAIN}/${SUB_TOKEN}.json" class="btn">⚡ Add to HAPP</a>
    <a href="https://www.happ.su/main/ru" target="_blank" class="btn download">⬇️ Download App</a>
</div>

<h2>🛡️ Полные JSON-конфиги со смарт-роутингом</h2>
<div class="config-row">
    <div class="config-label">🇳🇱 🇷🇺 РФ → Мир (Белые списки)</div>
    <div class="config-code" id="jsonConfigUrl">https://${ORIGIN_DOMAIN}/config.json</div>
    <button class="btn-action copy-btn" onclick="copyText('fullJsonRaw', this)">Copy JSON</button>
    <a href="/config.json" download="config.json" class="btn-action dl-btn">Download</a>
</div>

<div class="config-row">
    <div class="config-label">🇷🇺 ✈️ Заграница (Только RU)</div>
    <div class="config-code" id="abroadJsonUrl">https://${ORIGIN_DOMAIN}/config-abroad.json</div>
    <button class="btn-action copy-btn" onclick="copyText('abroadJsonRaw', this)">Copy JSON</button>
    <a href="/config-abroad.json" download="config-abroad.json" class="btn-action dl-btn">Download</a>
</div>

<div id="fullJsonRaw" style="display:none;">${FULL_JSON_CONTENT}</div>
<div id="abroadJsonRaw" style="display:none;">${ABROAD_JSON_CONTENT}</div>

<div><a style="color:white;margin:40px auto 20px;display:block;text-align:center;" href="https://github.com/xVRVx/autoXRAY">https://github.com/xVRVx/autoXRAY</a></div>

<div id="qrModal" class="modal-overlay"><div class="modal-content"><div id="qrcode"></div><button class="close-modal-btn" onclick="closeModal()">Close</button></div></div>
</body></html>
EOF

chown -R www-data:www-data "$WEB_ROOT"
chmod -R 644 "${WEB_ROOT}"/*
chmod 755 "$WEB_ROOT"

# ==============================================================================
# 7. БЕЗОПАСНОСТЬ: ФАЕРВОЛ UFW + FAIL2BAN
# ==============================================================================
log_info "7/7. Настройка фаервола UFW и службы Fail2ban..."

# UFW
ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1

ufw allow "${NEW_SSH_PORT}/tcp" comment 'SSH custom port' > /dev/null 2>&1
ufw allow 80/tcp comment 'Certbot HTTP-01' > /dev/null 2>&1
ufw allow 443/tcp comment 'Xray Reality and CDN' > /dev/null 2>&1

ufw --force enable > /dev/null 2>&1
log_success "Фаервол UFW настроен (открыты порты: ${NEW_SSH_PORT}, 80, 443)."

# Fail2ban
WHITELIST_IPS="127.0.0.1/8 ::1"
[[ -n "$EU_IP" ]] && WHITELIST_IPS="${WHITELIST_IPS} ${EU_IP}"

cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = ${WHITELIST_IPS}
bantime = 2h
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 48h
findtime = 10m
maxretry = 3
banaction = ufw
banaction_allports = ufw
backend = systemd

[sshd]
enabled = true
port = ${NEW_SSH_PORT}
mode = aggressive
maxretry = 3
findtime = 10m
bantime = 24h

[nginx-http-auth]
enabled = false

[nginx-botsearch]
enabled = false
EOF

systemctl restart fail2ban
systemctl enable fail2ban > /dev/null 2>&1
log_success "Fail2ban настроен и защищает SSH порт ${NEW_SSH_PORT}."
# ==============================================================================
# 8. НАСТРОЙКА УЧЕТНОЙ ЗАПИСИ SERVERCAT ДЛЯ МОНИТОРИНГА
# ==============================================================================
log_info "6/7. Настройка изолированного пользователя servercat..."

if id "servercat" &>/dev/null; then
    # Если скрипт запускается повторно, временно возвращаем права для генерации новых ключей
    chmod 755 /home/servercat 2>/dev/null || true
    chmod 700 /home/servercat/.ssh 2>/dev/null || true
    rm -f /home/servercat/.ssh/id_ed25519* /home/servercat/.ssh/authorized_keys
else
    adduser --disabled-password --gecos "" servercat > /dev/null 2>&1
fi

mkdir -p /home/servercat/.ssh
ssh-keygen -t ed25519 -N "" -f /home/servercat/.ssh/id_ed25519 -C "servercat_monitoring" -q
cat /home/servercat/.ssh/id_ed25519.pub > /home/servercat/.ssh/authorized_keys

chown -R servercat:servercat /home/servercat/.ssh
chmod 400 /home/servercat/.ssh/authorized_keys
chmod 500 /home/servercat/.ssh
chmod 555 /home/servercat

SERVERCAT_PRIV_KEY=$(cat /home/servercat/.ssh/id_ed25519)
log_success "Пользователь servercat и SSH-ключи успешно сгенерированы (Read-Only)."
# ==============================================================================
# ДИАГНОСТИКА И ИТОГОВЫЙ СТАТУС
# ==============================================================================
echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}      УСТАНОВКА И НАСТРОЙКА УСПЕШНО ЗАВЕРШЕНЫ!       ${NC}"
echo -e "${GREEN}======================================================${NC}\n"

echo -e "${BLUE}--- Параметры SSH ---${NC}"
sshd -T | grep -E '^(port|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication)' || true

echo -e "\n${BLUE}--- Веб-ресурсы подписки ---${NC}"
echo -e " 🚀 Мастер-подписка All-in-One: ${PURPLE}https://${ORIGIN_DOMAIN}/all-in-one.json${NC}"
echo -e " 🌐 Веб-портал:                 ${BLUE}https://${ORIGIN_DOMAIN}/${SUB_TOKEN}.html${NC}"
echo -e " 📱 Подписка autoXRAY:          ${BLUE}https://${ORIGIN_DOMAIN}/${SUB_TOKEN}.json${NC}"
echo -e " 🇳🇱 Конфиг РФ -> Мир (JSON):    ${BLUE}https://${ORIGIN_DOMAIN}/config.json${NC}"
echo -e " 🇷🇺 Конфиг Заграница (JSON):    ${BLUE}https://${ORIGIN_DOMAIN}/config-abroad.json${NC}\n"

echo -e "${YELLOW}ВНИМАНИЕ!${NC} Перед закрытием текущей сессии откройте новое окно терминала и проверьте вход:"
echo -e "  ${BLUE}ssh -p ${NEW_SSH_PORT} root@${ORIGIN_DOMAIN}${NC}\n"
