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
   log_err "Этот скрипт должен запускаться с правами root (sudo)."
fi

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}    autoXRAY EU VPS: Security, Firewall & Fail2ban    ${NC}"
echo -e "${GREEN}======================================================${NC}\n"

# ==============================================================================
# ЗАПРОС И ВАЛИДАЦИЯ ПАРАМЕТРОВ
# ==============================================================================
read -rp "1. Новый SSH-порт сервера [по умолчанию: 22222]: " NEW_SSH_PORT
NEW_SSH_PORT=${NEW_SSH_PORT:-22222}

read -rp "2. IP адрес RU VPS для белого списка Fail2ban [например, 94.232.41.172]: " RU_VPS_IP
[[ -z "$RU_VPS_IP" ]] && log_warn "IP адрес RU VPS не указан. В белом списке Fail2ban будет только localhost."

echo -e "\n${YELLOW}Вставьте ваш публичный SSH-ключ (начинается с ssh-ed25519 или ssh-rsa):${NC}"
read -rp "SSH Public Key: " SSH_PUB_KEY

if [[ -z "$SSH_PUB_KEY" && ! -s ~/.ssh/authorized_keys ]]; then
    log_err "SSH-ключ не передан, а файл ~/.ssh/authorized_keys пуст! Отключение паролей заблокирует доступ к серверу."
fi

# ==============================================================================
# 1. ОБНОВЛЕНИЕ ПАКЕТОВ И УСТАНОВКА УТИЛИТ
# ==============================================================================
log_info "1/5. Обновление репозиториев и установка ufw, fail2ban..."
apt-get update -qq && apt-get install -y -qq ufw fail2ban curl iptables > /dev/null 2>&1
log_success "Пакеты успешно установлены."

# ==============================================================================
# 2. НАСТРОЙКА SSH КЛЮЧЕЙ И ОТКЛЮЧЕНИЕ ПАРОЛЕЙ
# ==============================================================================
log_info "2/5. Настройка SSH (порт ${NEW_SSH_PORT}, доступ только по ключам)..."

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

# Проверка синтаксиса SSH перед перезапуском
sshd -t || log_err "Ошибка в конфигурации sshd! Проверьте параметры вручную."
systemctl restart ssh || systemctl restart sshd
log_success "Служба SSH перезапущена на порту ${NEW_SSH_PORT}."

# ==============================================================================
# 3. НАСТРОЙКА UFW FIREWALL И МАРШРУТИЗАЦИИ
# ==============================================================================
log_info "3/5. Настройка UFW фаервола и политик маршрутизации..."

# Сброс правил
ufw --force reset > /dev/null 2>&1

# Базовые политики безопасности и разрешение маршрутизации
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
ufw default allow routed > /dev/null 2>&1
sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

# Разрешение внутреннего обмена по интерфейсу loopback (Xray <-> WireProxy/WARP)
ufw allow in on lo comment 'loopback in' > /dev/null 2>&1
ufw allow out on lo comment 'loopback out' > /dev/null 2>&1

# Открытие внешних портов autoXRAY и сопутствующих сервисов
ufw allow "${NEW_SSH_PORT}/tcp" comment 'SSH custom port' > /dev/null 2>&1
ufw allow 80/tcp comment 'Certbot HTTP-01' > /dev/null 2>&1
ufw allow 443/tcp comment 'Xray Reality TCP' > /dev/null 2>&1
ufw allow 443/udp comment 'Xray Reality / HTTP3 UDP' > /dev/null 2>&1
ufw allow 8443/tcp comment 'autoXRAY aux TCP' > /dev/null 2>&1
ufw allow 8443/udp comment 'autoXRAY aux UDP' > /dev/null 2>&1
ufw allow 10443/tcp comment 'autoXRAY aux TCP' > /dev/null 2>&1
ufw allow 10443/udp comment 'autoXRAY aux UDP' > /dev/null 2>&1
ufw allow 2408/tcp comment 'oclrtc / wireguard TCP' > /dev/null 2>&1
ufw allow 2408/udp comment 'oclrtc / wireguard UDP' > /dev/null 2>&1

# Активация и применение
ufw --force enable > /dev/null 2>&1
ufw reload > /dev/null 2>&1
log_success "Фаервол UFW настроен и включен."

# ==============================================================================
# 4. НАСТРОЙКА FAIL2BAN
# ==============================================================================
log_info "4/5. Настройка Fail2ban (защита SSH + вайтлист RU VPS)..."

WHITELIST_IPS="127.0.0.1/8 ::1"
[[ -n "$RU_VPS_IP" ]] && WHITELIST_IPS="${WHITELIST_IPS} ${RU_VPS_IP}"

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
log_success "Fail2ban настроен и запущен."

# ==============================================================================
# 5. ПРОВЕРКА И ДИАГНОСТИКА
# ==============================================================================
echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}             ДИАГНОСТИКА СИСТЕМЫ                      ${NC}"
echo -e "${GREEN}======================================================${NC}\n"

echo -e "${BLUE}--- 1. Параметры SSH ---${NC}"
sshd -T | grep -E '^(port|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication)'

echo -e "\n${BLUE}--- 2. Статус UFW ---${NC}"
ufw status numbered

echo -e "\n${BLUE}--- 3. Статус Fail2ban ---${NC}"
fail2ban-client status sshd

echo -e "\n${BLUE}--- 4. Статус Xray & Nginx ---${NC}"
systemctl is-active xray && echo -e "Xray service:  ${GREEN}active (running)${NC}" || echo -e "Xray service:  ${RED}inactive${NC}"
systemctl is-active nginx && echo -e "Nginx service: ${GREEN}active (running)${NC}" || echo -e "Nginx service: ${RED}inactive${NC}"

echo -e "\n${YELLOW}ВНИМАНИЕ!${NC} Перед закрытием текущей сессии откройте новое окно терминала и проверьте вход:"
echo -e "  ${BLUE}ssh -p ${NEW_SSH_PORT} root@<EU_VPS_IP>${NC}\n"
