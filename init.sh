#!/bin/bash
# ============================================================
#  init.sh — инициализация окружения мониторинга
#
#  Запуск от sa на admin.redos.test:
#    chmod +x init.sh
#    ./init.sh
#
#  Что делает:
#    1. Проверяет/устанавливает Ansible (используются только builtin-модули)
#    2. Создаёт .vault_pass с правами 0600 (если нет)
#    3. Шифрует group_vars/vault.yml через ansible-vault
#    4. Проверяет ansible all -m ping
# ============================================================

set -e

VAULT_PASS_FILE=".vault_pass"
VAULT_PASS_EXAMPLE=".vault_pass.example"
VAULT_FILE="group_vars/vault.yml"
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$WORKDIR"

echo "================================================"
echo "  Финал IT-Планета 2026 / РЕД ОС"
echo "  Мониторинг инфраструктуры — инициализация"
echo "================================================"

# --- 1. Зависимости (поштучная проверка через rpm -q) ---
echo ""
echo "[1/4] Проверка зависимостей..."

ANSIBLE_PKGS=(ansible ansible-core sshpass)
EXTRA_PKGS=(sysstat procps-ng net-tools mailx jq curl postfix-ldap)

missing=()
for pkg in "${ANSIBLE_PKGS[@]}"; do
    if rpm -q "$pkg" &>/dev/null; then
        echo "  ✓ $pkg"
    else
        missing+=("$pkg")
    fi
done

if [ ${#missing[@]} -gt 0 ]; then
    echo "  Доустанавливаю: ${missing[*]}"
    sudo dnf install -y "${missing[@]}" || {
        echo "  ОШИБКА: dnf install не удался"
        exit 1
    }
fi

missing_extra=()
for pkg in "${EXTRA_PKGS[@]}"; do
    if rpm -q "$pkg" &>/dev/null; then
        echo "  ✓ $pkg"
    else
        missing_extra+=("$pkg")
    fi
done
if [ ${#missing_extra[@]} -gt 0 ]; then
    sudo dnf install -y "${missing_extra[@]}" >/dev/null 2>&1 || \
        echo "  (часть опциональных пакетов не установилась — поставит сам плейбук)"
fi

echo "  $(ansible --version 2>/dev/null | head -1)"

# --- 2. .vault_pass ---
echo ""
echo "[2/4] Vault password..."
if [ ! -f "$VAULT_PASS_FILE" ]; then
    if [ -f "$VAULT_PASS_EXAMPLE" ]; then
        cp "$VAULT_PASS_EXAMPLE" "$VAULT_PASS_FILE"
        echo "  Создан $VAULT_PASS_FILE из примера"
    else
        head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32 > "$VAULT_PASS_FILE"
        echo "  Сгенерирован новый случайный vault-пароль"
    fi
fi
chmod 600 "$VAULT_PASS_FILE"
perms="$(stat -c '%a' "$VAULT_PASS_FILE")"
[ "$perms" = "600" ] || { echo "ОШИБКА: права $VAULT_PASS_FILE = $perms"; exit 1; }
echo "  $VAULT_PASS_FILE: 0600 — OK"

# --- 3. Шифрование vault.yml ---
echo ""
echo "[3/4] Шифрование vault.yml..."
if [ -f "$VAULT_FILE" ]; then
    if head -1 "$VAULT_FILE" | grep -q '^\$ANSIBLE_VAULT'; then
        echo "  $VAULT_FILE уже зашифрован"
    else
        ansible-vault encrypt "$VAULT_FILE" --encrypt-vault-id default || {
            echo "ОШИБКА: encrypt не удался"
            exit 1
        }
        echo "  $VAULT_FILE зашифрован"
    fi
fi

# --- 4. Проверка соединения ---
echo ""
echo "[4/4] Проверка ansible ping..."
INVENTORY_FILE="$WORKDIR/inventory"
ansible all -i "$INVENTORY_FILE" -m ping 2>&1 | tail -20 || {
    echo "  ПРЕДУПРЕЖДЕНИЕ: ping не прошёл на всех хостах"
}

echo ""
echo "================================================"
echo "  Готово."
echo "  Запуск:    ansible-playbook monitoring_playbook.yml"
echo "  Справка:   ansible-playbook monitoring_playbook.yml --tags help"
echo "  Vault:     ansible-vault edit group_vars/vault.yml"
echo "================================================"
