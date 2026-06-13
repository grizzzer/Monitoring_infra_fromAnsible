# Мониторинг инфраструктуры РЕД ОС

Решение собрано на базе наработок, переработано в ролевую
структуру и адаптировано под точные требования задания (NextCloud, изоляция
после 3 сбоев, отчёты HTML+PDF, скорость интернета у студентов, и т.д.).

## Быстрый запуск

```bash
cd playbooks_v6
chmod +x init.sh
./init.sh                                                 # install, vault, ping
ansible-playbook monitoring_playbook.yml                  # развёртывание
ansible-playbook monitoring_playbook.yml --tags help      # все теги
ansible-playbook monitoring_playbook.yml --tags verify    # проверки
```

Перед сдачей смените тестовые секреты:
```bash
ansible-vault edit  group_vars/vault.yml
ansible-vault rekey group_vars/vault.yml
```

## Структура

```
playbooks_v6/
├── monitoring_playbook.yml        # главный плейбук
├── client_check.yml               # сбор метрик со студенческих машин
├── uninstall.yml                  # удаление мониторинга (force-only)
├── inventory                      # [monitoring] admin + [students] student.redos.test
├── ansible.cfg
├── init.sh                        # инициализация (Ansible + vault)
├── group_vars/
│   ├── monitoring.yml             # вся открытая конфигурация
│   └── vault.yml                  # секреты (AES-256)
├── templates/
│   ├── report_daily.html.j2       # шаблон ежедневного HTML-отчёта
│   └── report_weekly.html.j2      # шаблон еженедельного (с графиком)
├── roles/
│   ├── common/                    # пакеты, каталоги, ACL, monitor.env
│   ├── notifications/             # postfix submission, Dovecot LMTP, SASL, SELinux
│   ├── service_monitoring/        # 9 сервисов + NextCloud + 3-сбоя-карантин
│   ├── security_monitoring/       # brute-force, порты, SUID, журнал
│   ├── performance_monitoring/    # CPU/RAM/disk + monitor_internet
│   ├── incident_response/         # сеть/DNS/время/cert/OOM/queue/self-heal
│   ├── maintenance/               # daily update, weekly cleanup, monthly fscheck
│   ├── reporting/                 # daily/weekly HTML+PDF+SVG-графики, архивы
│   ├── dashboard/                 # /monitoring/ Basic Auth + IP allowlist
│   └── test_scenarios/            # демо-имитация инцидентов (только tag never)

```

## Что мониторится (требования задания)

### Сервисы (каждые 5 минут)
| Сервис | Назначение | Порт |
|---|---|---|
| `samba` | Контроллер домена Samba + файловый сервер | 445 |
| `dhcpd` | DHCP-сервер | 67 |
| `sshd` | SSH-сервис (порт 2026) | 2026 |
| `postfix` | Почтовый сервер iRedMail (SMTP) | 25 |
| `dovecot` | Почтовый сервер iRedMail (IMAP/POP3) | 143 |
| `squid` | Прокси-сервер Squid | 3128 |
| **`nextcloud`** | **NextCloud (через HTTP /nextcloud/status.php)** | **80** |
| `firewalld` | Брандмауэр | — |
| `httpd`, `mariadb` | Несущие сервисы NextCloud + iRedMail | 80, 3306 |
| `sogod` | SOGo (опциональный) | 20000 |

Добавление сервиса — одна строка в `group_vars/monitoring.yml`:
```yaml
- { name: redis, critical: true, port: 6379, protocol: tcp }
```

### Безопасность (каждые 5 минут)
- > 5 неудачных входов за 5 минут → бан IP на 1 час через firewalld rich-rule
- Источники: journalctl + `/var/log/secure` + `/var/log/auth.log`, с дедупликацией
- Также: неожиданные открытые порты, новые SUID-файлы, аномалии в journal

### Производительность
- **CPU > 90% в течение 5 минут** (5 последовательных минутных измерений)
- **RAM > 85%**
- **Диск:** предупреждение при < 10% свободного, авария при < 5%
- **Скорость интернета < 0.8 Мбит/с** — `curl` на `mon_speedtest_url`
- На студенческих машинах через `--tags client` — CPU/RAM/disk/speedtest

### Обслуживание
- **Ежедневно 03:00** — `dnf upgrade`
- **Воскресенье 02:00** — очистка ротированных логов и dnf cache
- **1 число месяца 05:00** — `xfs_scrub -n` / `e2scrub` / `btrfs scrub` (online безопасно)

### Отчёты
- **Ежедневно в 23:55** — HTML + PDF + TXT + JSON
- **Воскресенье в 23:00** — еженедельный HTML + PDF + SVG-график CPU/RAM/Disk
- **1 число в 04:00** — архивирование отчётов за месяц в `.tar.gz`
- Доставка по email через STARTTLS+SMTP-AUTH (или SMTPS:465 fallback)

## Автоматическое реагирование (требование задания, п.2)

1. **Перезапуск сервиса** через `systemctl restart`
2. **Email админу** через iRedMail submission (STARTTLS + AUTH)
3. **Лог инцидента** в `/var/log/infrastructure_monitor.log`
4. **Карантин хоста после 3 сбоев подряд:**
   - режим `firewall` (по умолчанию): `reject` для классной подсети `192.168.254.0/24`,
     `accept` для management IP — на 1800 секунд (firewalld auto-timeout)
   - режим `interface`: отключение интерфейса с автообратным подключением через `systemd-run`

## Все теги для управления

### Развёртывание
| Команда | Эффект |
|---|---|
| `ansible-playbook monitoring_playbook.yml` | Полное развёртывание |
| `… --tags help` | Список всех команд |
| `… --tags verify` | Только проверки |
| `… --tags run_once` | Прогон всех скриптов сейчас |

### Демонстрация инцидентов (тег `never` — только явный запуск)
| Команда | Эффект |
|---|---|
| `… --tags failure_demo` | Один сбой сервиса → алерт |
| `… --tags isolation_demo` | 3 сбоя подряд → **карантин хоста через firewalld** |
| `… --tags bruteforce_demo` | 7 неудачных SSH-входов → **бан IP** |

### Ручной триггер отчётов
| Команда | Эффект |
|---|---|
| `… --tags report_now` | Ежедневный HTML+PDF сейчас |
| `… --tags report_weekly_now` | Еженедельный с SVG-графиком |
| `… --tags archive_now` | Архивирование `.tar.gz` |

### Обслуживание вручную
| Команда | Эффект |
|---|---|
| `… --tags maintenance_cleanup_now` | Очистка логов |
| `… --tags maintenance_fscheck_now` | Проверка ФС (xfs_scrub/e2scrub) |

### Студент
| Команда | Эффект |
|---|---|
| `… --tags client` | Сбор метрик со студента (CPU/RAM/disk/internet) |

### Удаление
```bash
ansible-playbook uninstall.yml --tags uninstall_force
```

## Безопасность

| Что | Защита |
|---|---|
| `.vault_pass` | chmod 0600, в `.gitignore` |
| `group_vars/vault.yml` | AES-256-CBC + PBKDF2-HMAC-SHA256 |
| `/etc/monitoring/monitor.env` | 0640 root:monitoring (содержит SMTP-пароль) |
| `/var/log/monitoring/` | 0750 + ACL `g:monitoring:rx, o::---` |
| `/var/lib/monitoring/` | 0750 + ACL |
| `/var/log/infrastructure_monitor.log` | 0640 root:monitoring |
| Дашборд `/monitoring/` | Basic Auth (htpasswd через vault) + IP allowlist 192.168.254.0/24 |
| Email | STARTTLS обязателен для отчётов (или SMTPS fallback) |
| `no_log: yes` | На задачах с vault-секретами |

## Веб-просмотр отчётов и дашборда

### Дашборд + отчёты (рекомендуемый способ)

| Параметр | Значение |
|---|---|
| **URL дашборда** | `http://admin.redos.test/monitoring/` |
| Альтернатива по IP | `http://192.168.254.1/monitoring/` |
| **Логин** | `monadmin` |
| **Пароль** | `Mon1tor!ng2026` |
| Доступ откуда | **С любого IP** (защита только Basic Auth) — управляется `mon_dashboard_ip_allowlist` |

На главной странице дашборда есть **большие кнопки** для прямого открытия отчётов:

| Кнопка | URL |
|---|---|
| Ежедневный HTML | `http://admin.redos.test/monitoring/reports/latest_daily.html` |
| Ежедневный PDF | `http://admin.redos.test/monitoring/reports/latest_daily.pdf` |
| Еженедельный HTML (с графиком) | `http://admin.redos.test/monitoring/reports/latest_weekly.html` |
| Еженедельный PDF | `http://admin.redos.test/monitoring/reports/latest_weekly.pdf` |
| Архив всех отчётов | `http://admin.redos.test/monitoring/reports/` |

Браузер запросит логин (`monadmin`) и пароль (`Mon1tor!ng2026`) — те же, что у дашборда.

### Открыть с любой машины

```bash
# С любого компьютера в сети (admin, student, ваш ноут):
firefox http://admin.redos.test/monitoring/

# Если станция не разрешает admin.redos.test — добавьте в /etc/hosts:
echo "192.168.254.1 admin.redos.test" | sudo tee -a /etc/hosts
```

Если открываете **со своего ноутбука вне локальной сети** — нужно убедиться, что
машина имеет маршрут в `192.168.254.0/24` (через VPN/проброс портов или прямое
подключение к классной сети).

### Ужесточить защиту дашборда (если хочется ограничить IP)

В `group_vars/monitoring.yml`:
```yaml
# Только из классной сети + localhost (безопаснее)
mon_dashboard_ip_allowlist: "127.0.0.1 192.168.254.0/24"

# Только с admin (паранойя)
mon_dashboard_ip_allowlist: "127.0.0.1"
```

Затем перезапустить роль:
```bash
ansible-playbook monitoring_playbook.yml --tags dashboard
```

### Сменить логин/пароль дашборда

```bash
ansible-vault edit group_vars/vault.yml
# Поменять vault_dashboard_user / vault_dashboard_password
ansible-playbook monitoring_playbook.yml --tags dashboard
```

## Где смотреть результаты (через консоль)

```bash
# === ЛОГИ ===
sudo tail -f /var/log/infrastructure_monitor.log    # главный журнал инцидентов
sudo tail -f /var/log/monitoring/services.log
sudo tail -f /var/log/monitoring/performance.log
sudo tail -f /var/log/monitoring/security.log
sudo tail -f /var/log/monitoring/maintenance.log
sudo tail -f /var/log/monitoring/alerts.log

# === STATE (текущий снимок) ===
sudo cat /var/lib/monitoring/state_services.json    | jq
sudo cat /var/lib/monitoring/state_performance.json | jq
sudo cat /var/lib/monitoring/state_security.json    | jq
sudo cat /var/lib/monitoring/state_internet.json    | jq
sudo cat /var/lib/monitoring/state_clients.json     | jq  # после --tags client

# === ОТЧЁТЫ ===
ls -lt /var/log/monitoring/reports/
ls -la /var/log/monitoring/reports/latest_daily.{html,pdf,txt,json}
ls -la /var/log/monitoring/reports/latest_weekly.{html,pdf,txt,json}

# === АРХИВЫ ===
ls -lh /var/log/monitoring/archive/

# === ТАЙМЕРЫ ===
systemctl list-timers --all | grep monitor-
```

### Скопировать отчёты через scp (если не работает веб)

```bash
# На admin: сделать копию с правами sa
sudo cp /var/log/monitoring/reports/latest_daily.{html,pdf} /tmp/
sudo chown sa:sa /tmp/latest_daily.{html,pdf}

# На ноут:
scp -P 2026 sa@192.168.254.1:/tmp/latest_daily.html ./
xdg-open latest_daily.html
```

## Расширяемость

- **Новый сервис** — одна строка в `mon_services`, ничего больше менять не нужно
- **Новый хост** — добавить в `[monitoring]` или `[students]` inventory, тот же
  плейбук разворачивается на всех (свои state/log/timers на каждом)
- **Изменение порогов** — `group_vars/monitoring.yml`, перезапуск `--tags common`
- **Замена SMTP** — vault и `group_vars/monitoring.yml` (`mon_smtp_*`)
- **Переход на cron вместо systemd timers** — заменить шаблоны `monitor-*.timer.j2`


## Связанная документация

- **`docs/QA_ANSWERS.md`** — подробные ответы на 11 ключевых вопросов:
  карантин, brute-force, отчёты, PDF, ограничение доступа, что вставить в
  итоговый PDF-отчёт о тестировании
- **`docs/TESTING.md`** — пошаговые сценарии тестирования с фиксацией доказательств
