# MAXBOT v2

Однопользовательская панель для распределения недельных сообщений по MAX-группам. Приложение рассчитано на новую чистую установку; старые группы, сессии и история не импортируются.

## Состояние

Создан каркас FastAPI + SQLite, базовая панель, защищённый вход, настройки, текстовый пул, гостевые ссылки, назначения прокси/дней, подготовка недельных слотов, последовательные worker-задачи групп и журнал долговечных операций. PyMax изолирован в `maxbot_v2/max_adapter.py` и закреплён на `maxapi-python==2.4.1`.

Проверки используют локальную SQLite и фиктивный адаптер. Реальную авторизацию и отправку MAX в этой среде не выполняли. Внешние действия по умолчанию заблокированы; для разблокировки приложение требует операторскую запись разрешения с действующим сроком, ссылкой на договор и требуемыми областями действия. Она не хранится в Git и монтируется в контейнер как Docker secret.

## Разработка и запуск

Для выпуска нужны Docker Compose и домен, указывающий на VPS. Для локальной разработки установите Python 3.12 с [python.org](https://www.python.org/downloads/release/python-31210/). Windows-тестовое окружение создаётся так:

```powershell
py -3.12 --version
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

`requirements-dev.txt` устанавливает закреплённые runtime- и тестовые пакеты только в `.venv`; Docker-образ устанавливает только `requirements.txt`. Скрипты интерфейса можно проверить встроенной проверкой Node.js:

```powershell
node --check static/app.js
node --check static/join.js
```

Скопируйте `.env.example` в `.env`, задайте уникальные `APP_SECRET_KEY` и `DATA_ENCRYPTION_KEY`, а хеш начального пароля владельца получите интерактивно:

```powershell
.\.venv\Scripts\python.exe scripts/hash_password.py
```

В `.env` внесите полученный `OWNER_PASSWORD_HASH`, домен и случайные ключи. Сам пароль не записывайте в файлы проекта. Сгенерировать ключ шифрования можно через `\.venv\Scripts\python.exe -c "from maxbot_v2.crypto import SecretBox; print(SecretBox.generate_key())"`.
Секрет приложения можно создать через `\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"`.

Затем запустите `docker compose up -d --build`. Caddy получает TLS-сертификат автоматически; приложение слушает только внутреннюю сеть Compose. Вызовы PyMax выполняются через закреплённый прокси подключённого аккаунта; отдельный файл локального разрешения не требуется.

## Резервная копия и восстановление

Архив включает SQLite через Online Backup API и зашифрованные файлы сессий. Ключ `DATA_ENCRYPTION_KEY` и секреты развёртывания хранятся отдельно от архива. Команды `scripts/backup.py` и `scripts/restore.py` создают и проверяют восстановление в пустую директорию; эксплуатационный порядок — в [docs/operations.md](docs/operations.md).

## PyMax

Используется только версия `maxapi-python==2.4.1`. Документация: [Client](https://docs.pymax.org/client.html), [ExtraConfig](https://docs.pymax.org/api/client-config.html), [Messages](https://docs.pymax.org/messages.html). Клиент подключается с закреплённым прокси и отдельно зашифрованным session snapshot; временная SQLite-сессия находится в tmpfs контейнера. Для TCP-клиента принимаются прокси `http://` и `socks5://` с портом. Ссылка группы должна иметь вид `https://max.ru/join/...` или `https://max.im/join/...`: `resolve_group_by_link()` обрабатывает только ссылки с `/join/`. Эта интеграция опирается на неофициальный API MAX.

## Документы

- [Аудит исходного проекта](docs/audit.md)
- [Техническое задание v2](docs/specification.md)
- [План реализации и выпуска](docs/implementation-plan.md)
- [Эксплуатация и защита действий MAX](docs/operations.md)
