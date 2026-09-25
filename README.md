# MAXBOT v2

Однопользовательская панель на FastAPI, SQLite и обычном JavaScript для планирования сообщений в MAX-группах. Проект сохраняет данные и зашифрованные сессии из существующего `/data`; перед выпуском всё равно создайте и проверьте резервную копию. Поддерживаемая схема базы расширяется повторяемо без удаления пользовательских строк.

## Состояние

PyMax закреплён на `maxapi-python==2.4.1` и изолирован в `maxbot_v2/max_adapter.py`. Все внешние действия идут через назначенный прокси. В коде проекта нет требования к отдельному файлу разрешения или договору.

Автоматические проверки используют отдельную SQLite и фиктивный PyMax. Они не доказывают доставку SMS или работоспособность конкретного прокси/MAX-аккаунта. Реальную проверку проводите на тестовом номере и группе с согласованным содержимым. После выпуска `/health` возвращает `revision` образа; значение `unknown` означает, что SHA не был передан при сборке.

## Разработка

Нужны Python 3.12 и Node.js 24. В Windows создайте окружение и установите зависимости разработки:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\python.exe -m pytest -q
node --check static/app.js
node --check static/join.js
node --test tests/test_join_start.cjs
```

На Linux установите браузер вместе с системными пакетами командой `python -m playwright install --with-deps chromium`. CI выполняет те же Python, браузерные и JavaScript проверки на Windows и Linux, а также собирает Docker-образ. `requirements-dev.txt` содержит тестовые инструменты; производственный образ устанавливает только `requirements.txt`.

Создайте локальный `.env` из `.env.example`. Задайте уникальные `APP_SECRET_KEY`, `DATA_ENCRYPTION_KEY` и `OWNER_PASSWORD_HASH`. Хеш начального пароля создаётся интерактивно:

```powershell
.\.venv\Scripts\python.exe scripts/hash_password.py
```

Не сохраняйте секреты и реальные номера в Git или тестовых данных. Для первого локального запуска используйте отдельный каталог данных. Docker-режим запускается так:

```powershell
$env:BUILD_REVISION = (git rev-parse HEAD)
docker compose up -d --build
```

Caddy выдаёт TLS, а приложение доступно только во внутренней сети Compose. Кнопки «Запустить/Остановить» управляют работой сейчас; «Автозапуск после рестарта» задаёт состояние при следующем старте процесса.

## PyMax

Используется `maxapi-python==2.4.1`. Ссылки на первичную документацию: [Client](https://docs.pymax.org/client.html), [ExtraConfig](https://docs.pymax.org/api/client-config.html), [Messages](https://docs.pymax.org/messages.html) и [исходный код PyMax v2.4.1](https://github.com/MaxApiTeam/PyMax/tree/v2.4.1). TCP-клиент принимает прокси `http://` и `socks5://` с портом. Ссылки MAX-групп должны содержать `/join/`. Интеграция использует неофициальный API MAX.

Ответ PyMax на запрос кода не подтверждает доставку SMS. Диагностика выполняется последовательно: локальный вход без прокси, затем с назначенным прокси, тот же тест на VDS, затем веб-подключение. Не переключайте автоматом на прямое соединение, не повторяйте запросы чаще лимитов MAX и не включайте сырые логи PyMax с URL прокси.

## Резервные копии и документы

Архив включает SQLite snapshot и только зашифрованные файлы сессий. `DATA_ENCRYPTION_KEY` и секреты развёртывания храните отдельно. Порядок резервного копирования и восстановления описан в [docs/operations.md](docs/operations.md).

- [Инструкции для агентов](AGENTS.md)
- [Текущее состояние проекта](docs/project-state.md)
- [Журнал изменений](docs/change-log.md)
- [Техническая спецификация](docs/specification.md)
- [План реализации и выпуска](docs/implementation-plan.md)
- [Исторические аудиты](docs/audit.md) и [аудит 2026-09-25](docs/audit-2026-09-25.md)
