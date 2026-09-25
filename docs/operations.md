# Эксплуатация и защита действий MAX

## Закрытый по умолчанию шлюз

Приложение не выполняет внешний вызов MAX, если не может прочитать `MAX_AUTHORIZATION_FILE` и проверить запись со следующей структурой. В обычном `docker-compose.yml` secret не подключён, поэтому шлюз закрыт. Только если применение разрешено, создайте каталог `secrets` и файл разрешения вне Git, скопируйте overlay и запустите Compose с двумя файлами:

```sh
cp docker-compose.authorization.yml.example docker-compose.authorization.yml
mkdir -p secrets
# Создайте secrets/max-authorization.json из подтверждённой операторской записи.
docker compose -f docker-compose.yml -f docker-compose.authorization.yml up -d --build
```

Путь secret в контейнере — `/run/secrets/max-authorization.json`, он read-only.

```json
{
  "status": "authorized",
  "contract_reference": "internal reference",
  "expires_at": "2030-01-01T00:00:00Z",
  "scopes": ["connect", "request_otp", "verify_auth", "resolve_group", "check_membership", "send"]
}
```

Поместите файл вне Git и смонтируйте read-only в app-контейнер. Это операторская запись для выпуска, не пользовательский API и не переключатель в панели. Установка, файл и области действия должны соответствовать реально разрешённому сценарию на платформе MAX. Условия MAX отдельно оговаривают массовые рассылки и наличие соответствующего договора: <https://dev.max.ru/docs/legal/requirements>.

## Резервное копирование

Остановите приложение либо запустите Online Backup API скрипт из контейнера:

```sh
docker compose exec app python scripts/backup.py /data/backups/maxbot-$(date -u +%F).zip
```

Архив включает целостный SQLite snapshot и только зашифрованные session files. Храните `DATA_ENCRYPTION_KEY`, `APP_SECRET_KEY` и разрешение MAX в отдельном секретном хранилище. Без ключа сессии намеренно не расшифровать.

Восстановление запускается в отдельную пустую директорию:

```sh
python scripts/restore.py maxbot-backup.zip /srv/maxbot-restore
```

Скрипт сверяет `PRAGMA integrity_check`; затем укажите восстановленную базу/папку в отдельном тестовом экземпляре, установив исходный `DATA_ENCRYPTION_KEY`, и проверьте чтение аккаунтов/сессий. Не направляйте production на непроверенный архив.

## Выпуск и откат

Для первого выпуска используйте отдельный локальный порт и отдельный Docker volume. Подтвердите `/health`, TLS, backup и fake-провайдер. Затем остановите планировщик старой установки, снимите архив исходных данных, обновите Caddy и оставьте старые контейнеры/тома для отката. Откат переключает Caddy обратно и запускает старую установку только с расписанием v2, остановленным.
