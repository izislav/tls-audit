# TLS Audit Ops Runbook (v0.2)

Операционный runbook для релизов и обслуживания `tlsaudit.ru`.

## 1. Подготовка релиза

1. Проверить локально:
   - `docker-compose ps`
   - `python3 -m unittest discover -s tests -p 'test_*.py'`
2. Зафиксировать состояние:
   - `git status`
   - `git log --oneline -n 5`

## 2. Бэкап перед деплоем

1. PostgreSQL:
   - `bash deploy/scripts/backup-postgres.sh`
2. Текущий env:
   - `cp .env backups/.env.$(date +%Y%m%d-%H%M%S)`
3. Проверить размер и дату бэкапа:
   - `ls -lh backups | tail -n 5`

## 3. Деплой

1. Переключить код на нужный commit/branch.
2. Обновить контейнеры:
   - `docker-compose up -d --build api worker scheduler`
3. Применить схему:
   - `docker-compose exec -T postgres sh -lc "psql -U ${POSTGRES_USER:-tls_audit} -d ${POSTGRES_DB:-tls_audit} -f /docker-entrypoint-initdb.d/001-schema.sql"`

## 4. Smoke-проверка

1. API:
   - `curl -s http://127.0.0.1:8000/health`
2. UI:
   - главная страница;
   - запуск скана;
   - создание подписки free/pro;
   - подтверждение токена.
3. Почта:
   - получить письмо подтверждения;
   - проверить ссылку confirm/unsubscribe.
4. Trust zones (обязательно):
   - `curl -s -o /tmp/mon.out -w '%{http_code}' https://tlsaudit.ru/api/monitor/domains` -> `404`;
   - `curl -s -o /tmp/mon2.out -w '%{http_code}' -H 'x-monitoring-admin-token: wrong' https://tlsaudit.ru/api/monitor/domains` -> `404`;
   - открыть owner-ссылку `/monitor-status?token=...` и убедиться, что управление доступно только по валидному owner token.

## 5. Проверка мониторинга

1. Проверить расписание:
   - `docker-compose logs --tail=100 scheduler`
2. Проверить доставку:
   - новые записи в `subscription_report_deliveries`;
   - отсутствие дублей по одной и той же проверке.
3. Проверить недоступность цели:
   - событие должно фиксироваться как alert, а не "ломать" цикл мониторинга.

## 6. Откат

1. Вернуть предыдущий commit/branch.
2. Пересобрать:
   - `docker-compose up -d --build api worker scheduler`
3. Восстановить БД:
   - `bash deploy/scripts/restore-postgres.sh <backup.sql.gz>`
4. Повторить smoke-чек.

## 7. Таймеры и обслуживание

Поддерживать активными:

- `tls-audit-maintenance.timer`
- `tls-audit-healthcheck.timer`
- `tls-audit-stats.timer`
- `tls-audit-egress-firewall.service`

Периодически проверять:

- свободное место диска;
- размер БД и скорость роста;
- размер каталога `backups`;
- docker image/cache.

## 8. CI контроль

На каждый push/PR должен пройти workflow `.github/workflows/ci.yml`:

- общий прогон unit-тестов;
- обязательный trust-zone regression:
  - `tests.test_monitor_admin_api`
  - `tests.test_monitoring_access`

Релиз в прод без зелёного CI не выполнять.
