# TLS Audit Growth Plan (v0.2)

План развития после MVP: доверие, стабильность, спрос и монетизация без
перегруза интерфейса.

## 1. Доверие к результатам

Статус: `in_progress`.

- поддерживать публичную методику и changelog;
- хранить evidence/provenance в отчете;
- держать в явном виде границы инструмента (что проверяем и чего не проверяем);
- регулярно обновлять sample reports.

## 2. Стабильная эксплуатация на VPS

Статус: `in_progress`.

- ежедневные бэкапы и проверка восстановления;
- healthcheck + таймеры обслуживания;
- контроль диска, очереди, давности бэкапа, срока сертификата;
- периодическая очистка docker-cache и старых логов.
- рабочий чеклист: `docs/prod-reliability-seo-checklist.md`.

## 3. Защита и антиабьюз

Статус: `in_progress`.

- rate limit, queue guards, target guards;
- denylist для client IP и target host;
- сетевой egress firewall для scanner-контейнеров;
- ограничение доступа к приватным мониторинговым API.

## 4. SEO и контент-охват

Статус: `in_progress`.

- поддержка `robots.txt`/`sitemap.xml`/canonical;
- тематические страницы (TLS/HSTS/A+/конфиги);
- аккуратные внутренние ссылки без "мусорного" SEO.
- рабочий чеклист: `docs/prod-reliability-seo-checklist.md`.

## 5. Monitoring Product (free + pro)

Статус: `in_progress`.

- free: weekly отчет на 1 домен;
- pro: расширенный weekly отчет до 10 доменов;
- owner-token + ownership verification;
- алерты и diff в почтовом потоке, без перегруза главной страницы.

## 6. Что идет следующим блоком

Статус: `planned`.

1. фикс правил алертов (grade drop, cert expiry, critical findings);
2. стабилизация dedupe и retry по почтовой доставке;
3. export-слой (CSV/JSON) и стабильный digest API; PDF отложен;
4. billing provider integration;
5. вебхуки и публичный API-контракт.

Сделано в текущей ветке:

- CSV export для report/monitoring;
- digest JSON для report API;
- PDF не считаем обязательной частью текущего этапа.

## 7. Коммерческая рамка

Статус: `planned`.

- тарифная логика: free + pro;
- проработка цены/лимитов на базе реальной нагрузки;
- активация Pro только после готового функционала, а не раньше.
