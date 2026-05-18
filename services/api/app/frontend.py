import json
from html import escape

from .settings import settings


CONTACT_EMAIL = settings.contact_email
CONTACT_LINK = f'<a href="mailto:{CONTACT_EMAIL}">{CONTACT_EMAIL}</a>'


STATIC_PAGES = {
    "privacy": {
        "title": "Политика обработки персональных данных",
        "description": "Как TLS Audit обрабатывает технические данные, необходимые для работы сервиса проверки HTTPS/TLS-конфигурации.",
        "path": "/privacy",
        "sections": [
            (
                "Коротко",
                [
                    "TLS Audit принимает домен и порт, выполняет проверку публичной HTTPS/TLS-конфигурации и сохраняет технический отчет.",
                    "Сервис не требует регистрации, не принимает платежи и не просит вводить имя, телефон или пароль.",
                    "Мы не используем необязательные cookies и не подключаем рекламные трекеры.",
                ],
            ),
            (
                "Какие данные обрабатываются",
                [
                    "Домен, порт, IP-адреса цели, статус проверки, итоговый отчет и технические признаки TLS-конфигурации.",
                    "IP-адрес пользователя, время запроса и технические заголовки могут попадать в журналы Nginx/API и в механизм ограничения нагрузки.",
                    "Идентификатор проверки используется для открытия отчета по прямой ссылке.",
                ],
            ),
            (
                "Зачем это нужно",
                [
                    "Чтобы выполнить проверку, показать отчет, ограничивать злоупотребления и поддерживать стабильность сервиса.",
                    "Чтобы расследовать ошибки, атаки на сервис и чрезмерную нагрузку.",
                    "Чтобы улучшать качество рекомендаций и безопасность TLS Audit.",
                ],
            ),
            (
                "Срок хранения",
                [
                    "Отчеты и технические записи хранятся ограниченное время, заданное настройками сервиса.",
                    "Ошибочные и незавершенные проверки могут удаляться быстрее рабочих отчетов.",
                    "При публичном запуске срок хранения будет закреплен в этой политике точным числом дней.",
                ],
            ),
            (
                "Передача третьим лицам",
                [
                    "TLS Audit не продает данные и не передает их рекламным сетям.",
                    "Данные могут обрабатываться на серверной инфраструктуре, где размещен сервис.",
                    "Передача возможна только если это требуется законом или необходимо для защиты сервиса от злоупотреблений.",
                ],
            ),
            (
                "Права пользователя",
                [
                    "Можно запросить удаление отчета или уточнение данных, если вы можете указать ссылку/идентификатор проверки.",
                    f"Контакт для вопросов по данным и отчетам: {CONTACT_EMAIL}.",
                ],
            ),
        ],
    },
    "terms": {
        "title": "Пользовательское соглашение",
        "description": "Условия использования TLS Audit: проверяйте только свои домены или домены, на проверку которых у вас есть разрешение.",
        "path": "/terms",
        "sections": [
            (
                "Назначение сервиса",
                [
                    "TLS Audit помогает оценить публичную HTTPS/TLS-конфигурацию сайта и получить рекомендации по исправлению.",
                    "Отчет является справочной технической информацией и не заменяет полноценный аудит безопасности.",
                ],
            ),
            (
                "Разрешенное использование",
                [
                    "Проверяйте только свои сайты или сайты, на проверку которых у вас есть явное разрешение.",
                    "Не используйте сервис для массового сканирования, обхода ограничений, атаки на чужую инфраструктуру или создания чрезмерной нагрузки.",
                    "Не пытайтесь сканировать приватные сети, localhost, metadata endpoints и служебные адреса.",
                ],
            ),
            (
                "Ограничения",
                [
                    "Сервис может ограничивать частоту запросов, очередь, параллельные проверки и повторное сканирование одного домена.",
                    "TLS Audit может временно отказать в проверке, если цель выглядит небезопасной для сканирования или сервис перегружен.",
                ],
            ),
            (
                "Оценки и рекомендации",
                [
                    "Оценка A+...D является внутренней шкалой TLS Audit и может меняться по мере развития методики.",
                    "Рекомендации нужно применять с учетом вашей инфраструктуры, CDN, балансировщиков и требований совместимости.",
                ],
            ),
            (
                "Ответственность",
                [
                    "Сервис предоставляется как инструмент диагностики без гарантии абсолютной полноты результата.",
                    "Пользователь отвечает за правомерность запуска проверки и за изменения, которые он применяет на своем сервере.",
                ],
            ),
        ],
    },
    "cookies": {
        "title": "Политика cookies",
        "description": "TLS Audit сейчас не использует необязательные cookies и рекламные трекеры.",
        "path": "/cookies",
        "sections": [
            (
                "Текущее состояние",
                [
                    "TLS Audit сейчас не устанавливает необязательные cookies в браузер пользователя.",
                    "Сервис работает через обычные HTTP-запросы к API и не требует авторизации.",
                    "Если позже будет подключена аналитика, политика будет обновлена до включения такого инструмента.",
                ],
            ),
            (
                "Технические данные без cookies",
                [
                    "Серверные журналы могут содержать IP-адрес, дату, URL запроса, код ответа и user-agent.",
                    "Эти данные нужны для диагностики ошибок, защиты от злоупотреблений и оценки стабильности сервиса.",
                ],
            ),
            (
                "Будущая аналитика",
                [
                    "Для первого публичного этапа предпочтительна статистика по серверным логам без рекламных идентификаторов.",
                    "Если появится Яндекс Метрика или другой счетчик, нужно добавить уведомление, описание целей и настройку согласия.",
                ],
            ),
        ],
    },
    "security": {
        "title": "Безопасность и допустимое использование",
        "description": "Как TLS Audit защищает себя и какие проверки считаются допустимыми.",
        "path": "/security",
        "sections": [
            (
                "Что делает TLS Audit",
                [
                    "Проверяет только публичную HTTPS/TLS-конфигурацию указанного хоста и порта.",
                    "Блокирует приватные, служебные, link-local, localhost и metadata-адреса.",
                    "Повторно проверяет DNS перед запуском worker, чтобы снизить риск DNS rebinding.",
                ],
            ),
            (
                "Что не делает TLS Audit",
                [
                    "Не подбирает пароли, не сканирует веб-приложение на SQL-инъекции/XSS и не пытается получить доступ к данным сайта.",
                    "Не является инструментом массового сканирования чужой инфраструктуры.",
                    "Не гарантирует совместимость с SSL Labs: методика оценки у TLS Audit своя.",
                ],
            ),
            (
                "Защита сервиса",
                [
                    "Используются rate limit, очередь задач, таймауты worker и ограничения повторных проверок цели.",
                    "Сервис хранит минимальный набор технических данных, необходимых для отчета и стабильности.",
                    "Следующий инфраструктурный этап: внешний мониторинг, алерты, бэкапы и firewall-ограничения для scanner containers.",
                ],
            ),
            (
                "Сообщить о проблеме",
                [
                    f"Контакт для abuse/security сообщений: {CONTACT_EMAIL}.",
                    "В сообщении желательно указать домен, время проверки, ссылку на отчет и краткое описание проблемы.",
                ],
            ),
        ],
    },
    "ssl-certificate-check": {
        "title": "Проверка SSL-сертификата онлайн",
        "description": "Бесплатная проверка SSL-сертификата сайта: срок действия, SAN, issuer, совпадение домена и цепочка доверия.",
        "path": "/ssl-certificate-check",
        "sections": [
            (
                "Что проверяет TLS Audit",
                [
                    "Срок действия сертификата и количество дней до истечения.",
                    "Совпадает ли домен с SAN/CN сертификата.",
                    "Кто выпустил сертификат: issuer, алгоритм подписи и параметры ключа.",
                    "Есть ли признаки self-signed сертификата, hostname mismatch или проблем с цепочкой доверия.",
                ],
            ),
            (
                "Почему это важно",
                [
                    "Истекший сертификат или ошибка имени домена ломают доверие браузера и могут привести к предупреждению для посетителей.",
                    "Неполная цепочка сертификатов часто проявляется не у всех пользователей сразу, поэтому проблему легко пропустить.",
                    "Слабые алгоритмы подписи и маленький ключ снижают итоговую оценку TLS-конфигурации.",
                ],
            ),
            (
                "Как исправлять типовые проблемы",
                [
                    "Обновите сертификат заранее, не дожидаясь последнего дня действия.",
                    "Проверьте, что сертификат выпущен именно для нужного домена и всех используемых поддоменов.",
                    "Установите intermediate certificates в правильном порядке на веб-сервере или в панели хостинга.",
                    "После замены сертификата запустите повторную проверку без кеша и сравните отчет.",
                ],
            ),
        ],
    },
    "tls-versions-check": {
        "title": "Проверка TLS 1.2 и TLS 1.3",
        "description": "Проверка поддерживаемых TLS-версий сайта и рекомендации по отключению SSLv3, TLS 1.0 и TLS 1.1.",
        "path": "/tls-versions-check",
        "sections": [
            (
                "Современный минимум",
                [
                    "Для публичного сайта нормальная база — TLS 1.2 и TLS 1.3.",
                    "SSLv2 и SSLv3 считаются критически устаревшими и должны быть отключены.",
                    "TLS 1.0 и TLS 1.1 больше не должны использоваться для обычной публичной HTTPS-конфигурации.",
                ],
            ),
            (
                "Что показывает отчет",
                [
                    "Какие версии протокола принимает сервер.",
                    "Какой cipher suite согласуется для поддерживаемых версий.",
                    "Почему оценка может быть снижена при включенных legacy-протоколах.",
                ],
            ),
            (
                "Пример настройки",
                [
                    "Для Nginx обычно достаточно оставить ssl_protocols TLSv1.2 TLSv1.3.",
                    "Для Apache используйте SSLProtocol TLSv1.2 TLSv1.3.",
                    "Если рядом есть старые клиенты, сначала проверьте аудиторию и совместимость, а потом отключайте legacy-протоколы.",
                ],
            ),
        ],
    },
    "hsts-check": {
        "title": "Проверка HSTS и путь к A+",
        "description": "Проверка Strict-Transport-Security, max-age, includeSubDomains и рекомендаций для сильной HTTPS-конфигурации.",
        "path": "/hsts-check",
        "sections": [
            (
                "Что такое HSTS",
                [
                    "HSTS говорит браузеру всегда открывать сайт по HTTPS после первого успешного посещения.",
                    "Это снижает риск downgrade-атак и случайного перехода на небезопасный HTTP.",
                    "Для высокой оценки важны TLS 1.2/1.3, сильные cipher suites, корректный сертификат и включенный HSTS.",
                ],
            ),
            (
                "Как включать безопасно",
                [
                    "Начните с тестового max-age=300 и убедитесь, что весь сайт работает по HTTPS.",
                    "После проверки увеличьте max-age до 31536000.",
                    "includeSubDomains включайте только если все поддомены готовы к HTTPS.",
                    "preload требует особой осторожности: это почти необратимое публичное обязательство для домена.",
                ],
            ),
            (
                "Что проверяет TLS Audit",
                [
                    "Наличие Strict-Transport-Security на HTTPS-ответе.",
                    "Значение max-age, includeSubDomains и preload.",
                    "Связанные заголовки безопасности, которые помогают оценить общую конфигурацию.",
                ],
            ),
        ],
    },
    "nginx-tls-config": {
        "title": "TLS-конфиг для Nginx",
        "description": "Базовый современный TLS-конфиг для Nginx: TLS 1.2/1.3, HSTS, OCSP stapling и безопасные заголовки.",
        "path": "/nginx-tls-config",
        "sections": [
            (
                "Базовый пример",
                [
                    "ssl_protocols TLSv1.2 TLSv1.3;",
                    "ssl_prefer_server_ciphers off;",
                    "ssl_session_cache shared:SSL:10m;",
                    "ssl_session_timeout 1d;",
                    "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                ],
            ),
            (
                "Что проверить после включения",
                [
                    "Сертификат должен содержать все нужные домены в SAN.",
                    "HTTP должен редиректить на HTTPS без длинной цепочки редиректов.",
                    "TLS 1.0, TLS 1.1, SSLv2 и SSLv3 должны быть отключены.",
                    "HSTS с includeSubDomains включайте только если все поддомены готовы к HTTPS.",
                ],
            ),
            (
                "Осторожно с копированием",
                [
                    "Не вставляйте конфиг вслепую на production: сначала проверьте staging или непиковое окно.",
                    "Если сайт стоит за CDN или балансировщиком, TLS может завершаться не на Nginx, а выше по цепочке.",
                    "После изменения конфигурации запустите nginx -t, reload и повторную проверку в TLS Audit.",
                ],
            ),
        ],
    },
    "apache-tls-config": {
        "title": "TLS-конфиг для Apache",
        "description": "Базовый современный TLS-конфиг для Apache HTTP Server: TLS 1.2/1.3, HSTS и отключение устаревших протоколов.",
        "path": "/apache-tls-config",
        "sections": [
            (
                "Базовый пример",
                [
                    "SSLProtocol TLSv1.2 TLSv1.3",
                    "SSLHonorCipherOrder off",
                    "SSLCompression off",
                    "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
                ],
            ),
            (
                "Модули и контекст",
                [
                    "Для HTTPS нужен mod_ssl.",
                    "Для HSTS через Header нужен mod_headers.",
                    "Настройки обычно размещаются в VirtualHost для 443 порта или в общем SSL include.",
                ],
            ),
            (
                "Проверка после reload",
                [
                    "Запустите apachectl configtest перед reload.",
                    "Проверьте, что сертификат и intermediate chain установлены корректно.",
                    "После reload повторите проверку в TLS Audit и убедитесь, что legacy TLS больше не поддерживается.",
                ],
            ),
        ],
    },
    "a-plus-grade": {
        "title": "Как получить A+ за HTTPS/TLS",
        "description": "Что нужно для высокой оценки TLS Audit: корректный сертификат, TLS 1.2/1.3, сильные cipher suites, HSTS и отсутствие критичных проблем.",
        "path": "/a-plus-grade",
        "sections": [
            (
                "База для A+",
                [
                    "Действующий сертификат без hostname mismatch и с корректной цепочкой доверия.",
                    "Поддержка TLS 1.2 и TLS 1.3 без SSLv2, SSLv3, TLS 1.0 и TLS 1.1.",
                    "Отсутствие опасных cipher suites: NULL, EXPORT, anonymous, RC4 и 3DES.",
                    "Включенный HSTS с достаточным max-age после проверки всех HTTPS-переходов.",
                ],
            ),
            (
                "Что чаще всего мешает",
                [
                    "Старые протоколы оставлены ради совместимости, но реально уже не нужны аудитории сайта.",
                    "Сервер принимает CBC-only или другие legacy-наборы шифров.",
                    "Не установлен intermediate certificate или нарушен порядок цепочки.",
                    "HSTS не включен, потому что его забыли после настройки сертификата.",
                ],
            ),
            (
                "Практический порядок",
                [
                    "Сначала исправьте сертификат и цепочку доверия.",
                    "Потом отключите legacy TLS и опасные cipher suites.",
                    "После этого включите HSTS с тестовым max-age, проверьте сайт и только затем увеличивайте срок.",
                    "Запустите повторную проверку в TLS Audit и смотрите разделы 'Критично' и 'Влияет на безопасность'.",
                ],
            ),
        ],
    },
    "caddy-tls-config": {
        "title": "TLS-конфиг для Caddy",
        "description": "Базовая HTTPS/TLS-настройка Caddy: автоматические сертификаты, HSTS и проверка после запуска.",
        "path": "/caddy-tls-config",
        "sections": [
            (
                "Пример Caddyfile",
                [
                    "example.ru {",
                    "    encode zstd gzip",
                    "    header Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
                    "    reverse_proxy 127.0.0.1:3000",
                    "}",
                ],
            ),
            (
                "Особенности Caddy",
                [
                    "Caddy обычно сам получает и обновляет Let's Encrypt сертификаты.",
                    "TLS 1.2 и TLS 1.3 включены по умолчанию в современных версиях.",
                    "HSTS не стоит включать до проверки всех поддоменов, если используете includeSubDomains.",
                ],
            ),
            (
                "После изменения",
                [
                    "Проверьте конфиг командой caddy validate.",
                    "Перезагрузите сервис через systemctl reload caddy или caddy reload.",
                    "Запустите TLS Audit и убедитесь, что сертификат, TLS-версии и HSTS определяются корректно.",
                ],
            ),
        ],
    },
    "haproxy-tls-config": {
        "title": "TLS-конфиг для HAProxy",
        "description": "Базовая HTTPS/TLS-настройка HAProxy: bind с TLS, современные протоколы, HSTS и backend proxy.",
        "path": "/haproxy-tls-config",
        "sections": [
            (
                "Пример frontend",
                [
                    "frontend https-in",
                    "    bind :443 ssl crt /etc/haproxy/certs/example.pem alpn h2,http/1.1 ssl-min-ver TLSv1.2",
                    "    http-response set-header Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
                    "    default_backend app",
                ],
            ),
            (
                "На что обратить внимание",
                [
                    "Файл сертификата HAProxy обычно содержит private key, leaf certificate и chain в одном PEM.",
                    "ssl-min-ver TLSv1.2 отключает TLS 1.0 и TLS 1.1.",
                    "Если TLS завершается на HAProxy, настройки Nginx/Apache за ним уже не влияют на публичную TLS-оценку.",
                ],
            ),
            (
                "Проверка после reload",
                [
                    "Запустите haproxy -c -f /etc/haproxy/haproxy.cfg.",
                    "После reload проверьте, что HTTP/2, сертификат и HSTS видны снаружи.",
                    "Если перед HAProxy стоит CDN, проверять нужно публичную точку входа, а не внутренний backend.",
                ],
            ),
        ],
    },
    "methodology": {
        "title": "Методика проверки HTTPS/TLS",
        "description": "Как TLS Audit проверяет сайт, из чего складывается оценка и почему автоматический отчёт нужно читать вместе с рекомендациями.",
        "path": "/methodology",
        "sections": [
            (
                "Что проверяется",
                [
                    "Сертификат: срок действия, совпадение домена, SAN, issuer, параметры ключа и базовые признаки цепочки доверия.",
                    "TLS-конфигурация: поддерживаемые версии протокола, наборы шифров, forward secrecy и опасные legacy-настройки.",
                    "HTTP-защита: HSTS, OCSP stapling и связанные заголовки, которые влияют на устойчивость HTTPS-конфигурации.",
                    "Российская совместимость: признаки российских УЦ и ГОСТ вынесены отдельно и не смешиваются с глобальной TLS-оценкой.",
                ],
            ),
            (
                "Как читать оценку",
                [
                    "A+ означает сильную публичную HTTPS/TLS-конфигурацию без критичных замечаний и с включённым HSTS.",
                    "A и B обычно означают рабочую современную основу, но с улучшениями, которые стоит запланировать.",
                    "C и D показывают, что есть заметные проблемы безопасности или совместимости, которые лучше исправить первыми.",
                    "Информационные уведомления не обязаны снижать оценку: они помогают довести конфигурацию до аккуратного состояния.",
                ],
            ),
            (
                "Приоритеты исправлений",
                [
                    "Сначала исправляйте критичные проблемы: истёкший сертификат, mismatch домена, SSLv3, опасные cipher suites и недоверенную цепочку.",
                    "Затем убирайте устаревшие протоколы и слабые наборы шифров, если они включены ради старой совместимости.",
                    "После этого включайте HSTS и дополнительные hardening-настройки, проверяя сайт и поддомены перед жёсткими параметрами.",
                    "Повторная проверка показывает блок 'Было/стало', чтобы было видно, какие замечания исчезли после изменений.",
                ],
            ),
            (
                "Ограничения автоматической проверки",
                [
                    "Сервис видит публичную точку входа: если перед сайтом стоит CDN или балансировщик, отчёт относится именно к нему.",
                    "Некоторые риски зависят от приложения и содержимого страниц, поэтому они могут показываться как уведомления, а не как жёсткое снижение оценки.",
                    "Отчёт помогает быстро найти проблемы конфигурации, но не заменяет полноценный аудит инфраструктуры и веб-приложения.",
                    "Методика TLS Audit развивается, поэтому оценка может уточняться по мере появления новых проверок и практики эксплуатации.",
                ],
            ),
        ],
    },
}


def render_static_page(page_key: str) -> str:
    page = STATIC_PAGES[page_key]
    canonical = settings.public_base_url + page["path"]
    structured_data = render_json_ld(
        {
            "@context": "https://schema.org",
            "@type": "TechArticle",
            "headline": page["title"],
            "description": page["description"],
            "url": canonical,
            "inLanguage": "ru-RU",
            "publisher": {
                "@type": "Organization",
                "name": "TLS Audit",
                "url": settings.public_base_url + "/",
            },
            "dateModified": "2026-05-13",
        }
    )
    sections = "\n".join(
        f"""
        <section>
          <h2>{escape(title)}</h2>
          <ul>
            {''.join(f'<li>{render_text_with_contact_link(item)}</li>' for item in items)}
          </ul>
        </section>
        """
        for title, items in page["sections"]
    )
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(page["title"])} — TLS Audit</title>
  <meta name="description" content="{escape(page["description"])}">
  <meta name="robots" content="index,follow">
  <meta name="theme-color" content="#0f766e">
  <link rel="canonical" href="{escape(canonical)}">
  {structured_data}
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f4;
      --ink: #17191f;
      --muted: #606776;
      --line: #d9ddd4;
      --panel: #ffffff;
      --teal: #0f766e;
      --teal-dark: #0b5f59;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.55;
    }}
    main {{ width: min(920px, calc(100% - 32px)); margin: 0 auto; padding: 30px 0 48px; }}
    header {{ padding: 12px 0 22px; border-bottom: 1px solid var(--line); }}
    h1, h2, p {{ margin: 0; }}
    h1 {{ font-size: clamp(28px, 4vw, 42px); line-height: 1.05; letter-spacing: 0; }}
    h2 {{ font-size: 20px; margin-bottom: 10px; }}
    a {{ color: var(--teal-dark); }}
    .brand-link {{ color: inherit; text-decoration: none; }}
    .brand-link:hover {{ color: var(--teal-dark); }}
    .lead {{ color: var(--muted); margin-top: 10px; max-width: 760px; }}
    .back {{ display: inline-flex; margin-top: 18px; font-weight: 750; }}
    .content {{ display: grid; gap: 14px; margin-top: 18px; }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }}
    ul {{ margin: 0; padding-left: 18px; display: grid; gap: 7px; }}
    footer {{ margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); }}
    footer nav {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 8px; }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1><a class="brand-link" href="/">TLS Audit</a></h1>
      <p class="lead">{escape(page["description"])}</p>
      <a class="back" href="/">Вернуться к проверке</a>
    </header>
    <div class="content">
      {sections}
    </div>
    <footer>
      <p>Обновлено: 12.05.2026. Контакт: {CONTACT_LINK}. Документы нужно финально проверить перед широким публичным продвижением сервиса.</p>
      <nav>
        <a href="/ssl-certificate-check">Проверка SSL-сертификата</a>
        <a href="/tls-versions-check">TLS 1.2/1.3</a>
        <a href="/hsts-check">HSTS</a>
        <a href="/a-plus-grade">Оценка A+</a>
        <a href="/nginx-tls-config">Nginx TLS</a>
        <a href="/apache-tls-config">Apache TLS</a>
        <a href="/caddy-tls-config">Caddy TLS</a>
        <a href="/haproxy-tls-config">HAProxy TLS</a>
        <a href="/methodology">Методика</a>
        <a href="/privacy">Политика обработки данных</a>
        <a href="/terms">Пользовательское соглашение</a>
        <a href="/cookies">Cookies</a>
        <a href="/security">Безопасность</a>
      </nav>
    </footer>
  </main>
</body>
</html>""".replace("{CONTACT_LINK}", CONTACT_LINK)


def render_text_with_contact_link(value: str) -> str:
    escaped = escape(value)
    return escaped.replace(CONTACT_EMAIL, CONTACT_LINK)


def render_json_ld(data: dict) -> str:
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return f'<script type="application/ld+json">{payload}</script>'


def render_frontend() -> str:
    return """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TLS Audit — проверка HTTPS и TLS-конфигурации сайта</title>
  <meta name="description" content="Бесплатная проверка SSL/TLS-конфигурации сайта: сертификат, цепочка доверия, TLS-версии, cipher suites, HSTS, OCSP и рекомендации по исправлению.">
  <meta name="robots" content="index,follow">
  <meta name="theme-color" content="#0f766e">
  <link rel="canonical" href="https://tlsaudit.ru/">
  <meta property="og:type" content="website">
  <meta property="og:locale" content="ru_RU">
  <meta property="og:site_name" content="TLS Audit">
  <meta property="og:title" content="TLS Audit — проверка HTTPS и TLS-конфигурации сайта">
  <meta property="og:description" content="Проверьте сертификат, цепочку доверия, TLS-версии, cipher suites, HSTS и получите рекомендации по исправлению.">
  <meta property="og:url" content="https://tlsaudit.ru/">
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="TLS Audit — проверка HTTPS и TLS-конфигурации сайта">
  <meta name="twitter:description" content="Проверка SSL/TLS-конфигурации сайта с оценкой и рекомендациями.">
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    "name": "TLS Audit",
    "url": "https://tlsaudit.ru/",
    "applicationCategory": "SecurityApplication",
    "operatingSystem": "Web",
    "description": "Проверка HTTPS/TLS-конфигурации сайта: сертификат, цепочка доверия, TLS-версии, cipher suites, HSTS, OCSP и рекомендации.",
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "RUB"
    }
  }
  </script>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f4;
      --ink: #17191f;
      --muted: #606776;
      --line: #d9ddd4;
      --panel: #ffffff;
      --soft: #eef1ec;
      --teal: #0f766e;
      --teal-dark: #0b5f59;
      --blue: #315a9b;
      --amber: #a65f00;
      --red: #b42318;
      --green: #147a43;
      --violet: #6941c6;
      --code: #151922;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.45;
    }
    main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 48px; }
    header {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 18px;
      align-items: end;
      padding: 14px 0 24px;
      border-bottom: 1px solid var(--line);
    }
    h1, h2, h3, p { margin: 0; }
    h1 { font-size: clamp(28px, 4vw, 46px); line-height: 1.02; letter-spacing: 0; }
    h2 { font-size: 20px; line-height: 1.2; margin-bottom: 14px; }
    h3 { font-size: 15px; line-height: 1.2; margin-bottom: 8px; }
	    .muted { color: var(--muted); }
	    .brand-note { margin-top: 8px; max-width: 700px; color: var(--muted); }
	    .brand-link { color: inherit; text-decoration: none; }
	    .brand-link:hover { color: var(--teal-dark); }
    form {
      display: grid;
      grid-template-columns: minmax(220px, 1fr) 112px 136px;
      gap: 8px;
      align-items: center;
      min-width: min(100%, 620px);
    }
    label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 5px; }
    input, button {
      width: 100%;
      min-height: 44px;
      border-radius: 8px;
      font: inherit;
    }
    input {
      border: 1px solid #c9cec6;
      background: #fff;
      color: var(--ink);
      padding: 0 12px;
    }
    button {
      border: 0;
      background: var(--teal);
      color: #fff;
      font-weight: 750;
      cursor: pointer;
      padding: 0 14px;
      white-space: nowrap;
    }
    button:hover { background: var(--teal-dark); }
    button:disabled { cursor: wait; opacity: .65; }
    .ghost-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 38px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: #fff;
      color: var(--ink);
      padding: 0 12px;
      text-decoration: none;
      font-weight: 700;
    }
    .hero-status {
      display: grid;
      grid-template-columns: 160px minmax(0, 1fr);
      gap: 20px;
      align-items: stretch;
      padding: 26px 0 20px;
    }
    .grade-box {
      min-height: 150px;
      border-radius: 8px;
      background: #17202a;
      color: #fff;
      display: grid;
      place-items: center;
      text-align: center;
      padding: 16px;
    }
    .grade {
      font-size: 64px;
      line-height: 1;
      font-weight: 850;
      letter-spacing: 0;
    }
    .score { margin-top: 8px; color: #cdd6e1; }
    .grade-a { background: #12633f; }
    .grade-b { background: #315a9b; }
    .grade-c { background: #946200; }
    .grade-d { background: #9a3412; }
    .summary-panel {
      border-radius: 8px;
      background: var(--panel);
      border: 1px solid var(--line);
      padding: 18px;
      min-width: 0;
    }
    .summary-head {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 14px;
    }
    .target { font-size: 22px; font-weight: 800; overflow-wrap: anywhere; }
    .chips { display: flex; flex-wrap: wrap; gap: 8px; }
    .chip {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      border-radius: 999px;
      padding: 0 10px;
      font-size: 13px;
      font-weight: 700;
      background: var(--soft);
      color: #333a45;
    }
    .chip.good { background: #dff3e8; color: #075231; }
    .chip.warn { background: #fff0cf; color: #744600; }
    .chip.bad { background: #fde2df; color: #8a1f16; }
    .chip.info { background: #e8eefb; color: #274879; }
    .progress-wrap {
      border-radius: 8px;
      background: var(--panel);
      border: 1px solid var(--line);
      padding: 16px;
      margin: 20px 0 0;
    }
    .progress-track { height: 12px; border-radius: 999px; background: #e2e6df; overflow: hidden; }
    .progress-bar { height: 100%; width: 0%; background: linear-gradient(90deg, var(--teal), var(--blue)); transition: width .25s ease; }
    .progress-row { display: flex; justify-content: space-between; gap: 12px; margin-bottom: 10px; color: var(--muted); }
    .grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 14px; margin-top: 14px; }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      min-width: 0;
      max-width: 100%;
      overflow: hidden;
    }
    .span-4 { grid-column: span 4; }
    .span-5 { grid-column: span 5; }
    .span-6 { grid-column: span 6; }
    .span-7 { grid-column: span 7; }
    .span-8 { grid-column: span 8; }
    .span-12 { grid-column: span 12; }
    .kv { display: grid; grid-template-columns: minmax(130px, .48fr) minmax(0, 1fr); gap: 8px 12px; }
    .kv dt { color: var(--muted); }
    .kv dd { margin: 0; overflow-wrap: anywhere; font-weight: 650; }
    .list { display: grid; gap: 10px; }
    .list { min-width: 0; max-width: 100%; }
    .finding {
      border: 1px solid var(--line);
      border-left: 5px solid var(--blue);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
      min-width: 0;
      max-width: 100%;
      overflow: hidden;
    }
    .finding.critical, .finding.high { border-left-color: var(--red); }
    .finding.medium { border-left-color: var(--amber); }
    .finding.info { border-left-color: var(--blue); }
    .finding-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 6px; }
    .severity { font-size: 12px; font-weight: 850; text-transform: uppercase; color: var(--muted); }
    .recommendation {
      border-top: 1px solid var(--line);
      padding-top: 10px;
      margin-top: 10px;
      min-width: 0;
      max-width: 100%;
    }
    .finding p, .recommendation p { overflow-wrap: anywhere; }
    .detail-list {
      margin: 8px 0 0;
      padding-left: 18px;
      color: #303846;
      display: grid;
      gap: 4px;
    }
    .detail-list li { overflow-wrap: anywhere; }
    .compare-strip {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }
    .compare-card {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
      min-width: 0;
    }
    .compare-label { color: var(--muted); font-size: 13px; font-weight: 700; }
    .compare-value { margin-top: 4px; font-size: 20px; font-weight: 850; overflow-wrap: anywhere; }
    .compare-value.good { color: #075231; }
    .compare-value.bad { color: #8a1f16; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    pre {
      display: block;
      max-width: 100%;
      margin: 8px 0 0;
      padding: 12px;
      border-radius: 8px;
      background: var(--code);
      color: #edf1f7;
      overflow-x: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      font-size: 13px;
      line-height: 1.45;
    }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
    th { color: var(--muted); font-weight: 750; }
    td { overflow-wrap: anywhere; }
	    .empty {
	      padding: 30px 0;
	      color: var(--muted);
	      text-align: center;
	    }
	    .about-page {
	      display: grid;
	      grid-template-columns: repeat(3, minmax(0, 1fr));
	      gap: 14px;
	      margin-top: 18px;
	    }
	    .about-intro {
	      grid-column: span 3;
	      padding: 0 0 4px;
	      max-width: 860px;
	    }
	    .about-intro p { color: var(--muted); margin-top: 8px; }
	    .about-page ul {
	      margin: 0;
	      padding-left: 18px;
	      display: grid;
	      gap: 6px;
	      color: #303846;
	    }
    .site-footer {
      margin-top: 22px;
      padding-top: 16px;
      border-top: 1px solid var(--line);
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      gap: 10px 14px;
      align-items: center;
      justify-content: space-between;
    }
    .site-footer nav { display: flex; flex-wrap: wrap; gap: 10px 14px; }
    .site-footer a { color: var(--teal-dark); font-weight: 700; text-decoration: none; }
    .site-footer a:hover { text-decoration: underline; }
    .hidden { display: none !important; }
    .error {
      margin-top: 16px;
      padding: 12px 14px;
      border-radius: 8px;
      color: #831d15;
      background: #fde7e3;
      border: 1px solid #f6b8b1;
    }
    details { margin-top: 12px; }
    summary { cursor: pointer; font-weight: 750; color: var(--blue); }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    #monitoring-panel table th:last-child,
    #monitoring-panel table td:last-child {
      text-align: right;
      width: 1%;
      white-space: nowrap;
    }
    .monitor-actions {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      justify-content: flex-end;
    }
    .monitor-btn {
      min-height: 30px;
      border-radius: 6px;
      padding: 0 10px;
      font-size: 12px;
      font-weight: 700;
      line-height: 1;
    }
    .monitor-btn.secondary {
      background: #2f4f79;
    }
    .monitor-btn.secondary:hover {
      background: #264468;
    }
    @media print {
      @page { margin: 12mm; }
      body { background: #fff; color: #111; }
      main { width: 100%; padding: 0; }
      header, .progress-wrap, .site-footer, #about-page, #empty, #error, .actions { display: none !important; }
      #report { display: block !important; }
      .hero-status, .grid { display: block; }
      section, .summary-panel, .finding {
        break-inside: avoid;
        page-break-inside: avoid;
        border-color: #bbb;
        box-shadow: none;
      }
      section { margin-top: 10px; }
      .grade-box {
        min-height: auto;
        padding: 12px;
        color: #111;
        background: #fff !important;
        border: 2px solid #111;
      }
      .grade { font-size: 42px; }
      .chip {
        border: 1px solid #bbb;
        background: #fff !important;
        color: #111 !important;
      }
      pre {
        white-space: pre-wrap;
        background: #f3f4f6;
        color: #111;
        border: 1px solid #ccc;
      }
    }
	    @media (max-width: 900px) {
	      header, .hero-status { grid-template-columns: 1fr; }
	      form { grid-template-columns: 1fr 96px; }
	      form .domain-field { grid-column: span 2; }
	      .span-4, .span-5, .span-6, .span-7, .span-8 { grid-column: span 12; }
	      .about-page { grid-template-columns: 1fr; }
	      .about-intro { grid-column: auto; }
      .compare-strip { grid-template-columns: 1fr; }
	    }
    @media (max-width: 560px) {
      main { width: min(100% - 20px, 1180px); padding-top: 16px; }
      form { grid-template-columns: 1fr; }
      form .domain-field { grid-column: auto; }
      .grade { font-size: 52px; }
      .kv { grid-template-columns: 1fr; gap: 2px 0; }
      .finding-head { align-items: flex-start; flex-direction: column; }
      th, td { padding: 8px 6px; }
    }
  </style>
</head>
<body>
  <main>
    <header>
	      <div>
	        <h1><a class="brand-link" href="/">TLS Audit</a></h1>
	        <p class="brand-note">Отчет по HTTPS/TLS-конфигурации с причинами оценки и готовыми правками.</p>
	      </div>
      <form id="check-form" data-testid="check-form">
        <div class="domain-field">
          <label for="host">Домен</label>
          <input id="host" name="host" placeholder="example.ru" autocomplete="off" autofocus>
        </div>
        <div>
          <label for="port">Порт</label>
          <input id="port" name="port" inputmode="numeric" value="443">
        </div>
        <div>
          <label>&nbsp;</label>
          <button id="submit" type="submit">Проверить</button>
        </div>
      </form>
    </header>

    <div id="progress" class="progress-wrap hidden" data-testid="progress">
      <div class="progress-row">
        <span id="progress-stage">Ожидаем worker</span>
        <strong id="progress-percent">0%</strong>
      </div>
      <div class="progress-track"><div id="progress-bar" class="progress-bar"></div></div>
    </div>

	    <div id="error" class="error hidden" data-testid="error"></div>
	    <div id="empty" class="empty">Готов к первой проверке.</div>
      <section id="monitoring-panel">
        <h2>Мониторинг доменов</h2>
        <form id="monitor-form">
          <div class="domain-field">
            <label for="monitor-host">Домен</label>
            <input id="monitor-host" name="monitor-host" placeholder="example.ru" autocomplete="off">
          </div>
          <div>
            <label for="monitor-port">Порт</label>
            <input id="monitor-port" name="monitor-port" inputmode="numeric" value="443">
          </div>
          <div>
            <label for="monitor-interval">Интервал (сек.)</label>
            <input id="monitor-interval" name="monitor-interval" inputmode="numeric" value="86400">
          </div>
          <div>
            <label>&nbsp;</label>
            <button id="monitor-submit" type="submit">Добавить</button>
          </div>
        </form>
        <div id="monitor-msg" class="muted" style="margin-top:10px"></div>
        <div id="monitor-list" style="margin-top:12px"></div>
      </section>
		    <div id="report" class="hidden" data-testid="report"></div>
		    <div id="about-page" class="about-page" data-testid="about-page">
		      <div class="about-intro">
		        <h2>Что это за сервис</h2>
		        <p>TLS Audit проверяет публичную HTTPS/TLS-конфигурацию сайта и собирает короткий отчёт: оценка, причины, риски и готовые правки для администратора.</p>
		      </div>
	      <section>
	        <h2>Проверяем</h2>
	        <ul>
	          <li>сертификат, SAN и цепочку доверия;</li>
	          <li>TLS-версии и cipher suites;</li>
		          <li>HSTS, OCSP stapling и дополнительные проверки уязвимостей;</li>
	          <li>российскую TLS/ГОСТ-совместимость отдельным блоком.</li>
	        </ul>
	      </section>
	      <section>
	        <h2>Оценка</h2>
	        <ul>
	          <li>A+ означает сильную публичную TLS-конфигурацию;</li>
	          <li>D — нижняя публичная оценка для серьёзных проблем;</li>
	          <li>hardening не смешивается с критичными рисками;</li>
	          <li>российская совместимость не улучшает глобальную оценку.</li>
	        </ul>
	      </section>
	      <section>
	        <h2>Границы</h2>
	        <ul>
	          <li>сервис предназначен для своих доменов и разрешённых проверок;</li>
	          <li>приватные адреса и служебные сети блокируются;</li>
	          <li>отчёт помогает с конфигурацией, но не заменяет полноценный аудит.</li>
	        </ul>
		      </section>
		    </div>
    <footer class="site-footer">
      <span>TLS Audit проверяет только публичную HTTPS/TLS-конфигурацию. Контакт: {CONTACT_LINK}.</span>
      <nav aria-label="Документы сервиса">
        <a href="/ssl-certificate-check">SSL-сертификат</a>
        <a href="/tls-versions-check">TLS 1.2/1.3</a>
        <a href="/hsts-check">HSTS</a>
        <a href="/a-plus-grade">A+</a>
        <a href="/nginx-tls-config">Nginx TLS</a>
        <a href="/apache-tls-config">Apache TLS</a>
        <a href="/caddy-tls-config">Caddy TLS</a>
        <a href="/haproxy-tls-config">HAProxy TLS</a>
        <a href="/methodology">Методика</a>
        <a href="/privacy">Политика данных</a>
        <a href="/terms">Условия</a>
        <a href="/cookies">Cookies</a>
        <a href="/security">Безопасность</a>
      </nav>
    </footer>
	  </main>

  <script>
    const form = document.getElementById('check-form');
    const hostInput = document.getElementById('host');
    const portInput = document.getElementById('port');
    const submitButton = document.getElementById('submit');
    const progress = document.getElementById('progress');
    const progressStage = document.getElementById('progress-stage');
    const progressPercent = document.getElementById('progress-percent');
    const progressBar = document.getElementById('progress-bar');
	    const errorBox = document.getElementById('error');
	    const empty = document.getElementById('empty');
	    const reportBox = document.getElementById('report');
    const monitorForm = document.getElementById('monitor-form');
    const monitorHostInput = document.getElementById('monitor-host');
    const monitorPortInput = document.getElementById('monitor-port');
    const monitorIntervalInput = document.getElementById('monitor-interval');
    const monitorSubmitButton = document.getElementById('monitor-submit');
    const monitorMsg = document.getElementById('monitor-msg');
    const monitorList = document.getElementById('monitor-list');

    const severityOrder = {critical: 0, high: 1, medium: 2, low: 3, info: 4};
    const severityLabels = {
      critical: 'Критично',
      high: 'Высокий',
      medium: 'Средний',
      low: 'Низкий',
      info: 'Инфо'
    };

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      await startScan(hostInput.value, portInput.value);
    });
    monitorForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      await saveMonitoredDomain();
    });

	    window.addEventListener('popstate', () => {
	      const params = new URLSearchParams(location.search);
	      const job = params.get('job');
	      if (job) {
	        loadJob(job);
	        return;
	      }
	      showHomePage();
	    });

    bootstrap();

	    async function bootstrap() {
	      const params = new URLSearchParams(location.search);
	      const job = params.get('job');
	      if (job) {
        await loadJob(job);
        return;
      }
      const target = params.get('target');
	      if (target) {
	        hostInput.value = target;
	      }
	      showHomePage();
        await loadMonitoredDomains();
	    }

	    async function startScan(host, port) {
	      clearError();
	      reportBox.classList.add('hidden');
	      empty.classList.add('hidden');
      setProgress({ progress_percent: 2, progress_detail: 'Создаем проверку' });
      submitButton.disabled = true;
      try {
        const response = await fetch('/api/check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host: host.trim(), port: Number(port || 443) })
        });
        const data = await response.json();
        if (!response.ok) {
          throw new Error(apiErrorMessage(data, 'Проверка не создана'));
        }
        history.pushState({}, '', '/scan?job=' + encodeURIComponent(data.id));
        await pollJob(data.id);
      } catch (error) {
        showError(error.message);
        submitButton.disabled = false;
      }
    }

	    async function loadJob(jobId) {
	      clearError();
	      empty.classList.add('hidden');
	      reportBox.classList.add('hidden');
      setProgress({ progress_percent: 8, progress_detail: 'Загружаем статус' });
      submitButton.disabled = true;
      try {
        const status = await fetchJson('/api/check/' + encodeURIComponent(jobId));
        if (status.host) hostInput.value = status.host;
        if (status.port) portInput.value = status.port;
        if (status.status === 'done') {
          setProgress(status);
          const report = await fetchJson('/api/report/' + encodeURIComponent(jobId));
          renderReport(report, jobId, status);
          submitButton.disabled = false;
          progress.classList.add('hidden');
          return;
        }
        if (status.status === 'error') {
          throw new Error(status.error || 'Проверка завершилась ошибкой');
        }
        await pollJob(jobId);
      } catch (error) {
        showError(error.message);
        submitButton.disabled = false;
      }
    }

    async function pollJob(jobId) {
      for (let attempt = 0; attempt < 180; attempt += 1) {
        const status = await fetchJson('/api/check/' + encodeURIComponent(jobId));
        setProgress(status);
        if (status.status === 'done') {
          const report = await fetchJson('/api/report/' + encodeURIComponent(jobId));
          renderReport(report, jobId, status);
          submitButton.disabled = false;
          progress.classList.add('hidden');
          return;
        }
        if (status.status === 'error') {
          throw new Error(status.error || 'Проверка завершилась ошибкой');
        }
        await delay(1000);
      }
      throw new Error('Проверка длится слишком долго. Попробуйте повторить позже.');
    }

    async function fetchJson(url, options) {
      const response = await fetch(url, options);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(apiErrorMessage(data, 'Ошибка API'));
      }
      return data;
    }

    function apiErrorMessage(data, fallback) {
      const detail = data?.detail;
      if (typeof detail === 'string') return detail;
      if (detail?.message) {
        const retry = detail.retry_after ? ` Повторите через ${detail.retry_after} сек.` : '';
        return detail.message + retry;
      }
      return fallback;
    }

	    function setProgress(status) {
      const percent = Math.max(0, Math.min(100, Number(status.progress_percent || 0)));
      progress.classList.remove('hidden');
      progressBar.style.width = percent + '%';
      progressPercent.textContent = percent + '%';
	      progressStage.textContent = status.progress_detail || status.progress_stage || status.status || 'В работе';
	    }

	    function showHomePage() {
		      clearError();
		      progress.classList.add('hidden');
		      reportBox.classList.add('hidden');
		      empty.classList.remove('hidden');
		      submitButton.disabled = false;
		    }

    async function saveMonitoredDomain() {
      monitorMsg.textContent = '';
      monitorSubmitButton.disabled = true;
      try {
        const payload = {
          host: (monitorHostInput.value || '').trim(),
          port: Number(monitorPortInput.value || 443),
          scan_interval_seconds: Number(monitorIntervalInput.value || 86400),
          enabled: true,
          notes: ''
        };
        if (!payload.host) throw new Error('Укажите домен для мониторинга.');
        await fetchJson('/api/monitor/domains', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        monitorMsg.textContent = 'Домен добавлен в мониторинг.';
        await loadMonitoredDomains();
      } catch (error) {
        monitorMsg.textContent = error.message || 'Не удалось сохранить домен.';
      } finally {
        monitorSubmitButton.disabled = false;
      }
    }

    async function loadMonitoredDomains() {
      try {
        const data = await fetchJson('/api/monitor/domains?limit=30');
        const items = data.items || [];
        if (!items.length) {
          monitorList.innerHTML = '<p class="muted">Пока нет доменов в мониторинге.</p>';
          return;
        }
        const rows = await Promise.all(items.map(async (item) => {
          const events = await fetchJson('/api/monitor/domains/' + encodeURIComponent(String(item.id)) + '/events?limit=1');
          const lastEvent = (events.items || [])[0];
          return `
            <tr>
              <td>${escapeHtml(item.host)}:${escapeHtml(String(item.port || 443))}</td>
              <td>${item.enabled ? 'вкл' : 'выкл'}</td>
              <td>${escapeHtml(String(item.scan_interval_seconds || ''))}</td>
              <td>${escapeHtml(item.next_scan_at || '—')}</td>
              <td>${escapeHtml(lastEvent ? (lastEvent.title || lastEvent.event_type || '—') : '—')}</td>
              <td>
                <div class="monitor-actions">
                <button type="button" class="monitor-btn" data-monitor-toggle="${escapeHtml(String(item.id))}">
                  ${item.enabled ? 'выкл' : 'вкл'}
                </button>
                <button type="button" class="monitor-btn secondary" data-monitor-scan="${escapeHtml(String(item.id))}">
                  сканировать
                </button>
                </div>
              </td>
            </tr>
          `;
        }));
        monitorList.innerHTML = `
          <table>
            <thead>
              <tr>
                <th>Домен</th>
                <th>Статус</th>
                <th>Интервал</th>
                <th>След. скан</th>
                <th>Последнее событие</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>${rows.join('')}</tbody>
          </table>
        `;
        monitorList.querySelectorAll('[data-monitor-toggle]').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const id = btn.getAttribute('data-monitor-toggle');
            const row = items.find((x) => String(x.id) === String(id));
            if (!row) return;
            await toggleMonitoredDomain(row.id, !row.enabled);
          });
        });
        monitorList.querySelectorAll('[data-monitor-scan]').forEach((btn) => {
          btn.addEventListener('click', async () => {
            const id = btn.getAttribute('data-monitor-scan');
            if (!id) return;
            await runMonitoredScanNow(id);
          });
        });
      } catch (error) {
        monitorList.innerHTML = '<p class="muted">Не удалось загрузить список мониторинга.</p>';
      }
    }

    async function toggleMonitoredDomain(domainId, enabled) {
      monitorMsg.textContent = '';
      try {
        await fetchJson('/api/monitor/domains/' + encodeURIComponent(String(domainId)), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled })
        });
        monitorMsg.textContent = enabled ? 'Мониторинг включен.' : 'Мониторинг отключен.';
        await loadMonitoredDomains();
      } catch (error) {
        monitorMsg.textContent = error.message || 'Не удалось обновить статус домена.';
      }
    }

    async function runMonitoredScanNow(domainId) {
      monitorMsg.textContent = '';
      try {
        const result = await fetchJson('/api/monitor/domains/' + encodeURIComponent(String(domainId)) + '/scan-now', {
          method: 'POST'
        });
        if (result.status === 'queued' && result.job_id) {
          monitorMsg.textContent = 'Проверка поставлена в очередь.';
          history.pushState({}, '', '/scan?job=' + encodeURIComponent(result.job_id));
          await loadJob(result.job_id);
          return;
        }
        monitorMsg.textContent = result.detail || result.reason || 'Сканирование пропущено.';
        await loadMonitoredDomains();
      } catch (error) {
        monitorMsg.textContent = error.message || 'Не удалось запустить проверку.';
      }
    }

		    function renderReport(report, jobId, status) {
      const cert = report.certificate || {};
      const protocols = ((report.protocols || {}).items || []);
      const hsts = report.hsts || {};
      const chain = report.chain || {};
      const weakProbes = ((report.cipher_suites || {}).weak_probes || []);
      const testsslCiphers = ((report.cipher_suites || {}).testssl_cipher_tests || []);
      const serverPreferences = ((report.cipher_suites || {}).testssl_server_preferences || []);
      const forwardSecrecy = ((report.cipher_suites || {}).testssl_forward_secrecy || []);
      const vulnerabilities = report.vulnerabilities || {};
      const vulnerabilityProblems = vulnerabilities.problems || [];
      const russianTls = report.russian_tls || {};
      const findings = groupFindings(report.findings || []).sort((a, b) =>
        (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9)
      );
      const findingBuckets = bucketFindings(findings);
      const recommendations = report.recommendations || [];
      const supportedProtocols = protocols.filter((item) => item.supported).map((item) => item.version);
      const addresses = status?.addresses || report.raw?.basic_scanner?.addresses || [];

      const certDays = cert.expires_in_days;
      const certChipClass = cert.expired ? 'bad' : certDays !== null && certDays !== undefined && certDays <= 30 ? 'warn' : 'good';
      const hstsChipClass = hsts.hsts ? (hsts.hsts_include_subdomains ? 'good' : 'warn') : 'bad';

      reportBox.innerHTML = `
      <div class="hero-status">
          <div class="grade-box ${gradeClass(report.grade)}">
            <div>
              <div class="grade">${escapeHtml(displayGrade(report.grade))}</div>
              <div class="score">${displayScore(report.grade, report.score)}</div>
            </div>
          </div>
          <div class="summary-panel">
            <div class="summary-head">
              <div>
                <div class="target">${escapeHtml(report.host)}:${escapeHtml(String(report.port || 443))}</div>
                <p class="muted">${addresses.length ? escapeHtml(addresses.join(', ')) : 'IP-адрес не сохранен'}</p>
              </div>
              <div class="actions">
                <button type="button" id="rescan">Повторить</button>
                <button type="button" id="print-report">Печать/PDF</button>
                <a class="ghost-button" id="json-export" href="/api/report/${encodeURIComponent(jobId)}" target="_blank" rel="noopener">JSON</a>
              </div>
            </div>
            <div class="chips">
              ${chip('TLS: ' + (supportedProtocols.join(', ') || 'нет'), supportedProtocols.includes('TLS 1.2') || supportedProtocols.includes('TLS 1.3') ? 'good' : 'bad')}
              ${chip(cert.expired ? 'Сертификат истек' : certDays !== undefined && certDays !== null ? 'Сертификат: ' + certDays + ' дн.' : 'Сертификат: нет данных', certChipClass)}
              ${chip(hstsChipText(hsts), hstsChipClass)}
              ${chip(extraChecksChipText(vulnerabilities), vulnerabilities.testssl_status === 'done' ? (vulnerabilityProblems.length ? 'warn' : 'good') : 'info')}
              ${chip(russianChipText(russianTls), russianChipTone(russianTls))}
            </div>
            <div style="margin-top:14px">${renderSummary(report.summary || [])}</div>
          </div>
        </div>

        <div class="grid">
          <section class="span-12 hidden" id="compare-section">
            <h2>Было/стало</h2>
            <div id="compare-content"></div>
          </section>
          <section class="span-6">
            <h2>Критично</h2>
            ${renderFindings(findingBuckets.critical, 'Критичных проблем не найдено.')}
          </section>
          <section class="span-6">
            <h2>Влияет на безопасность</h2>
            ${renderFindings(findingBuckets.security, 'Серьёзных рисков безопасности не найдено.')}
          </section>
          <section class="span-7">
            <h2>Улучшение конфигурации</h2>
            ${renderFindings(findingBuckets.hardening, 'Обязательных улучшений конфигурации нет.')}
          </section>
          <section class="span-5">
            <h2>Готовые рекомендации</h2>
            ${renderRecommendations(recommendations)}
          </section>
          <section class="span-12">
            <h2>Информация</h2>
            ${renderFindings(findingBuckets.info, 'Информационных уведомлений нет.')}
          </section>
          <section class="span-6">
            <h2>Сертификат</h2>
            ${kv([
              ['Subject', cert.subject],
              ['Issuer', cert.issuer],
              ['SAN', Array.isArray(cert.subject_alt_names) ? cert.subject_alt_names.join(', ') : ''],
              ['Действителен до', cert.not_after],
              ['Осталось дней', cert.expires_in_days],
              ['Ключ', [cert.public_key_algorithm, cert.public_key_bits ? cert.public_key_bits + ' бит' : ''].filter(Boolean).join(', ')],
              ['Подпись', cert.signature_algorithm],
              ['Chain', cert.chain_length ? cert.chain_length + ' сертификата' : 'нет данных']
            ])}
          </section>
          <section class="span-6">
            <h2>Цепочка доверия</h2>
            ${renderTestsslItems(chain.testssl_items || [], 'Глубокая проверка пока не вернула данные по цепочке доверия.')}
          </section>
          <section class="span-6">
            <h2>TLS-протоколы</h2>
            ${renderProtocols(protocols)}
          </section>
          <section class="span-6">
            <h2>Уязвимости</h2>
            ${renderVulnerabilities(vulnerabilities)}
          </section>
          <section class="span-6">
            <h2>OCSP / Stapling</h2>
            ${renderOcsp(report.ocsp || {})}
          </section>
          <section class="span-8">
            <h2>Cipher suites</h2>
            ${renderCipherSuites(weakProbes, testsslCiphers, serverPreferences, forwardSecrecy)}
          </section>
          <section class="span-4">
            <h2>HSTS и заголовки</h2>
            ${kv([
              ['HSTS', hsts.hsts || 'нет'],
              ['max-age', hsts.hsts_max_age],
              ['includeSubDomains', hsts.hsts_include_subdomains ? 'да' : 'нет'],
              ['preload', hsts.hsts_preload ? 'да' : 'нет'],
              ['CSP', hsts.content_security_policy ? 'есть' : 'нет'],
              ['X-Content-Type-Options', hsts.x_content_type_options || 'нет'],
              ['Server', hsts.server]
            ])}
          </section>
          <section class="span-12">
            <h2>Российская совместимость</h2>
            ${renderRussianTls(russianTls)}
          </section>
        </div>
		      `;
      reportBox.classList.remove('hidden');
		      empty.classList.add('hidden');
      document.getElementById('rescan').addEventListener('click', () => {
        startScan(report.host, report.port || 443);
      });
      document.getElementById('print-report').addEventListener('click', () => {
        window.print();
      });
      loadComparison(jobId);
    }

    async function loadComparison(jobId) {
      const section = document.getElementById('compare-section');
      const content = document.getElementById('compare-content');
      if (!section || !content) return;
      try {
        const comparison = await fetchJson('/api/report/' + encodeURIComponent(jobId) + '/compare');
        if (!comparison.diff?.has_previous) {
          section.classList.add('hidden');
          return;
        }
        content.innerHTML = renderComparison(comparison);
        section.classList.remove('hidden');
      } catch (error) {
        section.classList.add('hidden');
      }
    }

    function renderComparison(comparison) {
      const previous = comparison.previous || {};
      const current = comparison.current || {};
      const diff = comparison.diff || {};
      const scoreDelta = diff.score_delta;
      const scoreDeltaText = scoreDelta === null || scoreDelta === undefined
        ? 'без данных'
        : (scoreDelta > 0 ? '+' : '') + formatNumber(scoreDelta);
      const scoreTone = scoreDelta > 0 ? 'good' : scoreDelta < 0 ? 'bad' : '';
      return `
        <div class="compare-strip">
          <div class="compare-card">
            <div class="compare-label">Оценка</div>
            <div class="compare-value">${escapeHtml(displayGrade(previous.grade))} → ${escapeHtml(displayGrade(current.grade))}</div>
          </div>
          <div class="compare-card">
            <div class="compare-label">Баллы</div>
            <div class="compare-value ${scoreTone}">${escapeHtml(scoreDeltaText)}</div>
          </div>
          <div class="compare-card">
            <div class="compare-label">Без изменений</div>
            <div class="compare-value">${escapeHtml(String(diff.unchanged_findings_count || 0))}</div>
          </div>
        </div>
        <div class="grid" style="margin-top:0">
          <div class="span-6">
            <h3>Ушло</h3>
            ${renderCompactFindings(diff.resolved_findings || [], 'Ничего не исчезло с прошлой проверки.')}
          </div>
          <div class="span-6">
            <h3>Появилось</h3>
            ${renderCompactFindings(diff.added_findings || [], 'Новых замечаний нет.')}
          </div>
        </div>
      `;
    }

    function renderCompactFindings(items, emptyMessage) {
      if (!items.length) return `<p class="muted">${escapeHtml(emptyMessage)}</p>`;
      return '<div class="list">' + items.map((item) => `
        <article class="finding ${escapeHtml(item.severity || 'info')}">
          <div class="finding-head">
            <h3>${escapeHtml(item.title || item.code || 'Finding')}</h3>
            <span class="severity">${escapeHtml(severityLabels[item.severity] || item.severity || 'Info')}</span>
          </div>
        </article>
      `).join('') + '</div>';
    }

    function formatNumber(value) {
      const number = Number(value || 0);
      if (Number.isInteger(number)) return String(number);
      return number.toFixed(1);
    }

    function renderSummary(items) {
      if (!items.length) return '<p class="muted">Причины оценки пока не сформированы.</p>';
      return '<div class="list">' + items.map((item) => `<p>${escapeHtml(item)}</p>`).join('') + '</div>';
    }

    function renderFindings(findings, emptyMessage) {
      if (!findings.length) {
        return `<p class="muted">${escapeHtml(emptyMessage || 'Заметных проблем не найдено.')}</p>`;
      }
      return '<div class="list">' + findings.map((finding) => `
        <article class="finding ${escapeHtml(finding.severity || 'info')}">
          <div class="finding-head">
            <h3>${escapeHtml(finding.title || finding.code || 'Finding')}</h3>
            <span class="severity">${escapeHtml(severityLabels[finding.severity] || finding.severity || 'Info')}</span>
          </div>
          ${renderFindingDetail(finding)}
          ${finding.grade_cap ? `<p class="muted" style="margin-top:6px">Ограничение оценки: ${escapeHtml(displayGrade(finding.grade_cap))}</p>` : ''}
        </article>
      `).join('') + '</div>';
    }

    function bucketFindings(findings) {
      const buckets = {critical: [], security: [], hardening: [], info: []};
      for (const finding of findings) {
        if (finding.severity === 'critical') {
          buckets.critical.push(finding);
        } else if (finding.severity === 'high') {
          buckets.security.push(finding);
        } else if (finding.severity === 'medium' || finding.severity === 'low') {
          buckets.hardening.push(finding);
        } else {
          buckets.info.push(finding);
        }
      }
      return buckets;
    }

    function groupFindings(items) {
      const groups = new Map();
      for (const item of items) {
        const key = [
          item.code || '',
          item.title || '',
          item.category || '',
          item.severity || '',
          item.grade_cap || ''
        ].join('|');
        if (!groups.has(key)) {
          groups.set(key, { ...item, details: [] });
        }
        const group = groups.get(key);
        const detail = String(item.detail || '').trim();
        if (detail && !group.details.includes(detail)) {
          group.details.push(detail);
        }
      }

      return [...groups.values()].map((group) => {
        if (group.details.length > 1 && String(group.code || '').startsWith('weak_cipher_')) {
          return {
            ...group,
            title: 'Сервер принимает слабые cipher suites',
            detail: `Обнаружено ${group.details.length} слабых набора шифров.`
          };
        }
        if (group.details.length > 1) {
          return {
            ...group,
            detail: `Обнаружено ${group.details.length} связанных замечания.`
          };
        }
        return {
          ...group,
          detail: group.details[0] || group.detail || ''
        };
      });
    }

    function hstsChipText(hsts) {
      if (!hsts.hsts) return 'HSTS: отсутствует';
      if (hsts.hsts_include_subdomains) return 'HSTS: включен с поддоменами';
      return 'HSTS: включен без поддоменов';
    }

    function extraChecksChipText(vulnerabilities) {
      if (vulnerabilities.testssl_status !== 'done') return 'Доп. проверки: нет данных';
      const count = (vulnerabilities.problems || []).length;
      if (!count) return 'Доп. проверки: OK';
      return 'Доп. проверки: ' + count + ' ' + pluralRu(count, 'замечание', 'замечания', 'замечаний');
    }

    function pluralRu(number, one, few, many) {
      const n = Math.abs(Number(number || 0));
      const mod10 = n % 10;
      const mod100 = n % 100;
      if (mod10 === 1 && mod100 !== 11) return one;
      if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return few;
      return many;
    }

    function renderFindingDetail(finding) {
      const details = finding.details || [];
      if (details.length <= 1) {
        return `<p>${escapeHtml(finding.detail || '')}</p>`;
      }
      return `
        <p>${escapeHtml(finding.detail || '')}</p>
        <ul class="detail-list">
          ${details.map((detail) => `<li>${escapeHtml(detail)}</li>`).join('')}
        </ul>
      `;
    }

    function renderRecommendations(recommendations) {
      if (!recommendations.length) {
        return '<p class="muted">Рекомендации появятся после проверки.</p>';
      }
      return '<div class="list">' + recommendations.map((item) => `
        <article class="finding">
          <h3>${escapeHtml(item.title || item.code)}</h3>
          <p>${escapeHtml(item.risk || '')}</p>
          <div class="recommendation">
            <p><strong>Исправление:</strong> ${escapeHtml(item.fix || '')}</p>
            ${item.nginx ? `<pre>${escapeHtml(item.nginx)}</pre>` : ''}
            ${item.apache ? `<pre>${escapeHtml(item.apache)}</pre>` : ''}
            ${item.iis ? `<p class="muted" style="margin-top:8px">IIS: ${escapeHtml(item.iis)}</p>` : ''}
          </div>
        </article>
      `).join('') + '</div>';
    }

    function renderProtocols(items) {
      if (!items.length) return '<p class="muted">Нет данных по протоколам.</p>';
      return `
        <table>
          <thead><tr><th>Версия</th><th>Статус</th><th>Cipher</th></tr></thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${escapeHtml(item.version || '')}</td>
                <td>${item.supported ? '<span class="chip good">поддерживается</span>' : '<span class="chip">нет</span>'}</td>
                <td>${escapeHtml(item.cipher || item.error || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderVulnerabilities(data) {
      if (data.testssl_status === 'disabled') {
        return '<p class="muted">Глубокая проверка временно недоступна.</p>';
      }
      if (data.testssl_status === 'error') {
        return '<p class="muted">Глубокая проверка не вернула результат.</p>';
      }
      const items = data.items || [];
      if (!items.length) return '<p class="muted">Глубокая проверка уязвимостей еще не выполнена.</p>';
      return `
        <table>
          <thead><tr><th>Проверка</th><th>Статус</th><th>Результат</th></tr></thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${escapeHtml(item.id || '')}</td>
                <td>${severityChip(item.severity)}</td>
                <td>${escapeHtml(item.finding || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderOcsp(data) {
      const items = data.testssl_items || [];
      if (!items.length) return '<p class="muted">Глубокая проверка не вернула OCSP-данные в этом профиле проверки.</p>';
      return `
        <table>
          <thead><tr><th>Параметр</th><th>Результат</th></tr></thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${escapeHtml(item.id || '')}</td>
                <td>${escapeHtml(item.finding || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderRussianTls(data) {
      if (!data || !Object.keys(data).length || data.status === 'not_checked') {
        return '<p class="muted">Российская TLS/ГОСТ-совместимость пока не проверена для этого отчета.</p>';
      }
      const trust = data.trust || {};
      const matches = data.matches || {};
      const gost = data.gost || {};
      const ordinary = data.ordinary_tls || {};
      return `
        <div class="chips" style="margin-bottom:12px">
          ${chip(data.status_label || russianChipText(data), russianChipTone(data))}
          ${chip(data.is_russian_ca ? 'УЦ РФ: найден' : 'УЦ РФ: нет', data.is_russian_ca ? 'good' : 'info')}
          ${chip(data.is_gost_certificate ? 'ГОСТ cert: найден' : 'ГОСТ cert: нет', data.is_gost_certificate ? 'warn' : 'info')}
          ${chip(ordinary.status === 'likely_ok' ? 'WebPKI: OK' : 'WebPKI: проверить', ordinary.status === 'likely_ok' ? 'good' : 'warn')}
        </div>
        ${renderSummary(data.summary || [])}
        <div style="margin-top:14px">
          ${kv([
            ['Источник списка УЦ', trust.source],
            ['Обновлен', trust.updated_at],
            ['Список устарел', trust.stale ? 'да' : 'нет'],
            ['Обычный TLS', ordinary.note],
            ['ГОСТ-маркеры', Array.isArray(gost.markers) && gost.markers.length ? gost.markers.join(', ') : 'не найдены'],
            ['ГОСТ OID', Array.isArray(gost.oids) && gost.oids.length ? gost.oids.join(', ') : 'не найдены']
          ])}
        </div>
        <h3 style="margin-top:14px">Совпадения со списком УЦ</h3>
        ${renderRussianMatches(matches)}
        <h3 style="margin-top:14px">Рекомендации РФ/ГОСТ</h3>
        ${renderBullets(data.recommendations || [], 'Дополнительных рекомендаций нет.')}
      `;
    }

    function renderRussianMatches(matches) {
      const items = [...(matches.roots || []), ...(matches.intermediates || [])];
      if (!items.length) return '<p class="muted">Совпадений с локальным списком российских УЦ нет.</p>';
      return `
        <table>
          <thead><tr><th>УЦ</th><th>Тип</th><th>Почему совпало</th></tr></thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${escapeHtml(item.name || '')}</td>
                <td>${escapeHtml(item.type || '')}</td>
                <td>${escapeHtml([...(item.matched_by || []), item.notes || ''].filter(Boolean).join('; '))}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderBullets(items, emptyMessage) {
      if (!items.length) return `<p class="muted">${escapeHtml(emptyMessage || 'Нет данных.')}</p>`;
      return '<ul class="detail-list">' + items.map((item) => `<li>${escapeHtml(item)}</li>`).join('') + '</ul>';
    }

    function renderCipherSuites(weakProbes, testsslCiphers, serverPreferences, forwardSecrecy) {
      if (!weakProbes.length && !testsslCiphers.length && !serverPreferences.length && !forwardSecrecy.length) return '<p class="muted">Нет данных по cipher suites.</p>';
      return `
        ${weakProbes.length ? '<h3>Быстрые проверки</h3>' + renderCipherProbes(weakProbes) : ''}
        ${serverPreferences.length ? '<h3 style="margin-top:14px">Предпочтения сервера</h3>' + renderTestsslItems(serverPreferences, '') : ''}
        ${forwardSecrecy.length ? '<h3 style="margin-top:14px">Forward secrecy / DH / EC</h3>' + renderTestsslItems(forwardSecrecy, '') : ''}
        ${testsslCiphers.length ? '<h3 style="margin-top:14px">Дополнительная проверка cipher suites</h3>' + renderTestsslCiphers(testsslCiphers) : ''}
      `;
    }

    function renderCipherProbes(items) {
      return `
        <table>
          <thead><tr><th>Suite</th><th>Результат</th><th>Причина</th></tr></thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${escapeHtml(item.name || '')}</td>
                <td>${item.accepted ? '<span class="chip warn">принимается</span>' : '<span class="chip good">отклонен</span>'}</td>
                <td>${escapeHtml(item.issue || item.error || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderTestsslCiphers(items) {
      return `
        <table>
          <thead><tr><th>Suite</th><th>Severity</th><th>Данные проверки</th></tr></thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${escapeHtml(cipherNameFromFinding(item.finding || item.id || ''))}</td>
                <td>${severityChip(item.severity)}</td>
                <td>${escapeHtml(item.finding || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderTestsslItems(items, emptyMessage) {
      if (!items.length) return `<p class="muted">${escapeHtml(emptyMessage || 'Нет данных.')}</p>`;
      return `
        <table>
          <thead><tr><th>Параметр</th><th>Статус</th><th>Результат</th></tr></thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${escapeHtml(item.id || '')}</td>
                <td>${severityChip(item.severity)}</td>
                <td>${escapeHtml(item.finding || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function cipherNameFromFinding(value) {
      const parts = String(value || '').trim().split(/\\s+/);
      return parts.length >= 3 ? parts[2] : value;
    }

    function severityChip(severity) {
      const normalized = String(severity || '').toUpperCase();
      const tone = normalized === 'OK' ? 'good' : normalized === 'INFO' ? 'info' : normalized === 'LOW' ? 'warn' : 'bad';
      return `<span class="chip ${tone}">${escapeHtml(normalized || 'INFO')}</span>`;
    }

    function kv(items) {
      return '<dl class="kv">' + items.map(([key, value]) => `
        <dt>${escapeHtml(key)}</dt>
        <dd>${escapeHtml(value === undefined || value === null || value === '' ? 'нет данных' : String(value))}</dd>
      `).join('') + '</dl>';
    }

    function chip(text, tone) {
      return `<span class="chip ${escapeHtml(tone || '')}">${escapeHtml(text)}</span>`;
    }

    function russianChipText(data) {
      const status = data?.status || '';
      if (status === 'not_checked') return 'РФ/ГОСТ: нет данных';
      if (status === 'data_error') return 'РФ/ГОСТ: ошибка данных';
      if (status === 'gost_and_russian_ca') return 'РФ/ГОСТ: найдено';
      if (status === 'gost_detected') return 'ГОСТ: найден';
      if (status === 'russian_ca_detected') return 'УЦ РФ: найден';
      if (status === 'trust_list_stale') return 'УЦ РФ: обновить список';
      if (status === 'not_detected') return 'РФ/ГОСТ: не найдено';
      return 'РФ/ГОСТ: проверено';
    }

    function russianChipTone(data) {
      const status = data?.status || '';
      if (status === 'data_error') return 'bad';
      if (status === 'trust_list_stale' || status === 'gost_detected' || status === 'gost_and_russian_ca') return 'warn';
      if (status === 'russian_ca_detected') return 'good';
      return 'info';
    }

    function gradeClass(grade) {
      grade = displayGrade(grade);
      if (grade === 'A+' || grade === 'A') return 'grade-a';
      if (grade === 'B') return 'grade-b';
      if (grade === 'C') return 'grade-c';
      if (grade === 'D') return 'grade-d';
      return 'grade-d';
    }

    function displayGrade(grade) {
      if (['A+', 'A', 'B', 'C', 'D'].includes(grade)) return grade;
      return 'D';
    }

    function displayScore(grade, score) {
      const normalizedGrade = displayGrade(grade);
      const numericScore = Number(score || 0);
      if (normalizedGrade === 'D' && numericScore < 55) {
        return 'до 54 / 100';
      }
      return numericScore + ' / 100';
    }

    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }

    function showError(message) {
      errorBox.textContent = message;
      errorBox.classList.remove('hidden');
      progress.classList.add('hidden');
      if (!reportBox.innerHTML) empty.classList.remove('hidden');
    }

    function clearError() {
      errorBox.classList.add('hidden');
      errorBox.textContent = '';
    }

    function delay(ms) {
      return new Promise((resolve) => setTimeout(resolve, ms));
    }
  </script>
</body>
</html>""".replace("{CONTACT_LINK}", CONTACT_LINK)
