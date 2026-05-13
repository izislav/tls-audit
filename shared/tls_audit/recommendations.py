from .report import Recommendation


TLS12_13_ONLY = Recommendation(
    code="tls_modern_protocols",
    title="Оставить только TLS 1.2 и TLS 1.3",
    risk="TLS 1.0/1.1 устарели и не должны использоваться в современной публичной конфигурации.",
    fix="Отключите TLS 1.0 и TLS 1.1. Оставьте TLS 1.2 и TLS 1.3.",
    nginx="ssl_protocols TLSv1.2 TLSv1.3;",
    apache="SSLProtocol -all +TLSv1.2 +TLSv1.3",
    iis="Отключите TLS 1.0/1.1 через SCHANNEL registry policy или Group Policy.",
)

ENABLE_HSTS = Recommendation(
    code="enable_hsts",
    title="Включить HSTS",
    risk="Без HSTS браузер может выполнить первый запрос по HTTP или принять downgrade-сценарий.",
    fix="После проверки всего сайта включите Strict-Transport-Security.",
    nginx='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
    apache='Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
    iis="Добавьте Strict-Transport-Security через HTTP Response Headers.",
)

HSTS_PRELOAD_OPTIONAL = Recommendation(
    code="hsts_preload_optional",
    title="HSTS preload включать только осознанно",
    risk="Отсутствие preload не является критической TLS-уязвимостью. Preload жестко закрепляет HTTPS в браузерах и может сломать поддомены, если они не готовы.",
    fix="Добавляйте preload только после аудита всех поддоменов, долгого max-age и проверки заявки в preload list.",
    nginx='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    apache='Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    iis="Добавляйте директиву preload в Strict-Transport-Security только после проверки всех зависимых хостов.",
)

FULLCHAIN_CERT = Recommendation(
    code="fullchain_certificate",
    title="Отдавать полный chain сертификатов",
    risk="Если intermediate certificate отсутствует, часть клиентов не сможет построить цепочку доверия.",
    fix="Установите leaf certificate вместе с intermediate certificates.",
    nginx="ssl_certificate /etc/letsencrypt/live/example.ru/fullchain.pem;",
    apache="SSLCertificateFile /etc/letsencrypt/live/example.ru/fullchain.pem",
)

SECURE_CIPHERS = Recommendation(
    code="secure_cipher_suites",
    title="Отключить слабые cipher suites",
    risk="RC4, 3DES, NULL, EXPORT, anonymous и CBC-only наборы снижают безопасность соединения.",
    fix="Оставьте AEAD suites: AES-GCM и CHACHA20-POLY1305 с forward secrecy.",
    nginx=(
        "ssl_ciphers "
        "'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';"
    ),
    apache=(
        "SSLCipherSuite "
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
    ),
)

BREACH_FIX = Recommendation(
    code="breach_http_compression",
    title="Снизить риск BREACH",
    risk="BREACH связан с HTTP compression: если страница с секретами сжимается gzip/brotli и отражает пользовательский ввод, секрет можно подбирать по размеру ответа.",
    fix="Не сжимайте ответы, где есть CSRF-токены, персональные данные или отраженный пользовательский ввод. Оставьте compression только для статических файлов.",
    nginx=(
        "gzip on;\n"
        "gzip_types text/css application/javascript image/svg+xml;\n"
        "location /account/ { gzip off; }"
    ),
    apache=(
        "SetEnvIfNoCase Request_URI \"^/(account|profile|admin)/\" no-gzip=1\n"
        "AddOutputFilterByType DEFLATE text/css application/javascript image/svg+xml"
    ),
    iis="Отключите dynamic compression для страниц с токенами и персональными данными.",
)

LUCKY13_FIX = Recommendation(
    code="lucky13_cbc_ciphers",
    title="Убрать CBC cipher suites",
    risk="LUCKY13 относится к атакам на CBC suites. Современная публичная конфигурация должна предпочитать AEAD: AES-GCM или CHACHA20-POLY1305.",
    fix="Отключите CBC suites и оставьте ECDHE + AEAD. Если нужны старые клиенты, вынесите их в отдельный совместимый профиль.",
    nginx=SECURE_CIPHERS.nginx,
    apache=SECURE_CIPHERS.apache,
)

OCSP_STAPLING_FIX = Recommendation(
    code="enable_ocsp_stapling",
    title="Включить OCSP stapling",
    risk="Без OCSP stapling браузер сам обращается к OCSP responder или работает без свежего статуса отзыва, что медленнее и менее надежно.",
    fix="Включите stapling и проверьте, что сервер может резолвить OCSP responder и отдаёт полный chain.",
    nginx=(
        "ssl_stapling on;\n"
        "ssl_stapling_verify on;\n"
        "resolver 1.1.1.1 8.8.8.8 valid=300s;"
    ),
    apache=(
        "SSLUseStapling on\n"
        "SSLStaplingCache shmcb:/var/run/ocsp(128000)"
    ),
    iis="OCSP stapling в IIS включается на уровне SChannel/сертификата; проверьте chain и доступность OCSP URL.",
)

CSP_HEADER = Recommendation(
    code="content_security_policy",
    title="Добавить Content-Security-Policy",
    risk="CSP не исправляет TLS, но снижает ущерб от XSS и внедрения стороннего контента.",
    fix="Начните с Content-Security-Policy-Report-Only, соберите нарушения и затем включите рабочую политику.",
    nginx='add_header Content-Security-Policy "default-src \'self\'; object-src \'none\'; base-uri \'self\'" always;',
    apache='Header always set Content-Security-Policy "default-src \'self\'; object-src \'none\'; base-uri \'self\'"',
    iis="Добавьте Content-Security-Policy через HTTP Response Headers.",
)

X_CONTENT_TYPE_OPTIONS = Recommendation(
    code="x_content_type_options",
    title="Добавить X-Content-Type-Options",
    risk="Без nosniff браузер может попытаться определить тип ответа не по Content-Type.",
    fix="Добавьте заголовок X-Content-Type-Options: nosniff ко всем HTTPS-ответам.",
    nginx='add_header X-Content-Type-Options "nosniff" always;',
    apache='Header always set X-Content-Type-Options "nosniff"',
    iis="Добавьте X-Content-Type-Options: nosniff через HTTP Response Headers.",
)

CERTIFICATE_RENEWAL = Recommendation(
    code="certificate_renewal",
    title="Перевыпустить или продлить сертификат",
    risk="Истекший или почти истекший сертификат ломает доверие браузеров и API-клиентов.",
    fix="Перевыпустите сертификат и настройте автоматическое продление с проверкой после reload web-сервера.",
    nginx="nginx -t && systemctl reload nginx",
    apache="apachectl configtest && systemctl reload apache2",
)

CERTIFICATE_MODERN = Recommendation(
    code="certificate_modern",
    title="Использовать современный сертификат",
    risk="Слабая подпись, маленький ключ или отсутствие SAN ухудшают совместимость и доверие клиентов.",
    fix="Выпустите сертификат с SAN, SHA-256+ и ключом RSA 2048/3072+ или ECDSA P-256/P-384.",
)

TLS_ENDPOINT = Recommendation(
    code="tls_endpoint_available",
    title="Проверить доступность HTTPS",
    risk="Если TLS-handshake не проходит, браузеры и API не смогут безопасно подключиться к сайту.",
    fix="Проверьте DNS, firewall, порт 443, сертификат и включенные TLS 1.2/TLS 1.3 на web-сервере.",
)

VULNERABILITY_FIX = Recommendation(
    code="tls_vulnerability_fix",
    title="Исправить TLS-уязвимость",
    risk="Обнаруженная уязвимость может снижать защиту TLS-соединения или раскрывать дополнительные риски конфигурации.",
    fix="Обновите web-сервер/OpenSSL и отключите затронутую функцию или протокол согласно конкретной находке.",
)
