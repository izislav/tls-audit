import unittest

from services.api.app.frontend import (
    CONTACT_EMAIL,
    STATIC_PAGES,
    render_frontend,
    render_static_page,
)


class FrontendPagesTests(unittest.TestCase):
    def test_main_page_links_to_public_documents(self):
        html = render_frontend()

        self.assertIn('href="/privacy"', html)
        self.assertIn('href="/terms"', html)
        self.assertIn('href="/cookies"', html)
        self.assertIn('href="/security"', html)
        self.assertIn('href="/ssl-certificate-check"', html)
        self.assertIn('href="/tls-versions-check"', html)
        self.assertIn('href="/hsts-check"', html)
        self.assertIn('href="/a-plus-grade"', html)
        self.assertIn('href="/nginx-tls-config"', html)
        self.assertIn('href="/apache-tls-config"', html)
        self.assertIn('href="/caddy-tls-config"', html)
        self.assertIn('href="/haproxy-tls-config"', html)
        self.assertIn('href="/methodology"', html)
        self.assertIn('href="/tls-audit-vs-ssl-labs"', html)
        self.assertIn('href="/methodology-changelog"', html)
        self.assertIn('href="/sample-reports"', html)
        self.assertIn('href="/faq"', html)
        self.assertIn("Политика данных", html)
        self.assertIn(f"mailto:{CONTACT_EMAIL}", html)
        self.assertIn("118 тестов", html)
        self.assertIn("Без регистрации", html)

    def test_static_pages_have_canonical_and_return_link(self):
        for page_key, page in STATIC_PAGES.items():
            with self.subTest(page=page_key):
                html = render_static_page(page_key)

                self.assertIn(f'<link rel="canonical" href="https://tlsaudit.ru{page["path"]}">', html)
                self.assertIn('"@type":"TechArticle"', html)
                self.assertIn('<a class="back" href="/">Вернуться к проверке</a>', html)
                self.assertIn(page["title"], html)

    def test_cookie_page_says_no_optional_cookies(self):
        html = render_static_page("cookies")

        self.assertIn("не устанавливает необязательные cookies", html)
        self.assertIn("Если позже будет подключена аналитика", html)

    def test_ssl_certificate_page_links_back_to_main_check(self):
        html = render_static_page("ssl-certificate-check")

        self.assertIn('<a class="back" href="/">Вернуться к проверке</a>', html)
        self.assertNotIn('class="inline-tool"', html)

    def test_policy_pages_use_working_contact_email(self):
        self.assertIn(CONTACT_EMAIL, render_static_page("privacy"))
        self.assertIn(CONTACT_EMAIL, render_static_page("security"))

    def test_seo_pages_have_search_intent_titles(self):
        cases = {
            "ssl-certificate-check": "Проверка SSL-сертификата онлайн",
            "tls-versions-check": "Проверка TLS 1.2 и TLS 1.3",
            "hsts-check": "Проверка HSTS и путь к A+",
            "nginx-tls-config": "TLS-конфиг для Nginx",
            "apache-tls-config": "TLS-конфиг для Apache",
            "a-plus-grade": "Как получить A+ за HTTPS/TLS",
            "caddy-tls-config": "TLS-конфиг для Caddy",
            "haproxy-tls-config": "TLS-конфиг для HAProxy",
            "methodology": "Методика проверки HTTPS/TLS",
            "tls-audit-vs-ssl-labs": "TLS Audit vs SSL Labs",
            "methodology-changelog": "Changelog методики TLS Audit",
            "sample-reports": "Примеры отчетов TLS Audit",
            "faq": "FAQ: проверка SSL и TLS",
        }

        for page_key, title in cases.items():
            with self.subTest(page=page_key):
                html = render_static_page(page_key)

                self.assertIn(title, html)
                self.assertIn("TLS Audit", html)

    def test_methodology_page_has_version_and_matrix(self):
        html = render_static_page("methodology")

        self.assertIn("Версия методики: 0.2", html)
        self.assertIn("Ключевые группы проверок", html)
        self.assertIn("Что не покрывается", html)
        self.assertIn("testssl.sh", html)

    def test_faq_page_has_search_intent_and_free_value(self):
        html = render_static_page("faq")

        self.assertIn("FAQ: проверка SSL и TLS", html)
        self.assertIn("проверку SSL/TLS", html)
        self.assertIn("Базовый weekly мониторинг", html)
        self.assertIn("TLS Audit не заявляет буквальную эквивалентность SSL Labs", html)


if __name__ == "__main__":
    unittest.main()
