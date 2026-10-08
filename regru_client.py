"""Модуль клиента для работы со страницей освобождающихся доменов REG.RU."""

import http.cookiejar
import json
import re
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple


def calculate_jhash(code: int) -> int:
    """Вычисляет числовой хэш для обхода JS-проверки reg.ru (DDoS-Guard)."""
    x = 123456789
    k = 0
    for i in range(1677696):
        x = ((x + code) ^ (x + (x % 3) + (x % 17) + code) ^ i) % 16776960
        if x % 117 == 0:
            k = (k + 1) % 1111
    return k


def encode_user_agent(user_agent: str) -> str:
    """Кодирует User-Agent в соответствии с JS-логикой fixedEncodeURIComponent."""
    encoded = urllib.parse.quote(user_agent, safe="")
    for ch in ["!", "'", "(", ")", "*"]:
        encoded = encoded.replace(f"%{ord(ch):02X}", f"%{ord(ch):02x}")
    return encoded


DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

BASE_REREG_URL = "https://www.reg.ru/domain/new/rereg"


class RegRuClient:
    """Клиент для взаимодействия со страницей освобождающихся доменов reg.ru."""

    def __init__(self, user_agent: str = DEFAULT_UA, request_delay: float = 3.0):
        self.user_agent = user_agent
        self.request_delay = request_delay
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        self.opener.addheaders = [
            ("User-Agent", self.user_agent),
            (
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
            ("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"),
        ]
        self.authenticated = False

    def solve_challenge(self) -> None:
        """Решает JS-challenge защиты reg.ru и сохраняет куки сессии."""
        req = urllib.request.Request(BASE_REREG_URL)
        resp = self.opener.open(req)
        set_cookie = resp.headers.get("Set-Cookie") or ""

        # Проверяем, есть ли кука __js_p_
        m = re.search(r"__js_p_=([0-9,]+)", set_cookie)
        if not m:
            # Возможно, проверка уже пройдена или не требуется
            self.authenticated = True
            return

        val = m.group(1)
        code = int(val.split(",")[0])
        jhash = calculate_jhash(code)
        jua = encode_user_agent(self.user_agent)

        # Устанавливаем куки __jhash_ и __jua_
        cookie_jhash = http.cookiejar.Cookie(
            0, "__jhash_", str(jhash), None, False,
            "www.reg.ru", True, False, "/", True, False, None, False, None, None, {}
        )
        cookie_jua = http.cookiejar.Cookie(
            0, "__jua_", jua, None, False,
            "www.reg.ru", True, False, "/", True, False, None, False, None, None, {}
        )
        self.cookie_jar.set_cookie(cookie_jhash)
        self.cookie_jar.set_cookie(cookie_jua)

        # Выполняем запрос для получения куки __hash_
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                return fp

        redirect_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
            NoRedirectHandler
        )
        redirect_opener.addheaders = self.opener.addheaders
        req2 = urllib.request.Request(BASE_REREG_URL)
        resp2 = redirect_opener.open(req2)

        set_cookie2 = resp2.headers.get("Set-Cookie") or ""
        m2 = re.search(r"__hash_=([^;]+)", set_cookie2)
        if m2:
            cookie_hash = http.cookiejar.Cookie(
                0, "__hash_", m2.group(1), None, False,
                "reg.ru", True, False, "/", True, False, None, False, None, None, {}
            )
            self.cookie_jar.set_cookie(cookie_hash)

        self.authenticated = True

    def _fetch_html_with_retry(self, url: str, max_retries: int = 3) -> str:
        """Загружает страницу с автоматическим повтором при превышении лимита."""
        last_error = ""
        for attempt in range(1, max_retries + 1):
            try:
                req = urllib.request.Request(url)
                resp = self.opener.open(req)
                html = resp.read().decode("utf-8", errors="ignore")

                # Проверка на превышение лимита запросов
                if "Превышение допустимого лимита обращений" in html:
                    backoff = self.request_delay * (attempt + 1)
                    time.sleep(backoff)
                    continue

                return html
            except Exception as e:
                last_error = str(e)
                time.sleep(self.request_delay * attempt)

        raise RuntimeError(
            f"Не удалось загрузить страницу {url} после {max_retries} попыток. "
            f"Последняя ошибка: {last_error or 'Превышение лимита обращений'}"
        )

    def extract_domains_from_html(self, html: str) -> List[Dict]:
        """Извлекает список доменов и их атрибутов из встроенного window.pDomainRereg."""
        m = re.search(r"window\.pDomainRereg\s*=\s*(\{[\s\S]*?\});\s*</script>", html)
        if not m:
            return []

        try:
            data = json.loads(m.group(1))
        except json.JSONDecodeError:
            return []

        raw_list = data.get("domainsArray", [])
        domains = []
        for item in raw_list:
            dataset = item.get("datasetTable", {})
            domain_info = {
                "name": item.get("name", "").strip(),
                "release_date": dataset.get("releaseDate", "").strip(),
                "min_price": item.get("minPrice", "").strip(),
                "max_price": item.get("maxPrice", "").strip(),
                "domain_age": dataset.get("domainAge", "").strip(),
                "current_bid": dataset.get("currentBid", "").strip(),
                "first_registration": dataset.get("firstRegistration", "").strip(),
            }
            if domain_info["name"]:
                domains.append(domain_info)

        return domains

    def extract_max_page(self, html: str) -> int:
        """Извлекает максимальный номер страницы pg из элементов пагинации."""
        pg_numbers = [int(p) for p in re.findall(r"[\?&]pg=(\d+)", html)]
        return max(pg_numbers) if pg_numbers else 0

    def init_filter(self, target_date_iso: str) -> Tuple[List[Dict], int]:
        """Инициализирует фильтр по дате (YYYY-MM-DD), возвращает (первая_страница, max_pg)."""
        if not self.authenticated:
            self.solve_challenge()

        url = (
            f"{BASE_REREG_URL}"
            f"?filter_expiring_from={target_date_iso}"
            f"&filter_expiring_to={target_date_iso}"
        )
        html = self._fetch_html_with_retry(url)
        domains = self.extract_domains_from_html(html)
        max_pg = self.extract_max_page(html)
        return domains, max_pg

    def fetch_page(self, page_index: int) -> List[Dict]:
        """Загружает страницу с индексом page_index (1..max_pg)."""
        time.sleep(self.request_delay)
        url = f"{BASE_REREG_URL}?pg={page_index}"
        html = self._fetch_html_with_retry(url)
        return self.extract_domains_from_html(html)
