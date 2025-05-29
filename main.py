import requests
from bs4 import BeautifulSoup
import logging
import time
from urllib.parse import urljoin, urlparse, urlunparse
from collections import deque
import sys
import re
from virustotal_api import get_scan_result_by_url

# Настройка логгера
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
START_TIME = 0
TIMEOUT = 0

# ---- Функции для обработки URL ----

def get_parent_url(url: str) -> str:
    check_time()
    """Возвращает URL родительской папки (на уровень выше)."""
    parsed = urlparse(url)
    path_parts = parsed.path.rstrip('/').split('/')
    if len(path_parts) <= 1:
        return None
    parent_path = '/'.join(path_parts[:-1]) or '/'
    return urlunparse(parsed._replace(path=parent_path))


def is_file_link(response, url, strict=True) -> bool:
    """Определяет, является ли ссылка ссылкой на файл."""
    cd = response.headers.get('Content-Disposition', '')
    if 'attachment' in cd.lower():
        return True

    content_type = response.headers.get('Content-Type', '')

    if strict:
        # Применяем whitelist только в строгом режиме
        WHITELIST_NOT_FILES_CONTENT_TYPES = {
            'application/xml', 'application/xhtml+xml', 'application/javascript',
            'application/json', 'image/x-icon', 'text/css', 'text/javascript',
            'text/xml', 'text/plain', 'text/html', 'image/svg+xml', 'image/png',
            'image/jpeg', 'application/rss+xml', 'application/atom+xml', 'application/x-web-app-manifest+json'
        }

        WHITELIST_NOT_FILES_EXTENSIONS = {
            '.ico', '.xml', '.json', '.js', '.css', '.txt', '.svg', '.png', '.webmanifest'
        }

        if any(content_type.startswith(t) for t in WHITELIST_NOT_FILES_CONTENT_TYPES):
            return False

        path = urlparse(url).path
        filename = path.split('/')[-1]
        if '.' in filename:
            ext = '.' + filename.split('.')[-1].lower()
            if ext in WHITELIST_NOT_FILES_EXTENSIONS:
                return False
            return True

    # Если strict=False — игнорируем whitelist
    if content_type and not content_type.startswith('text/html') and not content_type.startswith('video/'):
        return True

    return False


def parse_html_for_links(soup, base_url: str, visited: set, start_url: str, queue: deque) -> None:
    check_time()
    for tag in soup.find_all(['a', 'link', 'button']):
        href = extract_href_from_tag(tag)
        if not href:
            continue

        abs_url = urljoin(base_url, href)

        if is_internal_link(start_url, abs_url) and abs_url not in visited:
            try:
                r = requests.get(abs_url, timeout=10, stream=True)

                # Определяем strict=True только для <link>
                strict_mode = tag.name == 'link'

                if is_file_link(r, abs_url, strict=strict_mode):
                    logger.info(f'Найдена ссылка на файл: {abs_url}')
                    if use_virustotal:
                        check_with_virustotal(abs_url)
                        break
                    else:
                        sys.exit()
                    break
            except Exception as e:
                logger.warning(f'Ошибка запроса к {abs_url}: {e}')
                continue
            queue.append(abs_url)



def extract_href_from_tag(tag) -> str:
    """Извлекает href из тега a, link, button, включая обработку onclick и data-url."""
    check_time()
    href = None
    if tag.name in ['a', 'link'] and tag.has_attr('href'):
        href = tag['href'].strip()
    elif tag.has_attr('onclick'):
        onclick = tag['onclick']
        match = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", onclick)
        if match:
            href = match.group(1)
    elif tag.has_attr('data-url'):
        href = tag['data-url'].strip()

    return href


def is_internal_link(start_url: str, abs_url: str) -> bool:
    """Проверяет, является ли ссылка внутренней (тот же домен)."""
    check_time()
    start_domain = urlparse(start_url).netloc
    abs_domain = urlparse(abs_url).netloc
    return start_domain == abs_domain


def parse_js_for_links(soup, base_url: str, visited: set, queue: deque) -> None:
    """Извлекает ссылки из JS-скриптов."""
    check_time()
    scripts = soup.find_all('script')
    for s in scripts:
        script_text = s.string
        if script_text and 'href' in script_text:
            match = re.search(r"href\s*=\s*['\"]([^'\"]+)['\"]", script_text)
            if match:
                file_url = match.group(1)
                abs_url = urljoin(base_url, file_url)
                logger.info(f'Извлечена ссылка из JS: {abs_url}')
                r = requests.get(abs_url, timeout=10, stream=True)
                if abs_url not in visited:
                    if is_file_link(r, abs_url, strict=False):
                        logger.info(f'Найдена ссылка на файл: {abs_url}')
                        if use_virustotal:
                            check_with_virustotal(abs_url)
                        else:
                            sys.exit()
                        break

def check_time():
    """Проверяет, не превышено ли время выполнения скрипта."""
    global TIMEOUT
    global START_TIME


    logger.debug(f'Скан идет {round(time.time() - START_TIME, 2)} секунд')
    if time.time() - START_TIME > TIMEOUT > 0:
        logger.info(f'Время работы превысило лимит {TIMEOUT} секунд. Завершение сканирования.')
        sys.exit()

# ---- Основная функция обхода ----

def scan(start_url, use_virustotal=False):
    """Основная функция сканирования сайта."""
    global START_TIME
    visited = set()
    queue = deque([start_url])
    START_TIME = time.time()

    while queue or start_url:
        check_time()

        if not queue:
            # Очередь пуста — пытаемся подняться на уровень выше
            parent_url = get_parent_url(start_url)
            if parent_url is None or parent_url in visited:
                logger.info('No more parents to go up, stopping.')
                break
            logger.info(f'Queue empty, moving up to parent URL: {parent_url}')
            queue.append(parent_url)
            start_url = parent_url
            continue

        url = queue.popleft()
        if url in visited:
            continue

        logger.info(f'Обработка URL: {url}')
        try:
            response = requests.get(url, timeout=10, stream=True)
            if response.status_code == 304:
                continue
        except Exception as e:
            logger.warning(f'Ошибка запроса к {url}: {e}')
            visited.add(url)
            continue

        if is_file_link(response, url):
            logger.info(f'Найдена ссылка на файл: {url}')
            if use_virustotal:
                check_with_virustotal(url)
            else:
                sys.exit()
            break

        if 'text/html' in response.headers.get('Content-Type', ''):
            soup = BeautifulSoup(response.text, 'html.parser')

            # Парсим ссылки в HTML
            parse_html_for_links(soup, url, visited, start_url, queue)

            # Извлекаем ссылки из JS
            parse_js_for_links(soup, url, visited, queue)

        visited.add(url)


def check_with_virustotal(url: str) -> None:
    """Проверяет файл с помощью VirusTotal."""
    logger.info(f"Запуск VirusTotal проверки для: {url}")
    try:
        result = get_scan_result_by_url(url)
        logger.info(f"VirusTotal результат для {url}:\n"
                    f"Malicious: {result['last_analysis_stats']['malicious']}, "
                    f"Suspicious: {result['last_analysis_stats']['suspicious']}, "
                    f"Undetected: {result['last_analysis_stats']['undetected']}")
        sys.exit()
    except Exception as e:
        logger.error(f"Ошибка при проверке VirusTotal: {e}")

# ---- Запуск скрипта ----

if __name__ == '__main__':
    if len(sys.argv) < 2:
        logger.error("Использование: python main.py <URL> [таймаут] [--vt]")
        sys.exit(1)

    start_url = sys.argv[1]
    TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 30

    if '--vt' in sys.argv or '--virustotal' in sys.argv:
        use_virustotal = True
    else:
        use_virustotal = False

    scan(start_url, use_virustotal=use_virustotal)