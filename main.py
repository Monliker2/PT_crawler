import requests
from bs4 import BeautifulSoup
import logging
import time
from urllib.parse import urljoin, urlparse
from collections import deque
import sys

# Настройка логгера
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def is_file_link(response, url):
    """
    Определяет, является ли ссылка ссылкой на файл
    по заголовкам ответа и расширению URL.
    """
    #TODO Дополнить whitelist легитимными Content types
    WHITELIST_NOT_FILES_CONTENT_TYPES = {
        'application/xml',
        'application/xhtml+xml',
        'application/javascript',
        'application/json',
        'image/x-icon',  # favicon.ico
        'text/css',
        'text/javascript',
        'text/xml',
        'text/plain',  # иногда текстовые ресурсы
        'text/html',
        # добавь свои типы, которые НЕ считаешь файлами
    }


    cd = response.headers.get('Content-Disposition', '')
    if 'attachment' in cd.lower():
        return True

    content_type = response.headers.get('Content-Type', '')

    if any(content_type.startswith(t) for t in WHITELIST_NOT_FILES_CONTENT_TYPES):
        return False

    logger.debug(f'Content type: {content_type}')
    logger.debug(f'Headers: {response.headers}')

    if content_type and not content_type.startswith('video/'):
        return True

    path = urlparse(url).path
    if '.' in path.split('/')[-1]:  # есть расширение
        return True

    return False

def scan(start_url, timeout=30):
    """
    Основная функция сканирования сайта. Обходит сайт в ширину
    и ищет первую найденную ссылку на файл.
    """
    visited = set()
    queue = deque([start_url])
    start_time = time.time()

    while queue:
        if time.time() - start_time > timeout:
            logger.info('Время работы превысило лимит 30 секунд. Завершение сканирования.')
            break

        url = queue.popleft()
        if url in visited:
            continue

        logger.info(f'Обработка URL: {url}')
        try:
            response = requests.get(url, timeout=10, stream=True)
        except Exception as e:
            logger.warning(f'Ошибка запроса к {url}: {e}')
            visited.add(url)
            continue

        if is_file_link(response, url):
            logger.info(f'Найдена ссылка на файл: {url}')
            break

        if 'text/html' in response.headers.get('Content-Type', ''):
            soup = BeautifulSoup(response.text, 'html.parser')

            # Парсим ссылки в a, link, button
            for tag in soup.find_all(['a', 'link', 'button']):
                href = None

                # 1. Ссылка в href (a, link)
                if tag.name in ['a', 'link'] and tag.has_attr('href'):
                    href = tag['href'].strip()

                # 2. Ссылка в onclick="location.href='/file.pdf'"
                elif tag.has_attr('onclick'):
                    import re
                    onclick = tag['onclick']
                    match = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", onclick)
                    if match:
                        href = match.group(1)

                # 3. Ссылка в data-url
                elif tag.has_attr('data-url'):
                    href = tag['data-url'].strip()

                if not href:
                    continue

                abs_url = urljoin(url, href)

                # Пропускаем .html и .php
                path = urlparse(abs_url).path.lower()
                if path.endswith('.html') or path.endswith('.php'):
                    continue

                # Пропускаем внешние ссылки
                start_domain = urlparse(start_url).netloc
                abs_domain = urlparse(abs_url).netloc
                if start_domain != abs_domain:
                    continue

                if abs_url not in visited:
                    queue.append(abs_url)

            # --- Добавляем поиск ссылок внутри JS-функции downloadFile() ---
            import re
            scripts = soup.find_all('script')
            for s in scripts:
                script_text = s.string
                if script_text  and 'href' in script_text:
                    # Ищем присвоение href в JS
                    match = re.search(r"href\s*=\s*['\"]([^'\"]+)['\"]", script_text)
                    if match:
                        file_url = match.group(1)
                        abs_url = urljoin(url, file_url)
                        logger.info(f'Извлечена ссылка из JS downloadFile(): {abs_url}')
                        if abs_url not in visited:
                            queue.append(abs_url)

        visited.add(url)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        logger.error("Использование: python script.py https://example.com/page")
        sys.exit(1)
    scan(sys.argv[1])