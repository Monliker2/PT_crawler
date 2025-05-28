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
    cd = response.headers.get('Content-Disposition', '')
    if 'attachment' in cd.lower():
        return True

    content_type = response.headers.get('Content-Type', '')

    logger.debug(f'Content type: {content_type}')

    if content_type and not content_type.startswith('text/html') and not content_type.startswith('video/'):
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
            for link in soup.find_all(['a', 'link'], href=True):
                href = link['href'].strip()
                abs_url = urljoin(url, href)

                # Пропускаем ссылки с расширениями .html и .php
                path = urlparse(abs_url).path.lower()
                if path.endswith('.html') or path.endswith('.php'):
                    continue

                # Игнорируем внешние ссылки
                start_domain = urlparse(start_url).netloc
                abs_domain = urlparse(abs_url).netloc
                if start_domain != abs_domain:
                    continue

                if abs_url not in visited:
                    queue.append(abs_url)

        visited.add(url)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        logger.error("Использование: python script.py https://example.com/page")
        sys.exit(1)
    scan(sys.argv[1])