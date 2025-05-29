import requests
import logging
import time
from dotenv import load_dotenv
from os import getenv
import base64

load_dotenv()
API_KEY =  getenv('VIRUS_TOTAL_API')

logger = logging.getLogger(__name__)

API_URL = 'https://www.virustotal.com/api/v3/urls'

def get_url_id(url: str) -> str:
    """Возвращает base64-закодированный ID URL для запроса к VT."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')

def get_scan_result_by_url(url: str) -> dict:
    """Отправляет URL и получает результат анализа с VirusTotal."""
    logger.debug(f'Отправка URL в VirusTotal: {url}')
    # Сначала отправляем URL (если ранее не отправлялся)
    response = requests.post(
        API_URL,
        headers={
            "x-apikey": API_KEY,
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data=f"url={url}"
    )
    response.raise_for_status()

    url_id = get_url_id(url)
    logger.debug(f'Запрос результата по url_id: {url_id}')
    result_url = f'{API_URL}/{url_id}'

    # Пробуем получить результат
    for attempt in range(10):
        response = requests.get(
            result_url,
            headers={"x-apikey": API_KEY}
        )
        response.raise_for_status()
        result = response.json()
        if "last_analysis_stats" in result["data"]["attributes"]:
            return result["data"]["attributes"]
        time.sleep(1)

    return result["data"]["attributes"]

def get_scan_result(scan_id: str) -> dict:
    """Получает результат сканирования по scan_id."""
    logger.debug(f'Запрос результата по scan_id: {scan_id}')
    url = f'{API_URL}/{scan_id}'
    for attempt in range(10):  # 10 попыток, 1 секунда между ними
        response = requests.get(
            url,
            headers={"x-apikey": API_KEY}
        )
        response.raise_for_status()
        result = response.json()
        if result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            return result["data"]["attributes"]
        time.sleep(1)
    return result["data"]["attributes"]
