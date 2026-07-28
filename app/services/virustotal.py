import base64
import logging
import httpx
from time import time
from fastapi import HTTPException
from app.config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL

# Sistem Log Ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecurityScanner")

HEADERS = {
    "x-apikey": VIRUSTOTAL_API_KEY,
    "accept": "application/json"
}

# Basit In-Memory Cache (TTL: 1 Saat)
SCAN_CACHE = {}
CACHE_TTL = 3600  # saniye


def get_from_cache(key: str):
    if key in SCAN_CACHE:
        data, timestamp = SCAN_CACHE[key]
        if time() - timestamp < CACHE_TTL:
            logger.info(f"⚡ Önbellekten (Cache) yanıt dönüldü: {key}")
            return data
        else:
            del SCAN_CACHE[key]
    return None


def set_to_cache(key: str, data: dict):
    SCAN_CACHE[key] = (data, time())


async def scan_url_virustotal(url_to_scan: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        logger.error("VirusTotal API Key sistemde tanımlı değil!")
        raise HTTPException(status_code=500, detail="Servis geçici olarak hizmet veremiyor.")

    # Önbellek kontrolü
    cached_result = get_from_cache(url_to_scan)
    if cached_result:
        return cached_result

    url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
    endpoint = f"{VIRUSTOTAL_BASE_URL}/urls/{url_id}"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(endpoint, headers=HEADERS)
            if response.status_code == 200:
                attr = response.json()["data"]["attributes"]
                stats = attr["last_analysis_stats"]
                results = attr.get("last_analysis_results", {})

                parsed = parse_vt_stats(stats, results)
                set_to_cache(url_to_scan, parsed)
                return parsed
            else:
                return parse_default_clean()
        except Exception as e:
            logger.error(f"VirusTotal URL sorgu hatası: {str(e)}")
            return parse_default_clean()


async def scan_file_hash_virustotal(file_hash: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        logger.error("VirusTotal API Key sistemde tanımlı değil!")
        raise HTTPException(status_code=500, detail="Servis geçici olarak hizmet veremiyor.")

    cached_result = get_from_cache(file_hash)
    if cached_result:
        return cached_result

    endpoint = f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(endpoint, headers=HEADERS)
            if response.status_code == 200:
                attr = response.json()["data"]["attributes"]
                stats = attr["last_analysis_stats"]
                results = attr.get("last_analysis_results", {})

                parsed = parse_vt_stats(stats, results)
                set_to_cache(file_hash, parsed)
                return parsed
            else:
                return parse_default_unknown()
        except Exception as e:
            logger.error(f"VirusTotal Dosya Sorgu Hatası: {str(e)}")
            return parse_default_unknown()


def parse_vt_stats(stats: dict, results: dict) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    # Motor detaylarını süzme (Örn: Kaspersky: malicious)
    engine_details = {}
    for engine, detail in results.items():
        category = detail.get("category", "undetected")
        if category in ["malicious", "suspicious"]:
            engine_details[engine] = category

    if malicious > 0:
        verdict = "DANGEROUS"
    elif suspicious > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "status": verdict,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless_count": harmless,
        "undetected_count": undetected,
        "total_scanners": malicious + suspicious + harmless + undetected,
        "engine_details": engine_details
    }


def parse_default_clean():
    return {"status": "CLEAN", "malicious_count": 0, "suspicious_count": 0, "harmless_count": 1, "undetected_count": 0,
            "total_scanners": 1, "engine_details": {}}


def parse_default_unknown():
    return {"status": "UNKNOWN", "malicious_count": 0, "suspicious_count": 0, "harmless_count": 0,
            "undetected_count": 0, "total_scanners": 0, "engine_details": {}}