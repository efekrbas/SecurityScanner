from pydantic import BaseModel, HttpUrl, field_validator
import re

class URLScanRequest(BaseModel):
    url: str

    @field_validator('url')
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        v = v.strip()
        # Basit URL regex doğrulaması (Protokol opsiyonel)
        url_regex = re.compile(
            r'^(?:(?:http|ftp)s?://)?' # opsiyonel http:// veya https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
            r'localhost|' # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...veya ip
            r'(?::\d+)?' # opsiyonel port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if not re.match(url_regex, v):
            raise ValueError('Geçersiz URL formatı girildi.')
        return v

class ScanResultResponse(BaseModel):
    target: str
    scan_type: str        # 'URL' veya 'FILE'
    status: str           # 'CLEAN', 'SUSPICIOUS', 'DANGEROUS', 'UNKNOWN'
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    total_scanners: int
    resolved_ip: str | None = None
    engine_details: dict = {}  # Motor detaylarını ekrana basmak için (Örn: {"Kaspersky": "malicious"})