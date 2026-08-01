from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.models.scanner import URLScanRequest, ScanResultResponse
from app.services.virustotal import scan_url_virustotal, scan_file_hash_virustotal
from app.services.hasher import calculate_file_hash_async
import socket
import asyncio
from urllib.parse import urlparse
import ipaddress

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/api/scan", tags=["Scanner"])


@router.post("/url", response_model=ScanResultResponse)
@limiter.limit("10/minute")
async def scan_url(request: Request, payload: URLScanRequest):
    # Kullanıcı arayüzünde tam olarak kullanıcının yazdığı halini göstermek için orijinali saklıyoruz
    display_target = payload.url
    
    # VirusTotal API bir "URL" beklediği için arka planda (kullanıcıya çaktırmadan) HTTP protokolü ekliyoruz.
    # Güvenlik (OPSEC) gereği sunucumuzdan hedef siteye test isteği (ping) ATMIYORUZ.
    vt_scan_url = display_target
    if not vt_scan_url.startswith(('http://', 'https://')):
        vt_scan_url = f"http://{vt_scan_url}"

    result = await scan_url_virustotal(vt_scan_url)

    # DNS Çözümleme (IP -> Domain veya Domain -> IP)
    resolved_info = None
    try:
        parsed_url = urlparse(vt_scan_url)
        hostname = parsed_url.hostname or display_target
        hostname = hostname.split(':')[0] # portu temizle
        
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        loop = asyncio.get_event_loop()
        if is_ip:
            try:
                domain_name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, hostname)
                resolved_info = f"Domain: {domain_name}"
            except Exception:
                pass
        else:
            try:
                _, _, ip_addrs = await loop.run_in_executor(None, socket.gethostbyname_ex, hostname)
                if len(ip_addrs) > 1:
                    resolved_info = f"IP Adresleri: {', '.join(ip_addrs)}"
                else:
                    resolved_info = f"IP: {ip_addrs[0]}"
            except Exception:
                pass
    except Exception:
        pass

    return ScanResultResponse(
        target=display_target,  # Ekrana basılacak olan (örn: efekrbs.com.tr)
        scan_type="URL",
        status=result.get("status", "CLEAN"),
        malicious_count=result.get("malicious_count", 0),
        suspicious_count=result.get("suspicious_count", 0),
        harmless_count=result.get("harmless_count", 1),
        total_scanners=result.get("total_scanners", 1),
        resolved_ip=resolved_info,
        engine_details=result.get("engine_details", {})
    )


@router.post("/file", response_model=ScanResultResponse)
@limiter.limit("10/minute")
async def scan_file(request: Request, file: UploadFile = File(...)):
    # Asenkron ve parçalı hash hesaplama
    file_hash = await calculate_file_hash_async(file)

    result = await scan_file_hash_virustotal(file_hash)
    return ScanResultResponse(
        target=f"{file.filename} (SHA256: {file_hash[:10]}...)",
        scan_type="FILE",
        status=result.get("status", "UNKNOWN"),
        malicious_count=result.get("malicious_count", 0),
        suspicious_count=result.get("suspicious_count", 0),
        harmless_count=result.get("harmless_count", 0),
        total_scanners=result.get("total_scanners", 0),
        engine_details=result.get("engine_details", {})
    )