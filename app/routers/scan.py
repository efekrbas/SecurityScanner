from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.models.scanner import URLScanRequest, ScanResultResponse
from app.services.virustotal import scan_url_virustotal, scan_file_hash_virustotal
from app.services.hasher import calculate_file_hash_async

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/api/scan", tags=["Scanner"])


@router.post("/url", response_model=ScanResultResponse)
@limiter.limit("10/minute")
async def scan_url(request: Request, payload: URLScanRequest):
    result = await scan_url_virustotal(payload.url)
    return ScanResultResponse(
        target=payload.url,
        scan_type="URL",
        status=result.get("status", "CLEAN"),
        malicious_count=result.get("malicious_count", 0),
        suspicious_count=result.get("suspicious_count", 0),
        harmless_count=result.get("harmless_count", 1),
        total_scanners=result.get("total_scanners", 1),
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