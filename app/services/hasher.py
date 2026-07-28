import hashlib
from fastapi import UploadFile


async def calculate_file_hash_async(file: UploadFile) -> str:
    """Büyük dosyaları parçalar halinde (Chunk) okuyarak RAM kullanımını optimize eder."""
    sha256_hash = hashlib.sha256()

    # Dosya imlecini başa alalım
    await file.seek(0)

    # 64 KB'lık parçalar halinde okuyoruz
    chunk_size = 64 * 1024
    while chunk := await file.read(chunk_size):
        sha256_hash.update(chunk)

    # İşlem bittiğinde imleci tekrar başa alalım
    await file.seek(0)
    return sha256_hash.hexdigest()