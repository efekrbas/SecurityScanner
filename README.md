# 🛡️ SecurityScanner - Threat Intelligence & Security Analysis Portal

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-v3_API-3949AB?style=flat&logo=virustotal&logoColor=white)](https://www.virustotal.com/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-Dark_Mode-38B2AC?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)

**SecurityScanner**, şüpheli web bağlantılarını (URL) ve yerel dosyaları (SHA-256 hash imzaları üzerinden) 70'ten fazla antivirüs ve güvenlik motoru verisiyle asenkron olarak analiz eden siber güvenlik odaklı bir tehdit istihbarat portalıdır.

---

## 🚀 Öne Çıkan Özellikler (Key Features)

- 🔍 **Canlı URL Analizi:** Girilen bağlantıları VirusTotal v3 REST API altyapısı üzerinden sorgular ve güvenlik durumunu raporlar.
- 🧬 **SHA-256 Hash Tarama Motoru:** Yüklenen dosyaların kendisi yerine istemci/sunucu tarafında benzersiz `SHA-256` imzasını üreterek sorgulama yapar. Dosya yükleme riski barındırmaz.
- 📊 **Görsel Tehdit Dashboard'u:** Chart.js ve Tailwind CSS entegrasyonu ile tespit edilen zararlı (Malicious), şüpheli (Suspicious) ve temiz (Harmless) motor sayılarını dinamik pasta grafik ile görselleştirir.
- ⚡ **Asenkron Mimarisi (`httpx`):** Arka planda yüksek performanslı asenkron HTTP istekleri kullanarak sonuçları hızlıca derler.
- 🎨 **Siber Güvenlik Konseptli Arayüz:** Karanlık mod (Dark Mode) uyumlu modern arayüz tasarımı.

---

## 🛠️ Kullanılan Teknolojiler (Tech Stack)

* **Backend:** Python 3.10+, FastAPI, Pydantic, HTTPX (Async HTTP Client)
* **Güvenlik & Kriptografi:** Hashlib (SHA-256), VirusTotal v3 API Entegrasyonu
* **Frontend:** HTML5, Tailwind CSS, Chart.js, Lucide Icons, Jinja2
* **Konfigürasyon:** Python-Dotenv (`.env` güvenliği)

---

## 📁 Proje Klasör Mimarisi (Project Structure)

```text
SecurityScanner/
│
├── app/
│   ├── main.py                  # FastAPI uygulama giriş noktası
│   ├── config.py                # .env API anahtarı konfigürasyonu
│   │
│   ├── services/                # İş mantığı ve dış servisler
│   │   ├── virustotal.py        # VirusTotal v3 API entegrasyonu
│   │   └── hasher.py            # SHA-256 dosya hash çıkarma motoru
│   │
│   ├── models/                  # Pydantic veri modelleri
│   │   └── scanner.py
│   │
│   ├── routers/                 # API Endpoint yönlendirmeleri
│   │   └── scan.py
│   │
│   └── templates/               # Frontend Dashboard
│       └── index.html
│
├── .env.example                 # Örnek ortam değişkenleri
├── .gitignore                   # Git kısıtlama kuralları
├── README.md                    # Proje dokümantasyonu
└── requirements.txt             # Proje bağımlılıkları