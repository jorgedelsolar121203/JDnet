# JDnet 🔍

JDnet es una herramienta ligera en Python para analizar conexiones de red activas en Linux, identificar procesos sospechosos y verificar IPs remotas usando la API de VirusTotal.

## Características

- Escaneo de conexiones activas usando `ss`.
- Clasificación de IPs usando la API de VirusTotal.
- Reconocimiento de procesos legítimos.
- Generación de reportes en TXT, CSV o XLSX.
- Sistema de caché para evitar consumo excesivo de la API.

## Requisitos

- Python 3.7+
- Dependencias:

```bash
pip install -r requirements.txt
