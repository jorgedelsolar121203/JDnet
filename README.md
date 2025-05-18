# 🛡️ JDnet - Network Connection Analyzer

JDnet es una herramienta de línea de comandos para analizar conexiones de red activas en tiempo real, identificar procesos asociados y verificar la seguridad de las IPs destino mediante la API de VirusTotal. Pensado para entornos Linux, JDnet combina comandos del sistema con servicios externos para proporcionar un informe detallado de las conexiones de red.

## 🚀 Características principales

- Análisis de conexiones activas usando ss.
- Identificación del proceso asociado a cada conexión (PID y nombre del programa).
- Clasificación de conexiones como Seguras, Sospechosas o Peligrosas.
- Validación de IPs mediante la API de VirusTotal.
- Resolución DNS inversa para mostrar nombres de dominio cuando sea posible.
- Cacheo local de resultados para evitar el abuso de la API y acelerar análisis futuros.
- Exportación de reportes en formatos: .txt, .csv y .xlsx.
- Filtrado inteligente: muestra solo conexiones relevantes, pero incluye ejemplos seguros para contexto.

## 📸 Ejemplo de salida

IP LOCAL             PROTO   PROCESO                  PID       DESTINO (HOST/IP)                     CLASIFICACION  
--------------------------------------------------------------------------------------------------------------  
192.168.0.103        tcp     firefox                  1242      google.com                             Seguro  
192.168.0.103        tcp     unknown_process          1833      suspicious-domain.xyz                  Sospechoso  
...

## 📦 Instalación y uso

Clona este repositorio:  
git clone https://github.com/tuusuario/jdnet.git  
cd jdnet

Crea un entorno virtual (opcional pero recomendado):  
python3 -m venv venv  
source venv/bin/activate

Instala los requisitos:  
pip install -r requirements.txt

Configura tu clave de API de VirusTotal:

Importante: El archivo fuente tiene "X" como marcador. Sustitúyelo con tu clave de API manualmente:  
api_key = os.getenv("VT_API_KEY") or "X"

O bien, puedes definirla como variable de entorno:  
export VT_API_KEY="tu_clave_aqui"

Ejecuta la herramienta:  
python jdnet.py

Elige el formato del reporte cuando se te solicite.

## 📁 Requisitos

El archivo requirements.txt debería contener lo siguiente:  
requests  
pandas  
openpyxl

Puedes generarlo fácilmente con:  
pip freeze > requirements.txt

## ⚙️ Archivos auxiliares

cache.json: Archivo generado automáticamente para almacenar resultados previos de VirusTotal.  
procesos_legitimos.txt (opcional): Lista de procesos que pueden ser clasificados como "Seguros" sin necesidad de API.

## 🧠 Lógica de clasificación

Si la IP destino es común o conocida (Google DNS, Cloudflare), se clasifica como Segura.  
Si VirusTotal detecta indicadores de compromiso, se marca como Peligrosa o Sospechosa según el nivel.  
Si el proceso no está en la lista blanca de procesos legítimos, se marca como Sospechoso por nombre.
