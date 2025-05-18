import subprocess
import requests
import json
import os
import re
import socket
import csv
import pandas as pd
from datetime import datetime

def get_ss_data():
    result = subprocess.run(['ss', '-tunp'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return result.stdout.decode()

def parse_connections(ss_output):
    conexiones = []
    for line in ss_output.splitlines():
        if 'ESTAB' in line:
            match = re.search(
                r'\s+(\d{1,3}(?:\.\d{1,3}){3})\:\d+\s+(\d{1,3}(?:\.\d{1,3}){3})\:\d+.*users:\(\("([^"]+)",pid=(\d+)',
                line
            )
            if match:
                ip_local, ip_remota, process, pid = match.groups()
                if es_ipv4_valida(ip_remota):
                    proto = 'tcp' if 'tcp' in line else 'udp' if 'udp' in line else 'desconocido'
                    conexiones.append({
                        'ip': ip_local,
                        'proto': proto,
                        'pid_program': f"{process} (PID {pid})",
                        'ip_destino': ip_remota,
                    })
    return conexiones

def obtener_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def es_ipv4_valida(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

ips_conocidas = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"
}

def check_ip_virustotal(ip, api_key, cache):
    if ip in ips_conocidas:
        return {"malicious": 0, "suspicious": 0, "harmless": 100, "timestamp": datetime.now().strftime("%Y-%m-%d")}
    
    if ip in cache and es_cache_valido(ip, cache):
        return cache[ip]

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            stats['timestamp'] = datetime.now().strftime("%Y-%m-%d")
            cache[ip] = stats
            return stats
    except:
        pass

    cache[ip] = None
    return None

def cargar_cache():
    try:
        with open('cache.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def guardar_cache(cache):
    with open('cache.json', 'w') as f:
        json.dump(cache, f, indent=4)

def es_cache_valido(ip, cache, dias_validos=7):
    try:
        timestamp = cache[ip]['timestamp']
        fecha_cache = datetime.strptime(timestamp, "%Y-%m-%d")
        return (datetime.now() - fecha_cache).days < dias_validos
    except:
        return False

def clasificar_seguridad(stats):
    if not stats:
        return "Desconocido"
    elif stats.get('malicious', 0) > 0:
        return "Peligroso"
    elif stats.get('suspicious', 0) > 0:
        return "Sospechoso"
    else:
        return "Seguro"

def cargar_procesos_legitimos(ruta_archivo):
    with open(ruta_archivo, 'r') as f:
        return set(line.strip().lower() for line in f if line.strip())

def clasificar_seguridad_por_nombre(nombre_proceso, procesos_legitimos):
    nombre_base = nombre_proceso.split()[0].lower()
    return "Seguro" if nombre_base in procesos_legitimos else "Sospechoso"

def generar_reporte(conexiones, vt_data):
    conexiones_mostradas = 0
    conexiones_omitidas = 0

    with open("reporte_conexiones.txt", "w") as file:
        file.write("IP LOCAL".ljust(20) + "PROTO".ljust(8) + "PROCESO".ljust(25) +
                   "PID".ljust(10) + "DESTINO (HOST/IP)".ljust(40) + "CLASIFICACION".ljust(15) + "\n")
        file.write("-" * 130 + "\n")

        for conn in conexiones:
            if conn['clasificacion'] == "Seguro":
                conexiones_omitidas += 1
                continue

            nombre_proceso, pid = conn['pid_program'].split(' (PID ')
            pid = pid.rstrip(')')
            host_destino = obtener_hostname(conn['ip_destino'])

            file.write(
                conn['ip'].ljust(20) +
                conn['proto'].ljust(8) +
                nombre_proceso.ljust(25) +
                pid.ljust(10) +
                host_destino.ljust(40) +
                conn['clasificacion'].ljust(15) + "\n"
            )
            conexiones_mostradas += 1

        file.write("\nFecha del escaneo: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
        file.write(f"\nConexiones mostradas: {conexiones_mostradas}\n")
        file.write(f"Conexiones seguras omitidas: {conexiones_omitidas}\n")

PROCESOS_LEGITIMOS = {
    "python3", "sshd", "firefox", "bash", "systemd", "chrome", "code", "gnome-shell",
    "Xorg", "pulseaudio", "NetworkManager", "nm-applet", "bluetoothd", "gvfsd",
    "udisksd", "lightdm", "gdm3", "cupsd", "dbus-daemon", "login", "cron", "snapd",
    "nemo", "nautilus", "top", "htop", "wget", "curl", "apt", "dpkg", "ps", "zsh", "sh"
}

def exportar_reporte(conexiones, formato="txt", nombre="reporte_conexiones"):
    conexiones_filtradas = []
    conexiones_seguras = []

    for conn in conexiones:
        nombre_proceso, pid = conn['pid_program'].split(' (PID ')
        pid = pid.rstrip(')')
        host_destino = obtener_hostname(conn['ip_destino'])
        fila = {
            "IP LOCAL": conn['ip'],
            "PROTO": conn['proto'],
            "PROCESO": nombre_proceso,
            "PID": pid,
            "DESTINO": host_destino,
            "CLASIFICACION": conn['clasificacion']
        }

        if conn['clasificacion'] == "Seguro":
            conexiones_seguras.append(fila)
        else:
            conexiones_filtradas.append(fila)

    conexiones_mostrar = conexiones_filtradas + conexiones_seguras[:5]
    ruta_base = os.path.join(os.getcwd(), f"{nombre}.{formato}")
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if formato == "txt":
        with open(ruta_base, "w") as f:
            f.write("IP LOCAL".ljust(20) + "PROTO".ljust(8) + "PROCESO".ljust(25) +
                    "PID".ljust(10) + "DESTINO (HOST/IP)".ljust(40) + "CLASIFICACION".ljust(15) + "\n")
            f.write("-" * 130 + "\n")
            for row in conexiones_mostrar:
                f.write(
                    row['IP LOCAL'].ljust(20) +
                    row['PROTO'].ljust(8) +
                    row['PROCESO'].ljust(25) +
                    row['PID'].ljust(10) +
                    row['DESTINO'].ljust(40) +
                    row['CLASIFICACION'].ljust(15) + "\n"
                )
            f.write(f"\nFecha del escaneo: {fecha}\n")
            f.write(f"Conexiones mostradas: {len(conexiones_mostrar)}\n")
            f.write(f"Conexiones seguras omitidas: {max(len(conexiones_seguras) - 5, 0)}\n")

    elif formato == "csv":
        with open(ruta_base, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=conexiones_mostrar[0].keys())
            writer.writeheader()
            writer.writerows(conexiones_mostrar)

    elif formato == "xlsx":
        df = pd.DataFrame(conexiones_mostrar)
        df.to_excel(ruta_base, index=False)

    print(f"\nReporte generado con éxito en: {ruta_base}")

if __name__ == "__main__":
    print("Analizando conexiones...")
    api_key = os.getenv("VT_API_KEY") or "X"

    salida = get_ss_data()
    conexiones = parse_connections(salida)

    cache_virustotal = cargar_cache()
    for conn in conexiones:
        ip_destino = conn['ip_destino']
        stats_vt = check_ip_virustotal(ip_destino, api_key, cache_virustotal)
        conn['vt_stats'] = stats_vt
        nombre_proceso = conn.get('pid_program', '').split('(')[0].strip()
        conn['clasificacion'] = clasificar_seguridad(stats_vt) or clasificar_seguridad_por_nombre(nombre_proceso, PROCESOS_LEGITIMOS)

    guardar_cache(cache_virustotal)

    print("Análisis completado.")
    print("Selecciona el formato del reporte: 1) TXT  2) CSV  3) XLSX")
    opcion = input("Ingresa 1, 2 o 3: ").strip()

    formatos = {"1": "txt", "2": "csv", "3": "xlsx"}
    formato = formatos.get(opcion, "txt")
    exportar_reporte(conexiones, formato)
