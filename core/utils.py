import os 
from datetime import datetime
import keyring

class Utils:
    # Nombre del servicio y username para guardar en el keyring junto con la contraseña
    servicio = 'shodan'
    username = 'api_key'

    def __init__(self):
        pass
    
    def guardar_resultados(self,nombre_archivo, contenido, extension="txt"):
        """
        Guarda el resultado de la ejecución en un archivo si el usuario lo desea

        :param nombre_archivo:
        :param contenido: 
        :param extension:
        :return: Ruta completa del archivo guardado
        """
        carpeta = "resultados"
        os.makedirs(carpeta, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        nombre_archivo = f"{nombre_archivo}_{timestamp}.{extension}"
        ruta_completa = os.path.join(carpeta, nombre_archivo)

        try:
            with open(ruta_completa, "w", encoding="utf-8") as f:
                if isinstance(contenido, list):
                    for linea in contenido:
                        f.write(linea + "\n")
                else:
                    f.write(str(contenido))
            return ruta_completa
        except Exception as e:
            return f"[!] Error al guardar el archivo: {e}"

    def store_api_key(self, api_key: str):
        """Guarda la API key en el keyring
        :param api_key: API Key"""
        try:
            keyring.set_password(self.servicio, self.username, api_key)
        except Exception as e:
            return f"[!] Error al guardar la API key: {e}"

    def get_api_key(self) -> str:
        """Recoge la API key del keyring
        :return: API Key"""
        try:
            return keyring.get_password(self.servicio, self.username)
        except Exception as e:
            print(f"[!] Error al recuperar la API key: {e}")
            return None


    def banner_inicio(self) -> str:
        """Configura un banner de inicio para el programa"""
        return  r'''
            ____    __________                  __                                           
   /  _/___/_  __/ __ )________  ____ _/ /_____  _____                               
   / // __ \/ / / __  / ___/ _ \/ __ `/ //_/ _ \/ ___/                               
 _/ // /_/ / / / /_/ / /  /  __/ /_/ / ,< /  __/ /                                   
/___/\____/_/ /_____/_/___\___/\__,_/_/|_|\___/_/      ____              _           
      / /_  __  __   / ___/___  _________ _(_)___     / __ \________    (_)___  ____ 
     / __ \/ / / /   \__ \/ _ \/ ___/ __ `/ / __ \   / / / / ___/ _ \  / / __ \/ __ \
    / /_/ / /_/ /   ___/ /  __/ /  / /_/ / / /_/ /  / /_/ / /  /  __/ / / /_/ / / / /
   /_.___/\__, /   /____/\___/_/   \__, /_/\____/   \____/_/   \___/_/ /\____/_/ /_/ 
         /____/                   /____/                          /___/            
         '''
    def mostrar_ayuda(self) -> str:
        """Devuelve una guía básica de uso del programa"""
        return r'''
===============================================
Guía de uso de la aplicación
1 -> Inicia un ataque completo. El programa busca en Shodan con los parámetros introducidos, posteriormente se elige un dispositivo para escanearlo con Nmap y finalmente se ejecuta un ataque con Hydra
2 -> Inicia una búsqueda en Shodan + ataque de fuerza bruta: busca, selecciona y lanza Hydra
3 -> Se realiza una búsqueda en Shodan con opción de guardar resultados
4 -> Realiza un escaneo de puertos (Nmap) a la IP introducida
5 -> Realiza un ataque de fuerza bruta (Hydra) a la IP y puerto indicados
9 -> Configura o actualiza la clave API de Shodan y la guarda cifrada en el keyring
h -> Muestra este panel de ayuda
0 -> Salir de la aplicación

COMANDOS ÚTILES DE SHODAN:
 • product:UPnP port:1900        — Dispositivos UPnP en puerto 1900.
 • http.title:"IP Camera"        — Interfaz web de cámaras IP.
 • port:23 default password      — Telnet con credenciales por defecto.
 • product:Dropbear version <2013— Instancias SSH Dropbear antiguas.
 • port:161 community:public     — SNMP abierto con community “public”.
 • tag:honeypot                  — Hosts etiquetados como honeypot.
 • honeypot:true port:22         — Honeypots SSH activos.

COMANDOS NMAP EXPLICADOS:
 1) Escaneo TCP completo (-sT -Pn)
    -sT: TCP connect(), -Pn: no ping.
 2) Escaneo SYN (-sS -Pn)
    -sS: half-open SYN, requiere sudo, más sigiloso y rápido.
 3) Escaneo ACK (-sA -Pn)
    -sA: mapea firewalls (filtrado vs abierto).
 4) Escaneo vulnerabilidades (-sV --script vuln -Pn)
    -sV: detección de versiones, --script vuln: NSE scripts de vuln.
 5) tcp_fast_scan equivale a -sT -Pn para un escaneo ligero.

ATAQUES HYDRA CONFIGURADOS:
 • Diccionarios separados:
   hydra -L users.txt -P pass.txt -s <puerto> -f -V <ip> <módulo>
 • Fichero combo:
   hydra -C combo.txt -s <puerto> -f -V <ip> <módulo>
 • Fuerza bruta pura:
   hydra -l <usuario> -x min:max:charset -s <puerto> -f -V <ip> <módulo>

MÓDULOS SOPORTADOS:
 ssh, ftp, telnet, smtp, http-form-post, https-form-post,
 rdp, mysql, postgres, mssql, smb, snmp, redis
'''
