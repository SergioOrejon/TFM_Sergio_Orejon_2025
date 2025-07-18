import shodan
import time
from core.utils import Utils
class ShodanManager:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.api = shodan.Shodan(self.api_key) if self.api_key else None

    def setAPI(self, key):
        """Guarda y actualiza la clave API
        :param key:almacena la API Key en la clave ShodanManager durante la ejecución
        """
        self.api_key = key
        self.api = shodan.Shodan(self.api_key)

    def comprobarAPI(self):
        """Verifica si hay una clave en la clase ShodanManager y muestra las caracteristicas disponibles de la cuenta
        :return: Devuelve verdadero o falso si la clave existe o es correcta.
        """
        if not self.api:
            return False, "No se ha encontrado una clave API de Shodan. Configúrala con la opción 9."
        try:
            info = self.api.info()
            creditos = info.get("query_credits", 0)
            plan = info.get("plan", "desconocido")
            return True, f"[✓] Clave API válida ({plan}) - Créditos restantes: {creditos}"
        except shodan.exception.APIError as e:
            return False, f"[!] Error al conectar con la API de Shodan: {e}"
        except Exception as e:
            return False, f"[!] Error inesperado al verificar la API: {e}"
    @staticmethod
    def clasificar_color(port, banner):
        """
        Clasifica el color basado en puerto y banner del servicio.

        :param port: Puerto como string o número.
        :param banner: Primera línea del banner.
        :return: Código ANSI de color.
        """
        puertos_verdes = [# Servicios estándar
        '21', '22', '23', '80', '443', '445', '3306', '3389', '5900',
        # IoT comunes
        '1883',   # MQTT
        '8883',   # MQTT over TLS
        '554',    # RTSP (cámaras)
        '8554',   # RTSP alternativo
        '5683',   # CoAP
        '8888',   # UPnP SSDP (HTTP/XML)
        '1900',   # SSDP discovery
        '161',    # SNMP
        '502',    # Modbus
        '102',    # Siemens S7
        '5684',   # CoAP over DTLS
        '8889',   # Cámara IoT adicional
        ]
        respuestas_buenas = [        # Protocolos estándar
        '220', '230', 'SSH', 'FTP', 'HTTP/1.1 200', 'HTTP/1.0 200',
        'Login', 'Welcome', 'RDP', 'VNC', 'MySQL', 'SMTP', '302',
        # IoT específicos
        'MQTT', 'CoAP', 'SSDP', 'RTSP', 'Modbus', 'S7',
        'ESP8266', 'ESP32', 'Broadcom', 'BusyBox', 'Lighttpd', 'GoAhead-Webs',
        'Boa/0.', 'Boa/1.', 'Arduino', 'Linux 3.']

        puerto_bueno = str(port) in puertos_verdes
        respuesta_buena = any(respuesta in banner for respuesta in respuestas_buenas)

        if puerto_bueno and respuesta_buena:
            return "\033[92m"  # Verde
        elif puerto_bueno or respuesta_buena:
            return "\033[93m"  # Amarillo
        else:
            return "\033[91m"  # Rojo

    def buscar_dispositivos(self, query, limit=10, reintentos=2, raw_output=False):
        """
        Realiza una búsqueda en Shodan con una consulta dada, con reintentos en caso de error temporal.

        :param query: Consulta de búsqueda.
        :param limit: Número máximo de resultados.
        :param reintentos: Reintentos si hay fallo de conexión o error temporal.
        :param raw_output: Si es True, devuelve sólo texto sin códigos de color.
        :return: 
            Si raw_output=False (por defecto): (True, salida_coloreada, dispositivos)
            Si raw_output=True:  (True, salida_sin_color, dispositivos)
        """
        if not self.api:
            return False, "No hay clave API configurada."

        for intento in range(1, reintentos + 1):
            try:
                resultados = self.api.search(query)
                dispositivos = resultados.get("matches", [])[:limit]

                salida_coloreada = []
                salida_sin_color = []

                for i, device in enumerate(dispositivos, start=1):
                    try:
                        ip = device.get('ip_str', 'N/A')
                        port = device.get('port', 'N/A')
                        org = device.get('org', 'Desconocido')
                        product = device.get('product', 'Desconocido')
                        version = device.get('version', '')
                        transport = device.get('transport', 'tcp')
                        banner = device.get('data', '').strip().splitlines()[0] if device.get('data') else 'Sin banner'
                        servicio = f"{product} {version}".strip() if product else "No identificado"

                        color = self.clasificar_color(port, banner)

                        # Línea coloreada
                        linea_col = (
                            f"{color}{i}. {ip}:{port}/{transport} - {org}\n"
                            f"   Servicio: {servicio}\n"
                            f"   Banner: {banner}\033[0m\n"
                        )
                        salida_coloreada.append(linea_col)

                        # Línea sin color
                        linea_clean = (
                            f"{i}. {ip}:{port}/{transport} - {org}\n"
                            f"   Servicio: {servicio}\n"
                            f"   Banner: {banner}\n"
                        )
                        salida_sin_color.append(linea_clean)

                    except Exception as e:
                        err_line = f"{i}. Error al procesar resultado: {e}"
                        salida_coloreada.append(err_line)
                        salida_sin_color.append(err_line)

                if raw_output:
                    return True, salida_sin_color, dispositivos
                else:
                    return True, salida_coloreada, dispositivos

            except shodan.exception.APIError as e:
                return False, f"[!] Error en la búsqueda: {e}"

            except Exception as e:
                if intento < reintentos:
                    time.sleep(2)
                    continue
                else:
                    return False, f"[!] Error inesperado: {e}"


