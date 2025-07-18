import argparse
import cmd2
import readline
import time
from core.shodan_manager import ShodanManager
from core.nmap_manager import NmapManager
from core.hydra_manager import HydraManager
from core.utils import Utils

class Main(cmd2.Cmd):
    def __init__(self):
        super().__init__()
        self.prompt = "IoTBreaker [>] "
        self.shodan_manager = ShodanManager()
        self.nmap_manager = NmapManager()
        self.hydra_manager = HydraManager()
        self.utils = Utils()

    def preloop(self):
        """
        Metodo que se ejecuta antes de mostrar el menu inicial del programa, comprobando el funcionamiento de la clave API de Shodan.
        :param: <self> parámetros de entrada de la línea de comandos.
        """
        super().preloop()
        self.poutput(self.utils.banner_inicio())
        try:
            #Se recoge la API Key del gestor de claves de Linux
            key = self.utils.get_api_key()
            self.shodan_manager.setAPI(key)
            self.poutput("Clave Shodan cargada desde el keyring.")
            ok, msg = self.shodan_manager.comprobarAPI()
            self.poutput(msg)
        except Exception:
            self.poutput("[!] No hay clave en el keyring. Usa '9' para configurarla.")
        self.mostrar_menu()

    def postcmd(self, stop, line):
        """
        Se ejecuta después de cada ejecución completa y vuelve a mostrar el menú.
        :param: <self> parámetros de entrada de la línea de comandos.
        :param stop: Es un booleano que muestra si el sistema ha recogido una orden de finalizar
        """
        if stop:
            return True
        time.sleep(2)  # Se le añade un sleep para que al usuario le de tiempo a leer la salida una vez termina la ejecución
        self.mostrar_menu()
        return stop

    def mostrar_menu(self):
        """
        Muestra el menú inicial de la aplicación con todas las opciones
        :param: <self> parámetros de entrada de la línea de comandos.
        """
        self.poutput("\nSeleccione una opción para la auditoría:")
        self.poutput("1. Iniciar Ataque Completo (Shodan + Puertos + Fuerza Bruta)")
        self.poutput("2. Busqueda en Shodan + Ataque de Fuerza Bruta")
        self.poutput("3. Búsqueda en Shodan")
        self.poutput("4. Escaneo de puertos (Nmap)")
        self.poutput("5. Ataque de fuerza bruta (Hydra)")
        self.poutput("9. Configurar Clave API Shodan")
        self.poutput("h. Para obtener ayuda")
        self.poutput("0. Salir\n")
    def do_0(self, args):
        """Salir del programa"""
        self.poutput("Cerrando herramienta. Hasta luego!")
        return True
    def do_1(self, args):
        """Iniciar ataque completo (Shodan + Nmap + Hydra)"""
        # Búsqueda en Shodan
        disp = self._shodan_search_and_select()
        if not disp:
            return
        ip = disp['ip_str']
        self.poutput(f"\nHas seleccionado: {ip}:{disp['port']}")
        # Escaneo Nmap
        self.poutput("\nSelecciona tipo de escaneo:")
        opciones = {
            '1': self.nmap_manager.tcp_scan,
            '2': self.nmap_manager.syn_scan,
            '3': self.nmap_manager.ack_scan,
            '4': self.nmap_manager.vuln_scan,
            '5': self.nmap_manager.tcp_fast_scan,
        }
        self.poutput("1. Escaneo TCP completo (-sT), es lento.")
        self.poutput("2. Escaneo SYN (-sS)")
        self.poutput("3. Escaneo ACK (detección de firewall)")
        self.poutput("4. Escaneo de vulnerabilidades")
        self.poutput("5. Escaneo TCP rápido (100 puertos más comunes)")
        tipo = input("Opción (1/2/3/4/5): ")
        scan_fn = opciones.get(tipo)
        if not scan_fn:
            return self.poutput("Opción inválida.")
        if tipo == '4':
            # Si se realiza un Vulnerability scan: imprimimos la salida cruda
            resultado = self.nmap_manager.vuln_scan(ip)
            self.poutput("\n--- Escaneo de Vulnerabilidades (raw) ---\n")
            self.poutput(resultado)
            self.poutput("\n--- Fin Escaneo de Vulnerabilidades ---\n")
            servicios = scan_fn(ip)
            # Después de mostrar vulnerabilidades, continuar con Hydra si el usuario lo desea
        else:
            servicios = scan_fn(ip)
            self.poutput("\nResultado del escaneo:\n")
            self.poutput(self.nmap_manager._formatear_resultados(servicios))
        abiertos = [s for s in servicios if isinstance(s, dict) and s.get('state') == 'open']
        if not abiertos:
            return self.poutput("[!] No hay puertos abiertos detectados.")
        # Fuerza bruta Hydra
        if input("\n¿Atacar con fuerza bruta los servicios detectados? (s/n): ").lower() != 's':
            return self.poutput("El programa se va a cerrar.")
        # Con los puertos abiertos se inicia el flujo de ataque
        self.hydra_manager._hydra_attack_flow(ip,abiertos)
    def do_2(self, args):
        """Búsqueda en Shodan + Ataque de Fuerza Bruta"""
        # Búsqueda en Shodan
        disp = self._shodan_search_and_select()
        if not disp:
            return
        ip = disp['ip_str']
        # Escaneo Nmap para listar servicios abiertos
        self.poutput(f"\nEscaneando servicios en {ip} (-sV)...")
        servicios = self.nmap_manager._scan(ip, '-sV -F -Pn')
        abiertos = [s for s in servicios if isinstance(s, dict) and s.get('state') == 'open']
        if not abiertos:
            return self.poutput("[!] No hay puertos abiertos detectados.")
        # Con los puertos abiertos se inicia el flujo de ataque
        self.hydra_manager._hydra_attack_flow(ip,abiertos)
    def do_3(self, args):
        """
        Búsqueda de dispositivos en Shodan con la opción de guardado posteriormente.
        """
        self.poutput(
            "AVISO: si introduces filtros como 'country:', 'port:', 'org:', etc.,\n"
            "la búsqueda puede consumir créditos de tu cuenta de Shodan.\n"
        )
        try:
            query = input("Introduce una consulta (con o sin filtros): ")
            ok, resultado, dispositivos = self.shodan_manager.buscar_dispositivos(query)
            if not ok:
                return self.poutput(resultado)
            for i, linea in enumerate(resultado, 1):
                self.poutput(f"{i}. {linea}")
        except Exception as e:
            return self.poutput("La búsqueda ha fallado intentelo de nuevo")
        self.poutput(f"\nMostrando resultados para: {query}\n")
        for linea in resultado:
            self.poutput(linea)
        guardar = input("¿Deseas guardar los resultados en un archivo? (s/n): ").lower()
        if guardar == "s":
            ok2, clean_lines, _ = self.shodan_manager.buscar_dispositivos(query, raw_output=True)
            if ok2:
                ruta = self.utils.guardar_resultados("Shodan", clean_lines)
                self.poutput("Resultados guardados en " + ruta)
            else:
                self.poutput("No se pudieron obtener los resultados para guardar.")
    def do_4(self, args):
        """Escaneo de puertos"""
        ip = input("Introduce la IP objetivo para escanear: ")
        self.poutput("\nSelecciona tipo de escaneo:")
        self.poutput("1. Escaneo TCP completo (-sT), es lento.")
        self.poutput("2. Escaneo SYN (-sS)")
        self.poutput("3. Escaneo ACK (detección de firewall)")
        self.poutput("4. Escaneo de vulnerabilidades")
        self.poutput("5. Escaneo TCP rápido (100 puertos más comunes)")
        tipo = input("Opción (1/2/3/4/5): ")
        if tipo == "1":
            resultado = self.nmap_manager.tcp_scan(ip)
        elif tipo == "2":
            resultado = self.nmap_manager.syn_scan(ip)
        elif tipo == "3":
            resultado = self.nmap_manager.ack_scan(ip)
        elif tipo == "4":
            resultado = self.nmap_manager.vuln_scan(ip)
            self.poutput("\n--- Escaneo de Vulnerabilidades (raw) ---\n")
            self.poutput(resultado)
            self.poutput("\n--- Fin Escaneo de Vulnerabilidades ---\n")
        elif tipo == "5":
            resultado = self.nmap_manager.tcp_fast_scan(ip)
        else:
            self.poutput("Opción inválida.")
            return
        self.poutput("\nResultado del escaneo:\n")
        if not resultado:
            self.poutput("[!] No se obtuvieron resultados del escaneo.")
        self.poutput(self.nmap_manager._formatear_resultados(resultado))
        guardar = input("¿Deseas guardar los resultados en un archivo? (s/n): ").lower()
        if guardar == "s":
            ruta = self.utils.guardar_resultados("Nmap", self.nmap_manager._formatear_resultados(resultado))
            self.poutput("Resultados guardados en " + ruta)
    def do_5(self, args):
        """Ataque de fuerza bruta (Hydra)"""
        # Introducir objetivo
        ip = input("Introduce IP objetivo: ")

        # Escaneo de puertos abiertos para el ataque
        self.poutput(f"\nEscaneando servicios en {ip} (-sV)...")
        servicios = self.nmap_manager._scan(ip, '-sV -F -Pn')
        abiertos = [s for s in servicios if isinstance(s, dict) and s.get('state') == 'open']
        if not abiertos:
            return self.poutput("[!] No hay puertos abiertos detectados.")
        # Con los puertos abiertos se inicia el flujo de ataque
        self.hydra_manager._hydra_attack_flow(ip,abiertos)
    def do_9(self, args):
        """Configurar Clave API Shodan"""
        # Comprobamos si ya hay una clave almacenada en el keyring
        existing = self.utils.get_api_key()
        # Si existe una API key se le pregunta al usuario si está seguro de que quiere cambiar la API Key
        if existing:
            resp = input("Ya hay una API-Key configurada, ¿quieres cambiarla? (s/n): ").strip().lower()
            if resp != 's':
                self.poutput("Se mantiene la clave actual.")
                return
        # En caso de que el usuario la quiera cambiar solicitamos la nueva clave y la guardamos en el keyring
        nueva_clave = input("Introduce tu clave de API de Shodan: ").strip()
        try:
            self.utils.store_api_key(nueva_clave)
            # Cargamos inmediatamente la clave en ShodanManager
            self.shodan_manager.setAPI(nueva_clave)
            ok, msg = self.shodan_manager.comprobarAPI()
            self.poutput(msg)
        except Exception as e:
            self.poutput(f"[!] Error en la clave: {e}")
    def do_h(self, args: argparse.Namespace) -> None:
        """Ayuda sobre la aplicación"""
        self.poutput(self.utils.mostrar_ayuda())

    def _shodan_search_and_select(self) -> dict | None:
        """
        Realiza el flujo de búsqueda y selección de un dispositivo con shodan (realiza la llamada a buscar dispositivos)
        Se usa para unificar el funcionamiento de do_1 y do_2 evitando repetición de código
        Retorna None si el usuario cancela o la selección es inválida.
        :param: <self> parámetros de entrada de la línea de comandos.
        """
        self.poutput(
            "AVISO: si introduces filtros como 'country:', 'port:', 'org:', etc.,\n"
            "la búsqueda puede consumir créditos de tu cuenta de Shodan.\n"
        )
        try:
            query = input("Introduce una consulta (con o sin filtros): ")
            ok, resultado, dispositivos = self.shodan_manager.buscar_dispositivos(query)
            if not ok:
                self.poutput(resultado)
                return None
            for i, linea in enumerate(resultado, 1):
                self.poutput(f"{i}. {linea}")
        except Exception:
            self.poutput("La búsqueda ha fallado, inténtelo de nuevo.")
            return None
        try:
            sel = int(input("Selecciona el número de dispositivo que quieres atacar: ")) - 1
            if sel < 0 or sel >= len(dispositivos):
                raise IndexError
            return dispositivos[sel]
        except (ValueError, IndexError):
            self.poutput("[!] Selección inválida.")
            return None        

if __name__ == '__main__':
    app = Main()
    app.cmdloop()
