import subprocess
import re
from core.utils import Utils

class HydraManager:
    """
    Módulo para ejecutar ataques de fuerza bruta con Hydra, con módulos para ataques de diccionarios y fuerza bruta
    """
    def __init__(self, hydra_path: str = 'hydra', timeout: int = None):
        """
        :param hydra_path: Nombre o ruta completa al binario de Hydra para ejecutar Hydra en Linux.
        :param timeout: Tiempo máximo en segundos para cada ejecución de Hydra.
        """
        self.hydra_path = hydra_path
        self.timeout = timeout

    def _get_module(self, service: str = None, port: int = None) -> str:
        """
        Metodo que devuelve el servicio encontrado en Nmap para ejecutar un ataque de fuerza bruta seleccionando  protocolo y puerto
        :param service: Servicio encontrado en la búsqueda de nmap pasado por parámetro y mapeado para que hydra lo entienda.
        :param port: Puerto del servicio encontrado en la búsqueda de nmap, si se encuentra un puerto se mapea para que hydra lo entienda.
        :return mod o port: devuelve el servicio o el puerto mapeado para que Hydra lo entienda.
        """
        mapping = {
            'ssh': 'ssh', 'ftp': 'ftp', 'telnet': 'telnet',
            'smtp': 'smtp', 'http': 'http-post-form', 'https': 'https-post-form',
            'rdp': 'rdp','mysql': 'mysql', 'postgresql': 'postgres',
            'postgres': 'postgres', 'mssql': 'mssql', 'smb': 'smb', 'snmp': 'snmp',
            'redis': 'redis'
        }
        # Si tiene puerto en vez de servicio se mapean los números de puertos por el servicio para traducirlo para hydra
        if port:
            port_map = {
                22: 'ssh', 21: 'ftp', 23: 'telnet', 25: 'smtp',
                80: 'http-post-form', 443: 'https-post-form', 3389: 'rdp',
                3306: 'mysql', 5432: 'postgres', 1433: 'mssql', 445: 'smb',
                161: 'snmp', 6379: 'redis'
            }
            return port_map.get(port)
        #Se comprueba si existe el servicio encontrado con lo que se tiene en el diccionario para traducirlo para hydra
        if service:
            mod = mapping.get(service.lower())
            if mod:
                return mod
        #Si no encuentra ni servicio ni puertos disponibles del escaneo anterior no devuelve nada
        return None

    def _run(self, objetivo: str, modulo: str, puerto: int, usuarios: str = None, contrasenas: str = None, combo_file: str = None,
             brute: bool = False,
             min_len: int = None,
             max_len: int = None,
             charset: str = None,
             extra_args: list = None
         ) -> str:
        """
        Construye y ejecuta el comando de Hydra según las opciones pasadas opr parámetros
        :param objetivo: direccion IP del objetivo
        :param modulo: protocolo devuelto
        :param puerto: puerto del objetivo
        :param usuarios: diccionario de usuarios
        :param contrasenas: diccionario de contrasenas
        :param combo_file: diccionario con usuarios:contrasenas
        :param brute: booleano para comprobar si se hace un ataque de diccionarios o de fuerza bruta, si está a True es de fuerza bruta
        :param min_len: número mínimo de carácteres para hacer el ataque de fuerza bruta
        :param max_len: número máximo de carácteres para hacer el ataque de fuerza bruta
        :param charset: set de carácteres para realizar el ataque de fuerza bruta, por ejemplo a-zA-Z0-9
        :param extra_args: argumentos extra para introducir en Hydra
        Modos:
          - Diccionarios: '-L usuarios' y '-P contrasenas'.
          - Fichero combo: '-C combo_file'.
          - Fuerza bruta puro: '-l usuario -x min_len:max_len:charset'.
        """
        cmd = [self.hydra_path]

        if brute:
            # Modo fuerza bruta puro, este modo hay que añadirle pocos caracteres en min_len y max_len porque sino se crean millones de posibilidades
            if min_len is None or max_len is None or not charset or not usuarios:
                raise ValueError("Fuerza bruta requiere usuario, min_len, max_len y charset")
            cmd.extend(['-l', usuarios])
            cmd.extend(['-x', f"{min_len}:{max_len}:{charset}"])
        elif combo_file:
            cmd.extend(['-C', combo_file])
        else:
            cmd.extend(['-L', usuarios or '', '-P', contrasenas or ''])

        # Opciones comunes para el ataque en hydra (para configurar el comando que mandarle a Hydra)
        cmd.extend(['-s', str(puerto), '-f', '-V'])
        cmd.extend([objetivo, modulo])   # primero objetivo y módulo
        if extra_args:
            cmd.extend(extra_args)
        # Se ejecuta el subprocess para el ataque con Hydra, es decir se ejecuta Hydra como un subproceso en Linux
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=self.timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return "[!] Hydra ha expirado (timeout)."
        except FileNotFoundError:
            return "[!] No se encontró el ejecutable de Hydra. Revisa hydra_path."
        except Exception as e:
            return f"[!] Error al ejecutar Hydra: {str(e)}"

    def _parsear_resultados(self, salida: str) -> list:
        """
        Parsea la salida de Hydra y extrae las credenciales encontradas.

        :param salida: Texto completo de salida de Hydra.
        :return: Lista de dicts con host, port, service, login y password.
        """
        creds = []
        # Patrón unificado haciendo uso de una expresión regular
        # - Captura [port][service]
        # - Opcionalmente "host: <IP>" o "<IP>:port"
        # - Luego "login: <user>" y "password: <pass>"
        pattern = re.compile(
            r"^\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]" +
            r"(?:.*?host:\s*)?(?P<host>\d+\.\d+\.\d+\.\d+)(?:[:\s]\d+)?\s+" +
            r"login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)"
        )
        for line in salida.splitlines():
            m = pattern.match(line)
            if m:
                creds.append({
                    'host': m.group('host'),
                    'port': int(m.group('port')),
                    'service': m.group('service'),
                    'login': m.group('login'),
                    'password': m.group('password'),
                })
        return creds
    
    def _hydra_attack_flow(self, ip: str, servicios: list) -> None:
        """
        Dada la dirección IP y la lista de servicios abiertos (resultado de Nmap),
        muestra el menú de selección de servicio (select_service_for_hydra),
        luego el de modo de ataque (diccionarios/combo/brute) y ejecuta Hydra.
        Su función es unificar el flujo de ataque de fuerza bruta de do_1 y do_2
        :param ip: Recoge la IP del resultado de Nmap
        :param servicios: Recoge los servicios de Nmap
        """
        # Seleccionar servicio + parámetros HTTP si aplica
        seleccion = self.select_service_for_hydra(servicios)
        if not seleccion:
            return
        port, mod, extra_args = seleccion

        print(f"\nAtacando {mod} en {ip}:{port}")

        # Menú de modo de ataque
        print("\nModo de ataque:")
        print("1. Diccionarios separados (usuarios y contraseñas)")
        print("2. Fichero combo user:pass (-C)")
        print("3. Fuerza bruta pura (-x)")
        modo = input("Opción (1/2/3): ").strip()

        combo = None
        uf = pf = None
        brute_args = None

        if modo == '1':
            uf = input("Diccionario usuarios [users.txt]: ").strip()
            pf = input("Diccionario contraseñas [pass.txt]: ").strip()
        elif modo == '2':
            combo = input("Fichero combo user:pass [combo.txt]: ").strip()
            uf = pf = None
            if not combo:
                print("[!] Debes indicar fichero combo.")
                return
        elif modo == '3':
            user = input("Introduce un usuario a probar: ").strip()
            try:
                min_len = int(input("Longitud mínima: ").strip())
                max_len = int(input("Longitud máxima: ").strip())
            except ValueError:
                print("[!] Las longitudes deben ser números.")
                return
            charset = input("Charset (ej: a-zA-Z0-9): ").strip()
            brute_args = {
                'user':    user,
                'min':     min_len,
                'max':     max_len,
                'charset': charset
            }
        else:
            print("[!] Opción inválida.")
            return

        # Ejecutar Hydra
        print(f"\nIniciando fuerza bruta {mod} en {ip}:{port}...")
        creds, raw = self.attack(
            objetivo=ip,
            modulo=mod,
            puerto=port,
            usuarios=uf,
            contrasenas=pf,
            combo_file=combo,
            brute_args=brute_args,
            extra_args=extra_args
        )

        print("\n--- Ejecución de Hydra ---")
        print(raw)
        print("\n--- Ejecución de Hydra ---")
        if creds:
            for c in creds:
                print(f"✅ {c['login']}:{c['password']}")
            guardar = input("¿Deseas guardar los resultados en un archivo? (s/n): ").lower()
            if guardar == "s":
                cred_lines = [f"{ip} {port} {c['login']}:{c['password']}" for c in creds]
                ruta = Utils().guardar_resultados("Credenciales",cred_lines)
                print("Resultados guardados en " + ruta)
        else:
            print("❌ No se encontraron credenciales.")


    def attack(self,
               objetivo: str,
               modulo: str = None,
               puerto: int = None,
               usuarios: str = None,
               contrasenas: str = None,
               combo_file: str = None,
               brute_args: dict = None,
               extra_args: list = None
           ) -> tuple:
        """Ejecuta un ataque de Hydra (diccionario/combo/brute).
            :param objetivo: direccion IP del objetivo
            :param modulo: protocolo devuelto
            :param puerto: puerto del objetivo
            :param usuarios: diccionario de usuarios
            :param contrasenas: diccionario de contrasenas
            :param combo_file: diccionario con usuarios:contrasenas
            :param brute_args: lista de todos los argumentos para ejecutar un ataque de fuerza bruta (min_len, max_len...)
            :param extra_args: argumentos extra para introducir en Hydra
        """
        # Si no hay un protocolo encontrado llama al metodo get_module
        if not modulo:
            modulo = self._get_module(None, puerto)
        # Preparar parámetros de brute
        brute = False
        min_len = max_len = None
        charset = None
        user = usuarios
        if brute_args:
            brute = True
            user    = brute_args.get('user')
            min_len = brute_args.get('min')
            max_len = brute_args.get('max')
            charset = brute_args.get('charset')
        # Llama al metodo _run para ejecutar el ataque deseado
        salida = self._run(
            objetivo=objetivo,
            modulo=modulo,
            puerto=puerto,
            usuarios=user,
            contrasenas=contrasenas,
            combo_file=combo_file,
            brute=brute,
            min_len=min_len,
            max_len=max_len,
            charset=charset,
            extra_args=extra_args
        )
        creds = self._parsear_resultados(salida)
        return creds, salida

    def select_service_for_hydra(self, servicios: list) -> tuple:
        """
        Lenguaje interactivo para que el usuario elija el servicio a atacar de una lista de 'servicios'.
        Cada elemento de 'servicios' es un dict con al menos {'port': int, 'service': str, 'state': 'open'}.
        Retorna (port, module, extra_args) para pasárselo a .attack(), o None si hay error/cancel().
        :param servicios: Recoge los servicios de un escaneo de Nmap
        """
        # Filtrar solo los que estén 'open'
        abiertos = [s for s in servicios if isinstance(s, dict) and s.get('state') == 'open']
        if not abiertos:
            print("[!] No hay puertos abiertos detectados.")
            return None
        # Muestra la lista numerada de servicios
        print("\nSelecciona el servicio a atacar:")
        for i, s in enumerate(abiertos, 1):
            print(f"{i}. {s['port']}/{s['service']}")
        # Pide al usuario que elija el servicio a atacar
        try:
            idx = int(input("Opción (número): ").strip()) - 1
            if idx < 0 or idx >= len(abiertos):
                raise IndexError
            svc = abiertos[idx]
        except (ValueError, IndexError):
            print("[!] Selección inválida.")
            return None
        port = svc['port']
        service_name = svc.get('service')
        # Inferir módulo Hydra
        mod = self._get_module(service_name, port)
        if not mod:
            print(f"[!] Servicio no soportado para Hydra: {service_name}:{port}")
            return None
        extra_args = None
        # Si es HTTP/HTTPS, pedimos parámetros del formulario
        if mod in ('http-post-form', 'https-post-form'):
            print("\n== Parámetros HTTP-POST-FORM ==")
            ruta_form = input("Ruta del formulario (ej. /login.php): ").strip()
            campo_user = input("Nombre del campo para usuario (ej. user): ").strip()
            campo_pass = input("Nombre del campo para contraseña (ej. pass): ").strip()
            metodo_det = input("¿Detectar fallo por texto (1) o éxito por código (2)? [1/2]: ").strip()

            if metodo_det == '1':
                texto_fallo = input("Texto que aparece cuando falla el login: ").strip()
                form_string = f"{ruta_form}:{campo_user}=^USER^&{campo_pass}=^PASS^:F={texto_fallo}"
            elif metodo_det == '2':
                try:
                    codigo_exito = int(input("Código HTTP que indica éxito (ej. 302): ").strip())
                except ValueError:
                    print("[!] El código debe ser un número.")
                    return None
                form_string = f"{ruta_form}:{campo_user}=^USER^&{campo_pass}=^PASS^:S={codigo_exito}"
            else:
                print("[!] Opción inválida para método de detección.")
                return None
            extra_args = [form_string]
        # Devolver los valores listos para .attack()
        return port, mod, extra_args

