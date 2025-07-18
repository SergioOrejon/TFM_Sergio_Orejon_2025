import nmap

class NmapManager:
    def __init__(self):
        # Inicializa el objeto PortScanner de python-nmap
        self.scanner = nmap.PortScanner()
    

    def _scan(self, ip: str, arguments: str):
        """
        Ejecuta un escaneo con los argumentos dados y parsea el resultado.

        :param ip: IP o rango de destino.
        :param arguments: Cadena de argumentos para nmap (por ejemplo, '-sT -F -Pn').
        :return: Lista de diccionarios con información de cada puerto detectado o mensaje de error.
        """
        try:
            # Ejecuta el escaneo
            self.scanner.scan(hosts=ip, arguments=arguments)
            return self._parsear_resultados()
        except nmap.PortScannerError as e:
            return [f"[!] Error en Nmap: {e}"]
        except Exception as e:
            return [f"[!] Error en Nmap: {e}"]


    def tcp_scan(self, ip: str):
        """
        Realiza un escaneo TCP completo (-sT) y sin ping (-Pn).
        :param ip: IP o rango de destino.
        :return self._scan: devuelve una llamada a la función scan con los argumentos del metodo
        """
        return self._scan(ip, "-sT -sV -Pn")

    def syn_scan(self, ip: str):
        """
        Realiza un escaneo SYN (-sS) y sin ping (-Pn).
        :param ip: IP o rango de destino.
        :return self._scan: devuelve una llamada a la función scan con los argumentos del metodo
        """
        return self._scan(ip, "-sS -sV -Pn")

    def ack_scan(self, ip: str):
        """
        Realiza un escaneo ACK (-sA) y sin ping (-Pn) para detección de firewalls.
        :param ip: IP o rango de destino.
        :return self._scan: devuelve una llamada a la función scan con los argumentos del metodo
        """
        return self._scan(ip, "-sA  -sV -Pn")

    def vuln_scan(self, ip: str):
        """
        Realiza un escaneo de versiones y ejecuta scripts de detección de vulnerabilidades (--script vuln).
        :param ip: IP o rango de destino.
        :return self._scan: devuelve una llamada a la función scan con los argumentos del metodo
        """
        return self._scan(ip, "-sV --script vuln -Pn -F")

    def tcp_fast_scan(self, ip: str):
        """
        Realiza un escaneo TCP (-sT) a los 100 puertos más comunes (-F)
        :param ip: IP o rango de destino.
        :return self._scan: devuelve una llamada a la función scan con los argumentos del metodo
        """
        return self._scan(ip, "-sT -F -Pn -sV")


    def _parsear_resultados(self):
        """
        Parsea los resultados internos de nmap. PortScanner en una lista,
        combinando product/version/extrainfo en la columna 'version'.
        :return resultados: Devuelve una lista con los resultados antes de formatearlos para la salida
        """
        resultados = []
        
        for host in self.scanner.all_hosts():
            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto].keys():
                    info = self.scanner[host][proto][port]
                    # Montamos la versión igual que nmap CLI:
                    ver = " ".join(p for p in (
                        info.get("product", ""),
                        info.get("version", ""),
                        info.get("extrainfo", "")
                    ) if p) or "-"
                    resultados.append({
                        'host': host,
                        'protocol': proto,
                        'port': port,
                        'state': info.get('state'),
                        'service': info.get('name'),
                        'version': ver
                    })
        return resultados

    def _formatear_resultados(self, resultados):
        """
        Toma la lista de dicts de scan() y devuelve un string con tabla alineada:
        Host Protocolo Puerto Estado Servicio Versión
        :param resultados: se formatean los resultados obtenidos del escaneo de nmap a un formato concreto
        :return: Retorna una tabla con los resultados mostrando host protocolo puerto estado servicio y version
        """
        if not resultados or not isinstance(resultados, list) or not isinstance(resultados[0], dict):
            return "\n".join(resultados) if isinstance(resultados, list) else str(resultados)

        headers = ["Host", "Proto", "Port", "State", "Service", "Version"]
        rows = [
            [
                r["host"],
                r["protocol"],
                str(r["port"]),
                r["state"],
                r["service"] or "-",
                r["version"] or "-"
            ]
            for r in resultados
        ]
        widths = [max(len(col) for col in ([hdr] + [row[i] for row in rows])) for i, hdr in enumerate(headers)]
        lines = []
        lines.append("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
        lines.append("  ".join("-" * widths[i] for i in range(len(headers))))
        for row in rows:
            lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))
        return "\n".join(lines)
