# TFM_Sergio_Orejon_2025
Trabajo Fin de Máster de Sergio Orejón Pérez desarrollado para el máster en Ciberseguridad de UNIR (Universidad Internacional de la Rioja).

Herramienta para auditar dispositivos IoT (Internet of Things) desarrollada en python que integra búsqueda de los dispositivos a través de la API de Shodan, escaneos de puertos a través de Nmap y ataques de credenciales a través de Hydra.

Este software ha sido desarrollado exclusivamente con fines educativos. No se permite su uso en entornos reales sin autorización expresa.

Requisitos para la ejecución:
-Sistema operativo Linux, especialmente los que tengan Hydra preinstalado (Kali Linux).

-Clave API de Shodan con cuenta de pago para realizar búsquedas.

-Disponer de diccionarios de contraseñas con el formato establecido (en la carpeta diccionarios se encuentran algunos que se pueden utilizar).

Guía de instalación
Paso 1: Descargar o clonar el repositorio.
 ```
git clone https://github.com/SergioOrejon/TFM_Sergio_Orejon_2025.git
cd TFM_Sergio_Orejon_2025
```

Paso 2: Crear un venv e instalar las librerías necesarias, hay algunas distribuciones linux que no es necesario hacer uso del venv, con solo instalar los requirements y ejecutar el main.py funciona.
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Paso 3: Ejecutar (Antes de ejecutarlo, siempre hay que estar en el venv donde se han instalado los requirements)
```
python3 main.py
```

**Opcional** Paso 4: Si el programa no funciona antes de ejecutarlo por primera vez, instalar y crear un keyring en el sistema (ocurre en algunas Virtual Machines).
Una vez ejecutado reiniciar la máquina virtual y empezar por el paso 2.
```
sudo apt update
sudo apt install gnome-keyring dbus-user-session
eval "$(dbus-launch --sh-syntax)"
```
