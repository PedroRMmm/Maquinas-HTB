# Wizards HTB

Asistentes interactivos que **construyen** (nunca ejecutan) comandos de las
herramientas más habituales en máquinas de Hack The Box. Cada script te muestra
las opciones sección por sección con su descripción y caso de uso, y tú vas
escribiendo el comando en continuación. Al final imprime el comando listo para
que lo copies y lo ejecutes tú mismo.

## Estructura

Una carpeta por herramienta:

```
Wizards/
├── nmap/
│   └── nmap_wizard.py            # Escaneo de puertos, versiones, NSE (nmap)
├── ffuf/
│   └── ffuf_wizard.py            # Fuzzing de directorios/parámetros/vhosts (ffuf)
├── nuclei/
│   └── nuclei_wizard.py          # Escaneo de vulnerabilidades web por plantillas (nuclei)
├── smbclient/
│   └── smbclient_wizard.py       # Listar/navegar/descargar de shares SMB (smbclient)
└── rpcclient/
    └── rpcclient_wizard.py       # Enumerar usuarios/grupos/dominio por RPC (rpcclient)
```

## Uso

```bash
python3 nmap/nmap_wizard.py
python3 ffuf/ffuf_wizard.py
python3 nuclei/nuclei_wizard.py
python3 smbclient/smbclient_wizard.py
python3 rpcclient/rpcclient_wizard.py
```

Ninguno de los scripts ejecuta la herramienta: solo te ayudan a escribir el
comando paso a paso. Cancela en cualquier momento con Ctrl+C.
