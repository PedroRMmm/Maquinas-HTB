#!/usr/bin/env python3
"""
Asistente interactivo para CONSTRUIR (no ejecutar) comandos de nmap.

Guía al usuario pregunta por pregunta a través de cada categoría de opciones
de nmap (objetivo, descubrimiento de hosts, tipo de escaneo, puertos,
detección de versión/SO, scripts NSE, timing, evasión de firewall, salida)
mostrando para cada opción una descripción y un caso de uso, y va mostrando
el comando resultante paso a paso. Basado en el "Nmap Cheat Sheet" (Comparitech).

Este script NUNCA ejecuta nmap: solo imprime el comando final para que
el usuario lo copie y lo ejecute él mismo cuando quiera.
"""

import re
import sys

RULE = "-" * 72


def header(title):
    print("\n" + RULE)
    print(f" {title}")
    print(RULE)


def build_command(parts, target):
    tgt = target if target else "<objetivo pendiente>"
    return " ".join(["nmap", *[p for p in parts if p], tgt])


def flags_so_far(parts):
    """Comando (sin objetivo) tal y como va quedando, para usarlo como
    prefijo del prompt y que el usuario siga escribiendo en continuación."""
    return " ".join(["nmap", *[p for p in parts if p]])


def print_command(parts, target):
    print(f"\n>>> Comando hasta ahora:\n    {build_command(parts, target)}\n")


def ask_raw(prompt, default=None, allow_empty=False):
    while True:
        val = input(prompt).strip()
        if val:
            return val
        if default is not None:
            return default
        if allow_empty:
            return ""
        print("  (Este dato es obligatorio, intenta de nuevo)")


def show_options(options):
    for i, opt in enumerate(options, start=1):
        flag_part = f"[{i}] {opt['flag']}  -  {opt['name']}" if opt['flag'] else f"[{i}] {opt['name']}"
        print(f"\n{flag_part}")
        print(f"    Descripción : {opt['desc']}")
        print(f"    Cuándo usarlo: {opt['usecase']}")


def run_stage(title, intro, options, prefix, allow_skip=True):
    """Muestra un bloque de opciones como referencia (descripción y caso de
    uso) y deja que el usuario continúe escribiendo él mismo, en el mismo
    orden en que escribiría el comando a mano, los flags de esta sección.
    El prompt muestra el comando tal y como va quedando hasta ahora, y lo
    que se escriba se añade justo a continuación. Enter vacío omite la
    sección por completo."""
    header(title)
    if intro:
        print(intro)
    show_options(options)
    print(
        "\nContinúa el comando escribiendo aquí los flags de esta sección "
        "(puedes escribir\nvarios, con sus valores). Deja vacío para omitir "
        "esta sección."
    )
    raw = ask_raw(f"{prefix} ", allow_empty=allow_skip)
    if not raw:
        return []
    return [raw]


def stage_target(prefix):
    header("10) Objetivo (target)")
    print(
        "Toca cerrar el comando con el objetivo, tal y como se hace siempre al "
        "final:\n"
        "    nmap [tipos de escaneo] [opciones] {especificación de objetivo}\n"
    )
    options = [
        {
            "flag": "172.16.1.1",
            "name": "IP única",
            "desc": "Escanea una sola dirección IP.",
            "usecase": "Cuando ya conoces el host exacto a analizar.",
        },
        {
            "flag": "172.16.1.1 172.16.100.1",
            "name": "Varias IPs sueltas",
            "desc": "Lista de direcciones IP separadas por espacios.",
            "usecase": "Cuando tienes un puñado de hosts concretos, no un rango.",
        },
        {
            "flag": "172.16.1.1-254",
            "name": "Rango de IPs",
            "desc": "Escanea un rango continuo dentro del último octeto (o varios).",
            "usecase": "Redes pequeñas/medianas donde quieres cubrir un tramo completo.",
        },
        {
            "flag": "10.1.1.0/8",
            "name": "Notación CIDR",
            "desc": "Escanea toda la subred indicada por la máscara CIDR.",
            "usecase": "Escaneos de red completos, más compacto que un rango largo.",
        },
        {
            "flag": "xyz.org",
            "name": "Dominio",
            "desc": "nmap resuelve el nombre de dominio a IP y lo escanea.",
            "usecase": "Cuando solo tienes el nombre de dominio, no la IP.",
        },
        {
            "flag": "-iL scan.txt",
            "name": "Lista desde archivo",
            "desc": "Lee los objetivos desde un fichero de texto (uno por línea).",
            "usecase": "Escaneos masivos o repetibles con una lista ya preparada.",
        },
    ]
    show_options(options)
    print(
        "\nContinúa el comando escribiendo tu objetivo (IP/rango/dominio) al "
        "final, tal cual lo harías siempre."
    )
    while True:
        target = ask_raw(f"{prefix} ")
        if target:
            break
        print("  El objetivo no puede quedar vacío, intenta de nuevo.")

    if _looks_like_multi_host(target):
        exclude = ask_raw(
            "Tu objetivo parece abarcar varios hosts. ¿Quieres excluir alguna "
            "IP/rango? (--exclude). Déjalo vacío si no aplica: ",
            allow_empty=True,
        )
        if exclude:
            target = f"{target} --exclude {exclude}"
    return target


def _looks_like_multi_host(target):
    """Heurística simple para saber si el objetivo escrito representa varios
    hosts (rango, CIDR, lista de archivo o varias IPs), caso en el que tiene
    sentido preguntar por --exclude. Una IP única o un dominio no lo activan."""
    t = target.strip()
    if not t:
        return False
    if "/" in t:
        return True
    if re.search(r"\d+-\d+", t):
        return True
    if t.lower().startswith("-il"):
        return True
    if "," in t or " " in t:
        return True
    return False


def stage_discovery(prefix):
    intro = (
        "El descubrimiento de hosts decide QUÉ hosts se consideran 'vivos' antes de\n"
        "escanear puertos. Puedes combinar varias sondas (multi-selección)."
    )
    options = [
        {
            "flag": "-sL",
            "name": "List scan",
            "desc": "Solo lista los objetivos a escanear, sin enviar ningún paquete.",
            "usecase": "Verificar que la especificación de objetivos (rango/CIDR/DNS) es la que quieres antes de lanzar nada real.",
        },
        {
            "flag": "-sn",
            "name": "Ping scan (sin escaneo de puertos)",
            "desc": "Descubre qué hosts están activos pero NO escanea puertos.",
            "usecase": "Inventariar hosts vivos en una red rápidamente, sin tocar puertos.",
        },
        {
            "flag": "-Pn",
            "name": "Sin descubrimiento (asume todo vivo)",
            "desc": "Se salta la fase de descubrimiento y trata todos los hosts como activos.",
            "usecase": "Cuando el firewall bloquea ping/ICMP y nmap descartaría hosts que en realidad están arriba.",
        },
        {
            "flag": "-PS",
            "name": "TCP SYN discovery en puertos concretos",
            "desc": "Envía SYN a los puertos indicados para ver si el host responde.",
            "usecase": "Descubrir hosts detrás de firewalls que bloquean ICMP pero permiten ciertos puertos TCP.",
        },
        {
            "flag": "-PA",
            "name": "TCP ACK discovery en puertos concretos",
            "desc": "Envía ACK a los puertos indicados; útil para atravesar ciertos firewalls con estado.",
            "usecase": "Alternativa a -PS cuando el firewall filtra SYN pero no ACK.",
        },
        {
            "flag": "-PU",
            "name": "UDP discovery en un puerto",
            "desc": "Envía sondas UDP al puerto indicado para provocar respuesta ICMP 'port unreachable'.",
            "usecase": "Detectar hosts que solo responden a tráfico UDP (algunos firewalls dejan pasar UDP y bloquean TCP/ICMP).",
        },
        {
            "flag": "-PR",
            "name": "ARP discovery (red local)",
            "desc": "Usa ARP en lugar de IP para descubrir hosts en la misma red local.",
            "usecase": "Escaneos dentro de la LAN: es el método más rápido y fiable en red local.",
        },
        {
            "flag": "-n",
            "name": "Sin resolución DNS",
            "desc": "Nunca hace resolución DNS inversa de las IPs.",
            "usecase": "Acelerar el escaneo cuando no necesitas nombres de host, solo IPs.",
        },
    ]
    return run_stage("1) Descubrimiento de hosts", intro, options, prefix)


def stage_scan_type(prefix):
    intro = (
        "El tipo de escaneo define CÓMO se sondean los puertos (qué tipo de\n"
        "paquete se envía). Normalmente se elige uno solo."
    )
    options = [
        {
            "flag": "-sS",
            "name": "TCP SYN scan",
            "desc": "Envía SYN y analiza la respuesta sin completar el handshake ('half-open').",
            "usecase": "El escaneo por defecto y más usado: rápido y más sigiloso. Requiere privilegios de root/admin.",
        },
        {
            "flag": "-sT",
            "name": "TCP connect scan",
            "desc": "Completa el handshake TCP completo usando las llamadas de sistema normales.",
            "usecase": "Cuando no tienes privilegios de root para usar -sS, o escaneas desde un entorno restringido.",
        },
        {
            "flag": "-sA",
            "name": "TCP ACK scan",
            "desc": "Envía solo paquetes ACK; no determina puertos abiertos, sino reglas de firewall.",
            "usecase": "Mapear qué puertos están filtrados por un firewall (stateful vs stateless), no para encontrar puertos abiertos.",
        },
        {
            "flag": "-sU",
            "name": "UDP scan",
            "desc": "Escanea puertos UDP en lugar de TCP.",
            "usecase": "Servicios como DNS(53), SNMP(161) o DHCP corren sobre UDP y no se ven con un escaneo TCP normal. Es más lento.",
        },
        {
            "flag": "-sF",
            "name": "TCP FIN scan",
            "desc": "Envía un paquete con solo el flag FIN activado.",
            "usecase": "Intentar pasar desapercibido ante firewalls/IDS simples que solo filtran SYN.",
        },
        {
            "flag": "-sX",
            "name": "XMAS scan",
            "desc": "Envía un paquete con los flags FIN, PSH y URG activados a la vez.",
            "usecase": "Igual que FIN scan: técnica de evasión de firewalls/IDS antiguos; no funciona contra Windows.",
        },
        {
            "flag": "-sL",
            "name": "List scan",
            "desc": "Solo lista los hosts a escanear, no envía ningún paquete.",
            "usecase": "Comprobar la lista de objetivos resultante de un rango/CIDR/dominio antes de escanear de verdad.",
        },
    ]
    return run_stage("2) Tipo de escaneo (scan type)", intro, options, prefix)


def stage_ports(prefix):
    intro = (
        "Qué puertos se van a analizar. Si no eliges nada, nmap escanea por\n"
        "defecto los 1000 puertos más comunes."
    )
    options = [
        {
            "flag": "-p",
            "name": "Puerto específico",
            "desc": "Escanea un único puerto concreto.",
            "usecase": "Ya sabes exactamente qué puerto/servicio te interesa (ej: comprobar si el 3389 de RDP está abierto).",
        },
        {
            "flag": "-p",
            "name": "Rango de puertos",
            "desc": "Escanea un rango continuo de puertos.",
            "usecase": "Quieres cubrir un tramo concreto sin ir a los 65535 completos (ej: 23-100).",
        },
        {
            "flag": "-p",
            "name": "Puertos mixtos TCP/UDP",
            "desc": "Especifica puertos distintos para UDP (U:) y TCP (T:) en la misma pasada.",
            "usecase": "Cuando quieres revisar a la vez un puerto UDP típico (DNS/SNMP) y varios TCP en un solo comando.",
        },
        {
            "flag": "-p-",
            "name": "Todos los puertos (1-65535)",
            "desc": "Escanea absolutamente todos los puertos TCP.",
            "usecase": "Auditorías completas o cuando sospechas que hay un servicio en un puerto no estándar. Es lento.",
        },
        {
            "flag": "-F",
            "name": "Escaneo rápido (Fast)",
            "desc": "Escanea solo los 100 puertos más comunes en lugar de los 1000 por defecto.",
            "usecase": "Reconocimiento rápido cuando la velocidad importa más que la cobertura.",
        },
        {
            "flag": "-p",
            "name": "Por nombre de servicio/protocolo",
            "desc": "Selecciona puertos por su nombre en nmap-services en vez de por número.",
            "usecase": "Más legible cuando buscas servicios concretos, ej. http, https, smtp.",
        },
        {
            "flag": "-r",
            "name": "Orden secuencial de puertos",
            "desc": "Escanea los puertos en orden numérico en lugar de aleatorizarlos.",
            "usecase": "Cuando necesitas resultados reproducibles/ordenados, por ejemplo para comparar salidas entre escaneos.",
        },
    ]
    return run_stage("3) Especificación de puertos", intro, options, prefix)


def stage_version_os(prefix):
    intro = "Detección de versión de servicios y de sistema operativo."
    options = [
        {
            "flag": "-sV",
            "name": "Detección de versión",
            "desc": "Intenta determinar la versión del servicio que corre en cada puerto abierto.",
            "usecase": "Saber exactamente qué software/versión corre para buscar vulnerabilidades conocidas.",
        },
        {
            "flag": "--version-intensity",
            "name": "Intensidad de detección de versión",
            "desc": "Ajusta cuántas sondas se prueban, de 0 (ligero) a 9 (exhaustivo).",
            "usecase": "Subir la intensidad cuando -sV no identifica bien el servicio; bajarla para ir más rápido.",
        },
        {
            "flag": "--version-light",
            "name": "Modo ligero",
            "desc": "Equivalente rápido a una intensidad baja de detección de versión.",
            "usecase": "Reconocimientos rápidos donde no necesitas precisión total en las versiones.",
        },
        {
            "flag": "--version-all",
            "name": "Máxima intensidad (9)",
            "desc": "Prueba todas las firmas disponibles para identificar la versión.",
            "usecase": "Cuando necesitas la identificación más precisa posible y el tiempo no es problema.",
        },
        {
            "flag": "-O",
            "name": "Detección de sistema operativo",
            "desc": "Intenta identificar el SO remoto mediante fingerprinting de la pila TCP/IP.",
            "usecase": "Saber si el objetivo es Windows/Linux/etc. para orientar la explotación o el hardening.",
        },
        {
            "flag": "-A",
            "name": "Modo agresivo",
            "desc": "Activa a la vez detección de SO, de versión, scripts NSE por defecto y traceroute.",
            "usecase": "Reconocimiento completo en un solo flag; más ruidoso y lento, ideal cuando el sigilo no es prioridad.",
        },
    ]
    return run_stage("4) Detección de versión / sistema operativo", intro, options, prefix)


def stage_scripts(prefix):
    intro = (
        "El motor de scripts NSE (Nmap Scripting Engine) permite automatizar\n"
        "detección de vulnerabilidades, enumeración, etc."
    )
    options = [
        {
            "flag": "-sC",
            "name": "Scripts por defecto (seguros)",
            "desc": "Ejecuta el conjunto de scripts NSE marcados como 'default', considerados seguros.",
            "usecase": "Enumeración estándar sin riesgo de tumbar el servicio objetivo.",
        },
        {
            "flag": "--script=",
            "name": "Ejecutar script(s) o categoría concreta",
            "desc": "Ejecuta un script NSE, una categoría (ej: vuln, safe, auth) o una lista separada por comas.",
            "usecase": "Buscar algo específico, ej. --script=vuln para probar vulnerabilidades conocidas.",
        },
        {
            "flag": "--script-update-db",
            "name": "Actualizar la base de datos de scripts",
            "desc": "Reconstruye la base de datos de scripts NSE tras añadir/quitar scripts.",
            "usecase": "Después de instalar scripts NSE nuevos manualmente en el sistema.",
        },
        {
            "flag": "--script-help=",
            "name": "Ayuda de un script",
            "desc": "Muestra la documentación de uso de un script concreto.",
            "usecase": "Antes de usar un script poco conocido, para entender qué hace y qué argumentos acepta.",
        },
    ]
    return run_stage("5) Scripts NSE", intro, options, prefix)


def stage_timing(prefix):
    intro = (
        "Controla la velocidad/agresividad del escaneo. Más rápido = más ruido\n"
        "y más probabilidad de saturar la red o ser detectado por un IDS."
    )
    options = [
        {
            "flag": "-T0",
            "name": "Paranoid",
            "desc": "El escaneo más lento posible, con grandes pausas entre paquetes.",
            "usecase": "Evasión máxima de IDS; solo viable cuando el tiempo no importa en absoluto.",
        },
        {
            "flag": "-T1",
            "name": "Sneaky",
            "desc": "Muy lento, pensado para evitar sistemas de detección de intrusos.",
            "usecase": "Entornos con IDS sensible donde quieres pasar lo más desapercibido posible.",
        },
        {
            "flag": "-T2",
            "name": "Polite",
            "desc": "Escaneo pausado, reduce el uso de ancho de banda y carga en el objetivo.",
            "usecase": "Redes sensibles/productivas donde no quieres afectar el rendimiento del host.",
        },
        {
            "flag": "-T3",
            "name": "Normal (por defecto)",
            "desc": "Velocidad por defecto de nmap si no se especifica timing.",
            "usecase": "Uso general cuando no hay restricciones especiales de tiempo o sigilo.",
        },
        {
            "flag": "-T4",
            "name": "Aggressive",
            "desc": "Escaneo rápido, asume una red fiable y con buen ancho de banda.",
            "usecase": "El más usado en CTFs/laboratorios (como HTB) para ir rápido sin ser extremo.",
        },
        {
            "flag": "-T5",
            "name": "Insane",
            "desc": "El escaneo más rápido posible, sacrifica precisión por velocidad.",
            "usecase": "Redes muy rápidas donde priorizas la velocidad total sobre la exactitud de resultados.",
        },
    ]
    return run_stage("6) Timing (velocidad del escaneo)", intro, options, prefix)


def stage_evasion(prefix):
    intro = (
        "Técnicas para intentar evadir firewalls e IDS, o para manipular\n"
        "cómo se ven los paquetes en la red."
    )
    options = [
        {
            "flag": "-f",
            "name": "Fragmentar paquetes",
            "desc": "Divide los paquetes de sondeo en fragmentos IP más pequeños.",
            "usecase": "Intentar evadir firewalls/IDS antiguos que no reensamblan fragmentos antes de inspeccionar.",
        },
        {
            "flag": "--mtu",
            "name": "MTU personalizada",
            "desc": "Fragmenta los paquetes usando el tamaño de MTU indicado (múltiplo de 8).",
            "usecase": "Control fino de la fragmentación cuando -f no es suficiente para evadir un dispositivo concreto.",
        },
        {
            "flag": "-sI",
            "name": "Idle / zombie scan",
            "desc": "Usa un host 'zombie' intermedio para que el escaneo parezca venir de él.",
            "usecase": "Escaneo totalmente anónimo/sigiloso usando un tercer host con IP-ID predecible.",
        },
        {
            "flag": "--source-port",
            "name": "Puerto de origen manual",
            "desc": "Fuerza el puerto de origen de los paquetes enviados.",
            "usecase": "Evadir firewalls mal configurados que confían en tráfico proveniente de un puerto concreto (ej: 53 o 20).",
        },
        {
            "flag": "--data-length",
            "name": "Añadir datos aleatorios",
            "desc": "Añade bytes aleatorios al final de los paquetes para cambiar su tamaño/firma.",
            "usecase": "Dificultar que un IDS/firewall identifique el tráfico de nmap por su tamaño característico.",
        },
        {
            "flag": "--randomize-hosts",
            "name": "Aleatorizar orden de hosts",
            "desc": "Escanea los hosts objetivo en orden aleatorio en vez de secuencial.",
            "usecase": "Evitar patrones obvios en logs cuando escaneas muchos hosts de una red.",
        },
        {
            "flag": "--badsum",
            "name": "Checksum inválido",
            "desc": "Envía paquetes con checksum TCP/UDP incorrecto a propósito.",
            "usecase": "Comprobar si hay un firewall/IDS que responde igualmente (señal de que no valida checksums), útil para pruebas de integridad de la pila.",
        },
    ]
    return run_stage("7) Evasión de firewall/IDS", intro, options, prefix)


def stage_misc(prefix):
    intro = "Opciones adicionales sueltas pero útiles."
    options = [
        {
            "flag": "-6",
            "name": "Escanear IPv6",
            "desc": "Indica a nmap que el objetivo es una dirección/rango IPv6.",
            "usecase": "Cuando el objetivo tiene dirección IPv6 en vez de IPv4.",
        },
        {
            "flag": "--proxies",
            "name": "Usar proxies",
            "desc": "Enruta las conexiones del escaneo a través de una lista de proxies (HTTP/SOCKS4).",
            "usecase": "Anonimizar o encadenar el origen del escaneo a través de uno o varios proxies.",
        },
        {
            "flag": "--open",
            "name": "Mostrar solo puertos abiertos",
            "desc": "Filtra la salida para mostrar únicamente los puertos abiertos.",
            "usecase": "Reducir ruido visual en escaneos grandes donde solo te interesa lo que está abierto.",
        },
        {
            "flag": "--traceroute",
            "name": "Traceroute",
            "desc": "Traza la ruta de red hacia el objetivo, salto a salto.",
            "usecase": "Entender la topología de red hacia el host, o diagnosticar por qué un host no responde.",
        },
    ]
    return run_stage("8) Opciones varias", intro, options, prefix)


def stage_output(prefix):
    intro = "Cómo se guardan los resultados del escaneo en disco."
    options = [
        {
            "flag": "-oN",
            "name": "Formato normal",
            "desc": "Guarda la salida tal y como se ve en pantalla, en un fichero de texto.",
            "usecase": "Guardar un registro legible del escaneo para consultarlo después.",
        },
        {
            "flag": "-oX",
            "name": "Formato XML",
            "desc": "Guarda la salida en XML, estructurada y fácil de parsear por otras herramientas.",
            "usecase": "Importar los resultados en otra herramienta (ej: Metasploit, un script propio, un dashboard).",
        },
        {
            "flag": "-oG",
            "name": "Formato grepable",
            "desc": "Guarda la salida en un formato de una línea por host, fácil de usar con grep/awk.",
            "usecase": "Procesar resultados rápidamente con herramientas de línea de comandos clásicas.",
        },
        {
            "flag": "-oA",
            "name": "Todos los formatos a la vez",
            "desc": "Guarda simultáneamente en normal, XML y grepable usando el mismo nombre base.",
            "usecase": "Cuando no sabes cuál necesitarás después y prefieres tenerlos todos.",
        },
    ]
    return run_stage("9) Formato de salida", intro, options, prefix)


NEEDS_VALUE = {
    "-p": "puertos (ej: -p 22,80,443 o -p 1-65535)",
    "-oN": "un nombre de archivo (ej: -oN scan.txt)",
    "-oX": "un nombre de archivo (ej: -oX scan.xml)",
    "-oG": "un nombre de archivo (ej: -oG scan.gnmap)",
    "-oA": "un nombre base de archivo (ej: -oA scan)",
    "--mtu": "un valor numérico múltiplo de 8 (ej: --mtu 24)",
    "-sI": "un host zombie (ej: -sI 172.16.1.1)",
    "--source-port": "un puerto (ej: --source-port 53)",
    "--data-length": "un tamaño en bytes (ej: --data-length 25)",
    "--script": "un nombre de script o categoría (ej: --script vuln)",
    "--script=": "un nombre de script o categoría (ej: --script=vuln)",
    "--script-help": "un nombre de script (ej: --script-help http-title)",
    "--script-help=": "un nombre de script (ej: --script-help=http-title)",
    "--proxies": "una o varias URLs de proxy",
    "--version-intensity": "un número de 0 a 9",
    "-PS": "uno o varios puertos (ej: -PS22,25,80)",
    "-PA": "uno o varios puertos (ej: -PA22,25,80)",
    "-PU": "un puerto (ej: -PU53)",
}


def check_missing_values(parts):
    """Detecta flags que necesitan un valor detrás (ej: -oG, -p, --mtu) y que
    se han quedado sin él. Es el fallo típico que hace que nmap se coma el
    objetivo como si fuera el valor de ese flag y acabe sin escanear nada."""
    tokens = [tok for p in parts for tok in p.split()]
    warnings = []
    for i, tok in enumerate(tokens):
        if tok in NEEDS_VALUE:
            nxt = tokens[i + 1] if i + 1 < len(tokens) else None
            if nxt is None or nxt.startswith("-"):
                warnings.append((tok, NEEDS_VALUE[tok]))
    return warnings


def print_final(parts, target):
    header("COMANDO FINAL")
    print(build_command(parts, target))

    warnings = check_missing_values(parts)
    if warnings:
        print("\n⚠ AVISO: estos flags necesitan un valor justo después y no lo tienen:")
        for flag, hint in warnings:
            print(f"  - '{flag}' necesita {hint}")
        print(
            "  Si los dejas así, nmap puede coger tu objetivo como si fuera ese\n"
            "  valor y quedarse sin nada que escanear. Corrígelo antes de ejecutar."
        )

    print(
        "\nCopia este comando y ejecútalo tú mismo cuando quieras.\n"
        "Este script no lo ha ejecutado ni lo ejecutará."
    )


# ---------------------------------------------------------------------------
# Escenarios típicos de un reconocimiento en HTB (plantillas preconfiguradas)
# ---------------------------------------------------------------------------

HTB_SCENARIOS = [
    {
        "name": "Escaneo estándar rápido (top 1000 puertos + versión/scripts)",
        "flags": ["-sC", "-sV", "-T4", "-Pn"],
        "desc": "Escanea los 1000 puertos TCP más comunes con detección de versión y los scripts NSE por defecto.",
        "when": "Punto de partida más habitual cuando llegas a una máquina nueva de HTB: suele bastar en la mayoría de máquinas fáciles/medias, ya que el servicio importante está casi siempre en un puerto común.",
        "needs_ports": False,
    },
    {
        "name": "Fase 1: descubrir TODOS los puertos TCP abiertos",
        "flags": ["-p-", "-T4", "-Pn"],
        "desc": "Escanea los 65535 puertos TCP sin detección de versión, solo para saber cuáles están abiertos.",
        "when": "Primer paso del flujo de dos fases: muchas máquinas de HTB esconden un servicio en un puerto no estándar que el escaneo top-1000 no vería. Es rápido porque no analiza versiones ni scripts.",
        "needs_ports": False,
    },
    {
        "name": "Fase 2: escaneo detallado sobre los puertos ya encontrados",
        "flags": ["-sC", "-sV", "-T4", "-Pn", "-p", "{PORTS}"],
        "desc": "Detección de versión + scripts por defecto, limitado solo a los puertos abiertos que ya conoces.",
        "when": "Segundo paso típico tras la Fase 1: profundizas solo en los puertos reales para no perder tiempo re-escaneando los 65535. Es el 'nmap -sC -sV -p<puertos> <ip>' que aparece en casi todos los write-ups de HTB.",
        "needs_ports": True,
        "port_prompt": "Puertos abiertos que encontraste antes (ej: 22,80,443)",
    },
    {
        "name": "Escaneo UDP rápido (top puertos)",
        "flags": ["-sU", "--top-ports", "20", "-T4"],
        "desc": "Escanea los 20 puertos UDP más comunes en lugar de TCP.",
        "when": "Cuando el escaneo TCP no da nada interesante, o quieres comprobar servicios típicos en UDP como DNS(53), SNMP(161) o TFTP(69). Un escaneo UDP completo es muy lento, por eso se limita a los top puertos.",
        "needs_ports": False,
    },
    {
        "name": "Búsqueda de vulnerabilidades conocidas (scripts vuln)",
        "flags": ["--script", "vuln", "-sV", "-T4", "-Pn", "-p", "{PORTS}"],
        "desc": "Ejecuta los scripts NSE de la categoría 'vuln' contra los puertos indicados.",
        "when": "Una vez identificados los servicios (Fase 2), lanzas los scripts de detección de vulnerabilidades conocidas para buscar un vector de entrada rápido. Puede ser ruidoso y tardar.",
        "needs_ports": True,
        "port_prompt": "Puertos sobre los que buscar vulnerabilidades (ej: 22,80,443)",
    },
    {
        "name": "Todo en uno, agresivo (sin dividir en fases)",
        "flags": ["-A", "-T4", "-p-", "-Pn"],
        "desc": "Combina detección de SO, de versión, scripts por defecto y traceroute, sobre todos los puertos.",
        "when": "Cuando tienes ancho de banda/tiempo de sobra y prefieres un único comando en vez de ir por fases; más lento y más ruidoso, pero cómodo en máquinas fáciles donde el sigilo no importa.",
        "needs_ports": False,
    },
]


def parse_ports_from_output(text):
    """Extrae puertos abiertos de una salida de nmap ya generada por el
    usuario (formato normal -oN o grepable -oG). Solo LEE texto, no ejecuta
    nada."""
    ports = []
    seen = set()

    for match in re.finditer(r"^(\d+)/(?:tcp|udp)\s+(open\S*)", text, re.MULTILINE):
        port, state = match.groups()
        if state.startswith("open") and port not in seen:
            seen.add(port)
            ports.append(port)

    for line in text.splitlines():
        if line.startswith("Host:") and "Ports:" in line:
            after = line.split("Ports:", 1)[1]
            for entry in after.split(","):
                fields = entry.strip().split("/")
                if len(fields) >= 2 and fields[1].startswith("open") and fields[0]:
                    if fields[0] not in seen:
                        seen.add(fields[0])
                        ports.append(fields[0])

    return ports


def run_chained_flow():
    header("Flujo encadenado: Fase 1 automática -> extraer puertos -> Fase 2 + fine tuning")
    print(
        "Genero el comando de la Fase 1 (todos los puertos TCP) guardando el\n"
        "resultado en un archivo. TÚ lo ejecutas en tu terminal, fuera de esta\n"
        "herramienta. Cuando tengas el archivo, esta herramienta lo LEE (no\n"
        "ejecuta nada) para sacar los puertos abiertos y montarte la Fase 2\n"
        "automáticamente, lista para seguir afinándola."
    )

    default_file = "allports.txt"
    out_file = ask_raw(
        f"\nNombre de archivo para guardar el resultado de la Fase 1 (Enter = {default_file}): ",
        default=default_file,
        allow_empty=True,
    ) or default_file

    fase1 = ["-p-", "-T4", "-Pn", "-oN", out_file]
    target = stage_target(flags_so_far(fase1))
    print("\n--- Fase 1 ---")
    print_command(fase1, target)
    print(">>> Ejecuta TÚ ese comando en tu terminal. Cuando termine, vuelve aquí.\n")

    ports = []
    while True:
        path = ask_raw(
            "Ruta del archivo de resultados ya generado (Enter para escribir los\n"
            "puertos a mano en su lugar): ",
            allow_empty=True,
        )
        if not path:
            manual = ask_raw("Escribe los puertos abiertos manualmente (ej: 22,80,443): ")
            ports = [p.strip() for p in manual.split(",") if p.strip()]
            break
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError as e:
            print(f"  No se pudo leer ese archivo ({e}). Intenta de nuevo.")
            continue
        found = parse_ports_from_output(content)
        if not found:
            print("  No se detectaron puertos abiertos en ese archivo.")
            retry = ask_raw(
                "¿Quieres probar otra ruta? (S/n): ", allow_empty=True
            ).strip().lower()
            if retry.startswith("n"):
                manual = ask_raw("Escribe los puertos abiertos manualmente (ej: 22,80,443): ")
                ports = [p.strip() for p in manual.split(",") if p.strip()]
                break
            continue
        print(f"  Puertos abiertos detectados en el archivo: {', '.join(found)}")
        ports = found
        break

    parts = ["-sC", "-sV", "-T4", "-Pn", "-p", ",".join(ports)]
    print("\n--- Fase 2 (generada a partir de los puertos encontrados) ---")
    print_command(parts, target)

    refine = ask_raw(
        "\n¿Quieres afinar más la Fase 2 (evasión de firewall, opciones extra o\n"
        "formato de salida)? (s/N): ",
        allow_empty=True,
    ).strip().lower()
    if refine.startswith("s"):
        parts.extend(stage_evasion(flags_so_far(parts)))
        print_command(parts, target)
        parts.extend(stage_misc(flags_so_far(parts)))
        print_command(parts, target)
        parts.extend(stage_output(flags_so_far(parts)))
        print_command(parts, target)

    print_final(parts, target)


def run_htb_scenarios():
    header("Escenarios típicos de reconocimiento en HTB")
    print(
        "Plantillas con las combinaciones de opciones más habituales en un\n"
        "flujo de reconocimiento de Hack The Box, en el orden en que se suelen\n"
        "usar. Elige una y solo te preguntaré lo mínimo (objetivo y, si hace\n"
        "falta, los puertos)."
    )
    for i, sc in enumerate(HTB_SCENARIOS, start=1):
        base = " ".join(sc["flags"]).replace("{PORTS}", "<puertos>")
        print(f"\n[{i}] {sc['name']}")
        print(f"    Comando base : nmap {base} <objetivo>")
        print(f"    Qué hace     : {sc['desc']}")
        print(f"    Cuándo usarlo: {sc['when']}")

    chained_idx = len(HTB_SCENARIOS) + 1
    print(f"\n[{chained_idx}] Flujo encadenado: Fase 1 automática -> extrae puertos del archivo -> Fase 2 + fine tuning")
    print("    Qué hace     : Genera la Fase 1 con salida a archivo; cuando la ejecutes tú, lee ese archivo, saca los puertos reales y arma la Fase 2 sola.")
    print("    Cuándo usarlo: Cuando no quieres copiar puertos a mano entre fases y prefieres que se detecten del resultado real del escaneo.")

    raw = ask_raw("\nElige una opción por número: ")
    while not (raw.isdigit() and 1 <= int(raw) <= chained_idx):
        raw = ask_raw("Opción inválida, elige un número de la lista: ")
    choice = int(raw)

    if choice == chained_idx:
        run_chained_flow()
        return

    scenario = HTB_SCENARIOS[choice - 1]

    parts = []
    for tok in scenario["flags"]:
        if tok == "{PORTS}":
            ports = ask_raw(f"{scenario['port_prompt']}: ")
            parts.append(ports)
        else:
            parts.append(tok)

    target = stage_target(flags_so_far(parts))
    print_command(parts, target)

    refine = ask_raw(
        "\n¿Quieres afinar más el comando (evasión de firewall, opciones\n"
        "extra o formato de salida)? (s/N): ",
        allow_empty=True,
    ).strip().lower()

    if refine.startswith("s"):
        parts.extend(stage_evasion(flags_so_far(parts)))
        print_command(parts, target)
        parts.extend(stage_misc(flags_so_far(parts)))
        print_command(parts, target)
        parts.extend(stage_output(flags_so_far(parts)))
        print_command(parts, target)

    print_final(parts, target)


def run_guided_wizard():
    parts = []

    stages = [
        stage_discovery,
        stage_scan_type,
        stage_ports,
        stage_version_os,
        stage_scripts,
        stage_timing,
        stage_evasion,
        stage_misc,
        stage_output,
    ]

    for fn in stages:
        new_tokens = fn(flags_so_far(parts))
        parts.extend(new_tokens)
        print_command(parts, "")

    target = stage_target(flags_so_far(parts))
    print_final(parts, target)


def main():
    print(RULE)
    print(" ASISTENTE INTERACTIVO PARA CONSTRUIR COMANDOS NMAP")
    print(" (no ejecuta nada, solo te ayuda a escribir el comando paso a paso)")
    print(RULE)

    print("\n¿Cómo quieres construir el comando?\n")
    print(
        "[1] Modo guiado completo - repasa TODAS las categorías de opciones,\n"
        "    una a una (ideal para aprender nmap a fondo)."
    )
    print(
        "[2] Escenarios típicos de HTB - plantillas preconfiguradas para los\n"
        "    pasos habituales de un reconocimiento (más rápido)."
    )
    mode = ask_raw("\nElige un modo (1/2): ")
    while mode not in ("1", "2"):
        mode = ask_raw("Opción inválida, elige 1 o 2: ")

    if mode == "2":
        run_htb_scenarios()
    else:
        run_guided_wizard()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n\nCancelado por el usuario.")
        sys.exit(0)
