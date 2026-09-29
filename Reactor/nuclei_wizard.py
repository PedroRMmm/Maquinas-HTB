#!/usr/bin/env python3
"""
Asistente interactivo para CONSTRUIR (no ejecutar) comandos de nuclei.

Misma filosofía que nmap_wizard.py y ffuf_wizard.py: te muestra, sección por
sección, las opciones disponibles con su descripción y caso de uso, y TÚ vas
escribiendo el comando en continuación (el prompt te muestra lo que ya llevas
escrito y completas justo detrás), en el mismo orden en que lo escribirías a
mano: objetivo -> plantillas -> filtros -> cabeceras -> rendimiento -> salida
-> OOB/interactsh -> proxy -> opciones varias.

Incluye un selector de CATEGORÍAS DE PLANTILLAS (equivalente al selector de
SecLists de ffuf_wizard.py) según qué estés buscando: CVEs, exposiciones,
paneles expuestos, configuraciones erróneas, credenciales por defecto,
vulnerabilidades genéricas, tecnologías, subdomain takeovers...

Este script NUNCA ejecuta nuclei: solo construye el comando para que lo
copies y lo ejecutes tú mismo cuando quieras.
"""

import sys

RULE = "-" * 72


def header(title):
    print("\n" + RULE)
    print(f" {title}")
    print(RULE)


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
        flag_part = f"[{i}] {opt['flag']}  -  {opt['name']}" if opt["flag"] else f"[{i}] {opt['name']}"
        print(f"\n{flag_part}")
        print(f"    Descripción : {opt['desc']}")
        print(f"    Cuándo usarlo: {opt['usecase']}")


def flags_so_far(parts):
    return " ".join(["nuclei", *[p for p in parts if p]])


def build_command(parts):
    return " ".join(["nuclei", *[p for p in parts if p]])


def print_command(parts):
    print(f"\n>>> Comando hasta ahora:\n    {build_command(parts)}\n")


def run_stage(title, intro, options, prefix, allow_skip=True):
    """Muestra las opciones como referencia y deja que el usuario continúe
    escribiendo él mismo, en texto libre, los flags de esta sección tal
    cual irían en el comando. Enter vacío omite la sección."""
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
    header("1) Objetivo")
    print(
        "nuclei necesita saber contra qué probar las plantillas. La sintaxis\n"
        "general es:\n"
        "    nuclei -u <objetivo> -t <plantillas> [opciones]\n"
        "    nuclei -l <archivo con lista de objetivos> -t <plantillas> [opciones]\n"
    )
    options = [
        {
            "flag": "-u http://10.129.126.61:3000",
            "name": "URL/host único",
            "desc": "Escanea un solo objetivo (URL completa, o host:puerto).",
            "usecase": "Ya tienes un objetivo concreto localizado, como tras un nmap/ffuf.",
        },
        {
            "flag": "-u http://10.129.126.61:3000 -u http://10.129.126.61",
            "name": "Varios objetivos sueltos",
            "desc": "Repite -u tantas veces como objetivos quieras escanear a la vez.",
            "usecase": "Quieres lanzar el mismo set de plantillas contra 2-3 objetivos concretos.",
        },
        {
            "flag": "-l targets.txt",
            "name": "Lista de objetivos desde archivo",
            "desc": "Lee los objetivos de un fichero de texto, uno por línea.",
            "usecase": "Escaneo masivo, por ejemplo pasándole la salida de un subfinder/httpx previo.",
        },
        {
            "flag": "-l -",
            "name": "Objetivos por stdin",
            "desc": "Lee los objetivos desde la entrada estándar.",
            "usecase": "Encadenar herramientas: ej. httpx -l hosts.txt -silent | nuclei -l - -t http/cves/.",
        },
    ]
    show_options(options)
    while True:
        raw = ask_raw(f"{prefix} ")
        if "-u " in f" {raw}" or "-l " in f" {raw}" or raw.strip() in ("-u", "-l"):
            break
        print("  Falta -u (objetivo único) o -l (lista de objetivos); nuclei no sabe qué escanear sin uno de los dos.")
    return [raw]


TEMPLATE_CATEGORIES = [
    {
        "name": "CVEs conocidas",
        "usecase": "Ya identificaste una tecnología/versión concreta (ej. por -sV de nmap o cabeceras) y quieres ver si tiene CVEs con exploit público.",
        "examples": [
            ("-t http/cves/", "Todas las plantillas de CVEs."),
            ("-tags cve", "Alternativa por tag en vez de ruta."),
        ],
    },
    {
        "name": "Exposiciones (archivos, configs, backups, tokens)",
        "usecase": "Buscar .env, .git, backups, claves API filtradas, ficheros de configuración expuestos.",
        "examples": [
            ("-t http/exposures/", "Todas las plantillas de exposición de información."),
            ("-t http/exposures/configs/,http/exposures/backups/", "Solo configs y backups."),
        ],
    },
    {
        "name": "Paneles de administración expuestos",
        "usecase": "Detectar logins de administración (Grafana, Jenkins, phpMyAdmin, Next.js admin panels, etc.) accesibles sin protección.",
        "examples": [
            ("-t http/exposed-panels/", "Todas las plantillas de paneles expuestos."),
        ],
    },
    {
        "name": "Configuraciones erróneas (misconfiguration)",
        "usecase": "CORS mal configurado, directory listing, headers de seguridad ausentes, debug mode activado.",
        "examples": [
            ("-t http/misconfiguration/", "Todas las plantillas de misconfiguration."),
        ],
    },
    {
        "name": "Credenciales por defecto",
        "usecase": "Probar usuario/contraseña de fábrica en paneles conocidos (routers, CMS, dashboards de terceros).",
        "examples": [
            ("-t http/default-logins/", "Todas las plantillas de credenciales por defecto."),
        ],
    },
    {
        "name": "Vulnerabilidades genéricas (XSS, SQLi, SSRF, LFI, RCE...)",
        "usecase": "Barrido amplio de vulnerabilidades web comunes, no ligadas a un CVE concreto.",
        "examples": [
            ("-t http/vulnerabilities/", "Todas las plantillas de vulnerabilidades genéricas."),
            ("-tags xss,sqli,ssrf,lfi", "Solo esas familias concretas."),
        ],
    },
    {
        "name": "Fingerprinting de tecnologías",
        "usecase": "Identificar qué software/versión corre exactamente detrás del objetivo (para luego buscar CVEs a medida).",
        "examples": [
            ("-t http/technologies/", "Todas las plantillas de detección de tecnología."),
        ],
    },
    {
        "name": "Subdomain takeover",
        "usecase": "Cuando ya tienes subdominios (de un fuzzing DNS) y quieres ver si alguno apunta a un servicio abandonado.",
        "examples": [
            ("-t http/takeovers/", "Todas las plantillas de subdomain takeover."),
        ],
    },
    {
        "name": "Todo, filtrando solo por severidad",
        "usecase": "No sabes por dónde empezar: lanza TODO el repositorio pero quédate solo con lo grave.",
        "examples": [
            ("-t . -severity critical,high", "Todas las plantillas, solo críticas/altas."),
        ],
    },
]


def stage_templates(prefix):
    header("2) Selector de plantillas (-t / -tags)")
    print(
        "Elige la categoría de plantillas según qué estés buscando. Nuclei\n"
        "organiza sus plantillas oficiales por carpetas bajo ~/nuclei-templates/\n"
        "(se descargan solas la primera vez que ejecutas nuclei, o con -update-templates)."
    )
    for i, cat in enumerate(TEMPLATE_CATEGORIES, start=1):
        print(f"\n[{i}] {cat['name']}")
        print(f"    Cuándo usarlo: {cat['usecase']}")
        for flag, note in cat["examples"]:
            print(f"      - {flag}")
            print(f"        ({note})")

    print(
        "\nEscribe los flags de plantillas que quieras usar (copia uno de arriba\n"
        "o combina varios, ej: -t http/cves/ -t http/exposed-panels/). Deja vacío para usar\n"
        "el set de plantillas por defecto de nuclei (sin -t ni -tags)."
    )
    raw = ask_raw(f"{prefix} ", allow_empty=True)
    if not raw:
        return []
    return [raw]


def stage_filters(prefix):
    intro = "Filtros adicionales sobre qué plantillas se ejecutan."
    options = [
        {
            "flag": "-severity",
            "name": "Filtrar por severidad",
            "desc": "Solo ejecuta plantillas de la severidad indicada.",
            "usecase": "Reducir ruido, ej: -severity critical,high para ir directo a lo más grave.",
        },
        {
            "flag": "-etags",
            "name": "Excluir por tag",
            "desc": "Excluye plantillas que tengan ese tag.",
            "usecase": "Descartar categorías ruidosas o poco fiables, ej: -etags dos (denegación de servicio).",
        },
        {
            "flag": "-type",
            "name": "Filtrar por tipo de protocolo",
            "desc": "Limita a un tipo de plantilla: http, dns, tcp, ssl, file, headless, workflow.",
            "usecase": "Cuando solo te interesa un tipo concreto de comprobación, ej: -type http.",
        },
        {
            "flag": "-a",
            "name": "Filtrar por autor",
            "desc": "Solo ejecuta plantillas escritas por el autor indicado.",
            "usecase": "Cuando confías especialmente en las plantillas de un autor concreto.",
        },
        {
            "flag": "-etemplate",
            "name": "Excluir plantillas concretas",
            "desc": "Excluye archivos/rutas de plantilla concretos aunque coincidan con -t.",
            "usecase": "Tienes una categoría amplia activada pero una plantilla en concreto te da falsos positivos.",
        },
    ]
    return run_stage("3) Filtros de severidad/tipo/autor", intro, options, prefix)


def stage_headers(prefix):
    intro = "Cabeceras y variables personalizadas para las peticiones."
    options = [
        {
            "flag": "-H",
            "name": "Cabecera personalizada",
            "desc": "Añade una cabecera HTTP completa a cada petición (repetible).",
            "usecase": "Enviar cookies de sesión, tokens de auth, o el header de bypass que ya conoces, ej: -H 'Authorization: Bearer TOKEN'.",
        },
        {
            "flag": "-var",
            "name": "Variable personalizada",
            "desc": "Define una variable que las plantillas puedan usar (ej: {{user}}).",
            "usecase": "Plantillas que necesitan un dato variable concreto (usuario, dominio base, etc.).",
        },
    ]
    return run_stage("4) Cabeceras y variables", intro, options, prefix)


def stage_performance(prefix):
    intro = "Velocidad y agresividad del escaneo."
    options = [
        {
            "flag": "-rate-limit",
            "name": "Límite de peticiones por segundo",
            "desc": "Techo global de peticiones/segundo (150 por defecto).",
            "usecase": "Bajarlo en servicios sensibles/con rate-limiting; subirlo si el objetivo aguanta bien.",
        },
        {
            "flag": "-c",
            "name": "Concurrencia de plantillas",
            "desc": "Número de plantillas ejecutadas en paralelo.",
            "usecase": "Subir para ir más rápido con muchas plantillas activas; bajar para no saturar.",
        },
        {
            "flag": "-bulk-size",
            "name": "Hosts en paralelo por plantilla",
            "desc": "Cuántos hosts se analizan a la vez para cada plantilla.",
            "usecase": "Relevante sobre todo cuando escaneas muchos objetivos con -l.",
        },
        {
            "flag": "-timeout",
            "name": "Timeout por petición",
            "desc": "Segundos de espera antes de dar una petición por fallida (10 por defecto).",
            "usecase": "Subirlo si el objetivo responde lento; bajarlo para ir más rápido descartando cuelgues.",
        },
        {
            "flag": "-retries",
            "name": "Reintentos",
            "desc": "Número de reintentos para peticiones fallidas.",
            "usecase": "Subirlo en redes inestables para evitar falsos negativos por timeouts puntuales.",
        },
    ]
    return run_stage("5) Rendimiento", intro, options, prefix)


def stage_output(prefix):
    intro = "Cómo guardar los resultados."
    options = [
        {
            "flag": "-o",
            "name": "Archivo de salida",
            "desc": "Guarda los resultados (formato de texto normal) en el archivo indicado.",
            "usecase": "Conservar el resultado para revisarlo después.",
        },
        {
            "flag": "-je",
            "name": "Exportar a JSON",
            "desc": "Guarda los resultados en formato JSON Lines en el archivo indicado.",
            "usecase": "Procesar los resultados después con un script propio o pasarlos a otra herramienta.",
        },
        {
            "flag": "-markdown-export",
            "name": "Exportar a Markdown",
            "desc": "Guarda los resultados como informe en Markdown, uno por hallazgo.",
            "usecase": "Generar un informe legible rápido para incluir en un reporte.",
        },
        {
            "flag": "-sarif-export",
            "name": "Exportar a SARIF",
            "desc": "Guarda los resultados en formato SARIF (estándar para integraciones CI/CD).",
            "usecase": "Integrar los resultados en GitHub Code Scanning u otra herramienta que lea SARIF.",
        },
    ]
    return run_stage("6) Formato de salida", intro, options, prefix)


def stage_oob(prefix):
    intro = (
        "Interactsh permite detectar vulnerabilidades 'ciegas' (blind SSRF,\n"
        "blind XSS, blind RCE) que no muestran resultado directo en la\n"
        "respuesta, sino que provocan una conexión saliente a un servidor externo."
    )
    options = [
        {
            "flag": "-iserver",
            "name": "Servidor Interactsh propio",
            "desc": "Usa tu propio servidor Interactsh en vez del público de ProjectDiscovery.",
            "usecase": "Entornos sin salida a internet pública, o cuando quieres más control/privacidad sobre las callbacks.",
        },
        {
            "flag": "-itoken",
            "name": "Token de autenticación Interactsh",
            "desc": "Token para autenticarte contra tu servidor Interactsh propio.",
            "usecase": "Cuando tu servidor -iserver requiere autenticación.",
        },
    ]
    return run_stage("7) Detección OOB (Interactsh)", intro, options, prefix)


def stage_proxy(prefix):
    intro = "Enrutar el tráfico de nuclei a través de un proxy."
    options = [
        {
            "flag": "-proxy",
            "name": "Proxy HTTP/SOCKS",
            "desc": "Envía todas las peticiones a través del proxy indicado.",
            "usecase": "Interceptar y revisar cada petición en Burp Suite mientras nuclei escanea, ej: -proxy http://127.0.0.1:8080.",
        },
    ]
    return run_stage("8) Proxy", intro, options, prefix)


def stage_misc(prefix):
    intro = "Opciones adicionales útiles."
    options = [
        {
            "flag": "-silent",
            "name": "Modo silencioso",
            "desc": "Solo muestra los hallazgos, sin banner ni progreso.",
            "usecase": "Encadenar nuclei con otras herramientas o guardar salida limpia.",
        },
        {
            "flag": "-nc",
            "name": "Sin color",
            "desc": "Desactiva el color en la salida por terminal.",
            "usecase": "Cuando rediriges la salida a un archivo o la procesas con otro programa.",
        },
        {
            "flag": "-stats",
            "name": "Mostrar estadísticas",
            "desc": "Muestra progreso y estadísticas del escaneo mientras corre.",
            "usecase": "Escaneos largos donde quieres ver que sigue avanzando y cuánto queda.",
        },
        {
            "flag": "-v",
            "name": "Verbose",
            "desc": "Muestra más detalle de cada plantilla ejecutada.",
            "usecase": "Depurar por qué una plantilla concreta no está dando el resultado esperado.",
        },
        {
            "flag": "-irr",
            "name": "Incluir petición/respuesta completa",
            "desc": "Añade la petición y respuesta HTTP completas al resultado (con -je).",
            "usecase": "Necesitas la evidencia completa de la petición/respuesta para el informe.",
        },
        {
            "flag": "-dc",
            "name": "Desactivar clustering",
            "desc": "No agrupa plantillas similares en una sola petición optimizada.",
            "usecase": "Depuración fina cuando el clustering automático de nuclei oculta qué plantilla exacta disparó un hallazgo.",
        },
    ]
    return run_stage("9) Opciones varias", intro, options, prefix)


NEEDS_VALUE = {
    "-u": "una URL/host (ej: -u http://IP:3000)",
    "-l": "una ruta de archivo con la lista de objetivos (ej: -l targets.txt)",
    "-t": "una ruta/categoría de plantilla (ej: -t http/cves/)",
    "-tags": "uno o varios tags separados por coma (ej: -tags cve,rce)",
    "-etags": "uno o varios tags a excluir (ej: -etags dos)",
    "-severity": "severidades separadas por coma (ej: -severity critical,high)",
    "-type": "un tipo de protocolo (ej: -type http)",
    "-a": "un nombre de autor",
    "-etemplate": "una ruta de plantilla a excluir",
    "-H": "una cabecera completa (ej: -H 'Authorization: Bearer TOKEN')",
    "-var": "una variable en formato clave=valor",
    "-rate-limit": "un número (ej: -rate-limit 100)",
    "-c": "un número de hilos (ej: -c 25)",
    "-bulk-size": "un número (ej: -bulk-size 25)",
    "-timeout": "segundos (ej: -timeout 10)",
    "-retries": "un número (ej: -retries 1)",
    "-o": "un nombre de archivo de salida (ej: -o resultado.txt)",
    "-je": "un nombre de archivo (ej: -je resultado.json)",
    "-markdown-export": "una carpeta de salida (ej: -markdown-export reportes/)",
    "-sarif-export": "un nombre de archivo (ej: -sarif-export resultado.sarif)",
    "-iserver": "una URL de servidor Interactsh",
    "-itoken": "un token de autenticación",
    "-proxy": "una URL de proxy (ej: -proxy http://127.0.0.1:8080)",
}


def check_missing_values(parts):
    tokens = [tok for p in parts for tok in p.split()]
    warnings = []
    for i, tok in enumerate(tokens):
        if tok in NEEDS_VALUE:
            nxt = tokens[i + 1] if i + 1 < len(tokens) else None
            if nxt is None or (nxt.startswith("-") and not nxt[1:2].isdigit()):
                warnings.append((tok, NEEDS_VALUE[tok]))
    return warnings


def print_final(parts):
    header("COMANDO FINAL")
    cmd = build_command(parts)
    print(cmd)

    tokens = cmd.split()
    if "-u" not in tokens and "-l" not in tokens:
        print(
            "\n⚠ AVISO: no hay ningún '-u' ni '-l' en el comando. Sin un "
            "objetivo,\nnuclei no tiene nada que escanear y dará error al "
            "arrancar."
        )
    if "-t" not in tokens and "-tags" not in tokens and " -t " not in f" {cmd} " and "-t ." not in cmd:
        print(
            "\n⚠ AVISO: no parece haber ninguna plantilla seleccionada (-t o "
            "-tags).\nSin plantillas nuclei no ejecuta ninguna comprobación."
        )

    warnings = check_missing_values(parts)
    if warnings:
        print("\n⚠ AVISO: estos flags necesitan un valor justo después y no lo tienen:")
        for flag, hint in warnings:
            print(f"  - '{flag}' necesita {hint}")

    print(
        "\nCopia este comando y ejecútalo tú mismo cuando quieras.\n"
        "Este script no lo ha ejecutado ni lo ejecutará."
    )


def main():
    print(RULE)
    print(" ASISTENTE INTERACTIVO PARA CONSTRUIR COMANDOS NUCLEI")
    print(" (no ejecuta nada, solo te ayuda a escribir el comando paso a paso)")
    print(RULE)

    parts = stage_target(flags_so_far([]))
    print_command(parts)

    parts += stage_templates(flags_so_far(parts))
    print_command(parts)

    stages = [
        stage_filters,
        stage_headers,
        stage_performance,
        stage_output,
        stage_oob,
        stage_proxy,
        stage_misc,
    ]
    for fn in stages:
        new_tokens = fn(flags_so_far(parts))
        parts.extend(new_tokens)
        print_command(parts)

    print_final(parts)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n\nCancelado por el usuario.")
        sys.exit(0)
