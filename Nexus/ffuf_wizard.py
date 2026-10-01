#!/usr/bin/env python3
"""
Asistente interactivo para CONSTRUIR (no ejecutar) comandos de ffuf.

Misma filosofía que nmap_wizard.py: te muestra, sección por sección, las
opciones disponibles con su descripción y caso de uso, y TÚ vas escribiendo
el comando en continuación (el prompt te muestra lo que ya llevas escrito y
completas justo detrás), en el mismo orden en que lo escribirías a mano:
URL objetivo -> wordlist -> filtros -> método/datos -> cabeceras ->
extensiones -> recursividad -> rendimiento -> salida -> opciones varias.

Incluye un selector de wordlists de SecLists según qué estés buscando
(directorios, API, subdominios, parámetros, extensiones, credenciales).

Este script NUNCA ejecuta ffuf: solo construye el comando para que lo
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
    return " ".join(["ffuf", *[p for p in parts if p]])


def build_command(parts):
    return " ".join(["ffuf", *[p for p in parts if p]])


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


def stage_target():
    header("1) URL objetivo (con FUZZ)")
    print(
        "ffuf necesita que le indiques DÓNDE probar cada palabra del wordlist,\n"
        "marcando ese punto con la palabra clave FUZZ (en mayúsculas). La\n"
        "sintaxis general es:\n"
        "    ffuf -u <URL con FUZZ> -w <wordlist> [opciones]\n"
    )
    options = [
        {
            "flag": "http://10.129.126.61:3000/FUZZ",
            "name": "Fuzzing de directorios/archivos",
            "desc": "Prueba cada palabra del wordlist como una ruta distinta.",
            "usecase": "El caso más común: descubrir rutas/páginas que no están enlazadas.",
        },
        {
            "flag": "http://10.129.126.61:3000/page.FUZZ",
            "name": "Fuzzing de extensión de archivo",
            "desc": "Prueba distintas extensiones sobre un archivo conocido.",
            "usecase": "Ya sabes el nombre del archivo y buscas su extensión real (.php, .bak, .json...).",
        },
        {
            "flag": "http://10.129.126.61:3000/api/search?FUZZ=test",
            "name": "Fuzzing de nombre de parámetro",
            "desc": "Prueba distintos nombres de parámetro GET.",
            "usecase": "Descubrir parámetros ocultos que acepta un endpoint (ej. ?debug=test, ?id=test).",
        },
        {
            "flag": "http://10.129.126.61:3000/api/search?id=FUZZ",
            "name": "Fuzzing de valor de un parámetro",
            "desc": "Prueba distintos valores para un parámetro ya conocido.",
            "usecase": "Ya conoces el parámetro (ej. id) y quieres probar valores (IDOR, SQLi, etc.).",
        },
        {
            "flag": "http://FUZZ.10.129.126.61.nip.io:3000/",
            "name": "Fuzzing de subdominio / vhost",
            "desc": "Prueba distintos subdominios en la URL (o combínalo con -H 'Host: FUZZ...').",
            "usecase": "El sitio sirve contenido distinto según el vhost/subdominio (frecuente en HTB).",
        },
    ]
    show_options(options)
    while True:
        url = ask_raw(
            "\nEscribe tu URL con la palabra FUZZ en el punto que quieras probar: "
        )
        if "FUZZ" in url:
            break
        print("  Falta la palabra FUZZ en la URL (ffuf la necesita para saber dónde fuzzear), intenta de nuevo.")
    return [f"-u {url}"]


SECLISTS_CATEGORIES = [
    {
        "name": "Directorios y archivos web genéricos",
        "usecase": "Primer paso casi siempre: descubrir rutas/páginas no enlazadas en la web.",
        "paths": [
            ("raft-small-directories.txt", "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt", "Rápida, buena primera pasada."),
            ("raft-medium-directories.txt", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "Más cobertura, más lenta."),
            ("common.txt", "/usr/share/seclists/Discovery/Web-Content/common.txt", "Clásica y compacta."),
            ("big.txt", "/usr/share/seclists/Discovery/Web-Content/big.txt", "Muy completa, tarda bastante."),
        ],
    },
    {
        "name": "Endpoints de API",
        "usecase": "Cuando ya sabes que hay una API (ej. /api/...) y quieres enumerar sus rutas.",
        "paths": [
            ("api-endpoints.txt", "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt", "Rutas de API típicas (login, users, admin, health...)."),
            ("objects.txt", "/usr/share/seclists/Discovery/Web-Content/api/objects.txt", "Nombres de recursos/objetos típicos de una API REST."),
        ],
    },
    {
        "name": "Subdominios / Virtual Hosts",
        "usecase": "El sitio responde distinto según el Host/subdominio, o quieres mapear subdominios de un dominio.",
        "paths": [
            ("subdomains-top1million-5000.txt", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "Lista corta y rápida, buena primera pasada."),
            ("bitquark-subdomains-top100000.txt", "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt", "Mucha más cobertura, más lenta."),
        ],
    },
    {
        "name": "Parámetros GET/POST",
        "usecase": "Buscar parámetros ocultos que acepta un endpoint (debug, admin, redirect...).",
        "paths": [
            ("burp-parameter-names.txt", "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt", "Nombres de parámetros habituales en apps web."),
        ],
    },
    {
        "name": "Extensiones de archivo",
        "usecase": "Combinar con -e para probar varias extensiones sobre cada palabra encontrada.",
        "paths": [
            ("web-extensions.txt", "/usr/share/seclists/Discovery/Web-Content/web-extensions.txt", "Extensiones comunes en apps web (.php, .asp, .bak...)."),
        ],
    },
    {
        "name": "Usuarios (para login / fuerza bruta)",
        "usecase": "Enumerar o probar nombres de usuario válidos en un formulario de login.",
        "paths": [
            ("top-usernames-shortlist.txt", "/usr/share/seclists/Usernames/top-usernames-shortlist.txt", "Lista corta con los usuarios más habituales."),
            ("xato-net-10-million-usernames.txt", "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt", "Lista enorme, úsala si la corta no da resultado."),
        ],
    },
    {
        "name": "Contraseñas (para login / fuerza bruta)",
        "usecase": "Probar contraseñas contra un usuario ya conocido (o junto a usuarios en fuzzing de 2 puntos).",
        "paths": [
            ("10-million-password-list-top1000.txt", "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top1000.txt", "Compacta, ideal para una primera prueba."),
            ("rockyou.txt", "/usr/share/wordlists/rockyou.txt", "La clásica de Kali; a veces viene comprimida (gunzip rockyou.txt.gz)."),
        ],
    },
]


def stage_wordlist(prefix):
    header("2) Wordlist (-w)")
    print(
        "Elige la wordlist según qué estés buscando. Estas son rutas típicas\n"
        "en Kali con seclists instalado (comprueba que existen con 'ls', pueden\n"
        "variar según tu instalación)."
    )
    for i, cat in enumerate(SECLISTS_CATEGORIES, start=1):
        print(f"\n[{i}] {cat['name']}")
        print(f"    Cuándo usarlo: {cat['usecase']}")
        for fname, path, note in cat["paths"]:
            print(f"      - {path}")
            print(f"        ({note})")

    print(
        "\nEscribe la ruta de la wordlist que quieras usar (copia una de arriba\n"
        "o pon la tuya). Si vas a fuzzear dos puntos a la vez (ej. usuario Y\n"
        "contraseña), puedes escribir varias con -w wordlist:FUZZ1 -w wordlist2:FUZZ2."
    )
    path = ask_raw(f"{prefix} -w ")
    return [f"-w {path}"]


def stage_matchers(prefix):
    intro = (
        "Los matchers/filtros deciden qué respuestas se te muestran. Sin\n"
        "ninguno, ffuf te enseña TODO, incluyendo cientos de 404 iguales."
    )
    options = [
        {
            "flag": "-mc",
            "name": "Match por código de estado",
            "desc": "Solo muestra respuestas cuyo código esté en la lista dada.",
            "usecase": "Quedarte solo con lo interesante, ej: -mc 200,301,302,401,403.",
        },
        {
            "flag": "-fc",
            "name": "Filtrar por código de estado",
            "desc": "Excluye respuestas con esos códigos.",
            "usecase": "Descartar los 404 explícitamente si por algún motivo no quieres usar -mc.",
        },
        {
            "flag": "-fs",
            "name": "Filtrar por tamaño de respuesta",
            "desc": "Excluye respuestas de un tamaño exacto en bytes.",
            "usecase": "El servidor devuelve 200 para todo (soft-404) pero el tamaño de la página de error es constante.",
        },
        {
            "flag": "-fw",
            "name": "Filtrar por número de palabras",
            "desc": "Excluye respuestas con un número de palabras concreto.",
            "usecase": "Alternativa a -fs cuando el tamaño exacto varía pero el conteo de palabras no.",
        },
        {
            "flag": "-fl",
            "name": "Filtrar por número de líneas",
            "desc": "Excluye respuestas con un número de líneas concreto.",
            "usecase": "Igual que -fw pero basado en líneas; útil en páginas de error muy uniformes.",
        },
    ]
    return run_stage("3) Coincidencias y filtros", intro, options, prefix)


def stage_method(prefix):
    intro = "Método HTTP y datos enviados (para fuzzear formularios o APIs)."
    options = [
        {
            "flag": "-X",
            "name": "Método HTTP",
            "desc": "Cambia el verbo HTTP de la petición (GET por defecto).",
            "usecase": "Fuzzear un login o una API que espera POST/PUT, ej: -X POST.",
        },
        {
            "flag": "-d",
            "name": "Cuerpo de la petición",
            "desc": "Datos enviados en el body; puede contener FUZZ.",
            "usecase": "Fuzzear un campo de un JSON o formulario, ej: -d '{\"user\":\"admin\",\"password\":\"FUZZ\"}'.",
        },
    ]
    return run_stage("4) Método HTTP y datos", intro, options, prefix)


def stage_headers(prefix):
    intro = (
        "Cabeceras HTTP personalizadas: tokens, cookies, Content-Type, o el\n"
        "propio punto de fuzzing si estás probando vhosts/subdominios."
    )
    options = [
        {
            "flag": "-H",
            "name": "Cabecera personalizada",
            "desc": "Añade una cabecera HTTP completa a la petición (repetible).",
            "usecase": "Ej: -H 'Authorization: Bearer FUZZ', -H 'Cookie: session=FUZZ', -H 'Host: FUZZ.dominio.com', o probar bypasses como -H 'x-middleware-subrequest: middleware'.",
        },
    ]
    return run_stage("5) Cabeceras HTTP", intro, options, prefix)


def stage_extensions(prefix):
    intro = "Extensiones que ffuf añade automáticamente a cada palabra del wordlist."
    options = [
        {
            "flag": "-e",
            "name": "Extensiones",
            "desc": "Añade estas extensiones a cada palabra probada.",
            "usecase": "Buscar archivos con extensión concreta sin tenerlas en el wordlist, ej: -e .php,.html,.json,.bak.",
        },
    ]
    return run_stage("6) Extensiones automáticas", intro, options, prefix)


def stage_recursion(prefix):
    intro = "Fuzzing recursivo: cuando encuentra un directorio, vuelve a fuzzear dentro de él."
    options = [
        {
            "flag": "-recursion",
            "name": "Activar recursividad",
            "desc": "Vuelve a lanzar el fuzzing automáticamente dentro de cada directorio encontrado.",
            "usecase": "Explorar estructuras de carpetas en profundidad sin repetir el comando a mano.",
        },
        {
            "flag": "-recursion-depth",
            "name": "Profundidad máxima",
            "desc": "Limita cuántos niveles de recursividad se siguen.",
            "usecase": "Evitar que la recursividad se dispare sin control en sitios muy grandes, ej: -recursion-depth 2.",
        },
        {
            "flag": "-recursion-strategy",
            "name": "Estrategia de recursividad",
            "desc": "'default' solo recurre en respuestas que parecen directorio; 'greedy' recurre en cualquier match.",
            "usecase": "Usa 'greedy' si sospechas que hay rutas interesantes que 'default' se salta.",
        },
    ]
    return run_stage("7) Recursividad", intro, options, prefix)


def stage_performance(prefix):
    intro = "Velocidad y agresividad del fuzzing."
    options = [
        {
            "flag": "-t",
            "name": "Hilos concurrentes",
            "desc": "Número de peticiones en paralelo (40 por defecto).",
            "usecase": "Subir para ir más rápido en redes fiables; bajar para no saturar el servicio o evitar bloqueos.",
        },
        {
            "flag": "-p",
            "name": "Delay entre peticiones",
            "desc": "Pausa (fija o rango aleatorio) entre cada petición.",
            "usecase": "Evadir rate-limiting o WAFs, ej: -p 0.1-0.5.",
        },
        {
            "flag": "-rate",
            "name": "Límite de peticiones por segundo",
            "desc": "Techo global de peticiones/segundo, más fino que -t.",
            "usecase": "Control preciso para no tumbar un servicio sensible.",
        },
        {
            "flag": "-timeout",
            "name": "Timeout por petición",
            "desc": "Segundos de espera antes de dar una petición por fallida.",
            "usecase": "Subirlo si el objetivo responde lento; bajarlo para descartar peticiones colgadas más rápido.",
        },
    ]
    return run_stage("8) Rendimiento", intro, options, prefix)


def stage_output(prefix):
    intro = "Cómo guardar los resultados en disco."
    options = [
        {
            "flag": "-o",
            "name": "Archivo de salida",
            "desc": "Guarda los resultados en el archivo indicado.",
            "usecase": "Conservar el resultado para revisarlo después o pasarlo a otra herramienta.",
        },
        {
            "flag": "-of",
            "name": "Formato de salida",
            "desc": "Formato del archivo: json, ejson, html, md, csv, all.",
            "usecase": "Elige 'json' si luego quieres parsear el resultado con un script; 'html' para revisarlo a simple vista.",
        },
    ]
    return run_stage("9) Formato de salida", intro, options, prefix)


def stage_misc(prefix):
    intro = "Opciones adicionales útiles."
    options = [
        {
            "flag": "-c",
            "name": "Colorear salida",
            "desc": "Colorea la salida por terminal para leerla más fácil.",
            "usecase": "Uso interactivo normal en terminal.",
        },
        {
            "flag": "-v",
            "name": "Verbose",
            "desc": "Muestra más detalle de cada resultado (URL completa, headers).",
            "usecase": "Cuando necesitas ver más contexto de cada match sin abrir cada URL a mano.",
        },
        {
            "flag": "-ac",
            "name": "Auto-calibración",
            "desc": "ffuf prueba solo palabras aleatorias primero para detectar respuestas 'falsas' (soft-404) y las filtra solo.",
            "usecase": "Sitios que devuelven 200 con contenido variable para rutas que no existen; te ahorra configurar -fs/-fw a mano.",
        },
        {
            "flag": "-fr",
            "name": "Filtrar por regex en el cuerpo",
            "desc": "Excluye respuestas cuyo cuerpo coincida con la expresión regular dada.",
            "usecase": "Cuando ni el tamaño ni el código de estado distinguen los falsos positivos, pero el texto sí (ej. un mensaje de error concreto).",
        },
        {
            "flag": "-x",
            "name": "Proxy",
            "desc": "Enruta las peticiones a través de un proxy (ej. Burp).",
            "usecase": "Interceptar y analizar cada petición/respuesta en Burp Suite mientras ffuf fuzzea, ej: -x http://127.0.0.1:8080.",
        },
        {
            "flag": "-ignore-body",
            "name": "No descargar el cuerpo",
            "desc": "No guarda/descarga el cuerpo de la respuesta, solo cabeceras/código/tamaño.",
            "usecase": "Acelerar el fuzzing cuando solo te interesan los códigos de estado, no el contenido.",
        },
    ]
    return run_stage("10) Opciones varias", intro, options, prefix)


NEEDS_VALUE = {
    "-u": "la URL con FUZZ (ej: -u http://IP:3000/FUZZ)",
    "-w": "la ruta al wordlist (ej: -w /usr/share/seclists/.../common.txt)",
    "-mc": "códigos de estado a incluir (ej: -mc 200,301,302)",
    "-fc": "códigos de estado a excluir (ej: -fc 404)",
    "-fs": "un tamaño en bytes a excluir (ej: -fs 1234)",
    "-fw": "un número de palabras a excluir (ej: -fw 5)",
    "-fl": "un número de líneas a excluir (ej: -fl 10)",
    "-X": "el método HTTP (ej: -X POST)",
    "-d": "el cuerpo de la petición (ej: -d '{\"user\":\"FUZZ\"}')",
    "-H": "una cabecera completa (ej: -H 'Authorization: Bearer FUZZ')",
    "-e": "extensiones separadas por coma (ej: -e .php,.html)",
    "-o": "un nombre de archivo de salida (ej: -o resultado.json)",
    "-of": "un formato (ej: -of json)",
    "-t": "un número de hilos (ej: -t 50)",
    "-p": "un delay (ej: -p 0.1-0.5)",
    "-rate": "un límite de peticiones/segundo (ej: -rate 50)",
    "-timeout": "segundos de timeout (ej: -timeout 10)",
    "-recursion-depth": "una profundidad máxima (ej: -recursion-depth 2)",
    "-recursion-strategy": "'default' o 'greedy'",
    "-x": "una URL de proxy (ej: -x http://127.0.0.1:8080)",
    "-fr": "una expresión regular",
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

    if "FUZZ" not in cmd:
        print(
            "\n⚠ AVISO: no hay ninguna palabra 'FUZZ' en el comando. ffuf la "
            "necesita\nen algún punto (la URL, el body con -d, o una cabecera "
            "con -H) para saber\ndónde probar el wordlist; sin ella, ffuf dará "
            "error al arrancar."
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
    print(" ASISTENTE INTERACTIVO PARA CONSTRUIR COMANDOS FFUF")
    print(" (no ejecuta nada, solo te ayuda a escribir el comando paso a paso)")
    print(RULE)

    parts = stage_target()
    print_command(parts)

    parts += stage_wordlist(flags_so_far(parts))
    print_command(parts)

    stages = [
        stage_matchers,
        stage_method,
        stage_headers,
        stage_extensions,
        stage_recursion,
        stage_performance,
        stage_output,
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
