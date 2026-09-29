#!/usr/bin/env python3
"""
Asistente interactivo para CONSTRUIR (no ejecutar) comandos de smbclient
(cliente SMB para listar y navegar recursos compartidos en Windows/Samba).

Misma filosofía que nmap_wizard.py, ffuf_wizard.py y nuclei_wizard.py: te
muestra, sección por sección, las opciones disponibles con su descripción y
caso de uso, y TÚ vas escribiendo el comando en continuación (el prompt te
muestra lo que ya llevas escrito y completas justo detrás), en el mismo orden
en que lo escribirías a mano: objetivo (listar shares o conectar a uno) ->
autenticación -> comandos/acciones -> opciones varias.

Para enumerar usuarios/grupos/política del dominio por RPC usa su asistente
hermano rpcclient_wizard.py.

Este script NUNCA ejecuta smbclient: solo construye el comando para que lo
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


def build_command(parts):
    return " ".join(["smbclient", *[p for p in parts if p]])


def flags_so_far(parts):
    return " ".join(["smbclient", *[p for p in parts if p]])


def print_command(parts):
    print(f"\n>>> Comando hasta ahora:\n    {build_command(parts)}\n")


def run_stage(title, intro, options, prefix, allow_skip=True):
    """Muestra las opciones como referencia y deja que el usuario continúe
    escribiendo él mismo, en texto libre, los flags de esta sección tal cual
    irían en el comando. Enter vacío omite la sección."""
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
    header("1) Objetivo: ¿listar shares o conectar a uno?")
    print(
        "smbclient tiene dos usos principales. La sintaxis general es:\n"
        "    smbclient -L //HOST                 (listar recursos compartidos)\n"
        "    smbclient //HOST/RECURSO            (conectarte a un recurso)\n"
    )
    options = [
        {
            "flag": "-L //10.10.10.10",
            "name": "Listar recursos compartidos (shares)",
            "desc": "Enumera los shares que ofrece el servidor (nombre, tipo y comentario).",
            "usecase": "Primer paso: ver qué hay disponible (ADMIN$, C$, IPC$, y shares personalizados jugosos).",
        },
        {
            "flag": "//10.10.10.10/NombreDelShare",
            "name": "Conectar a un recurso compartido",
            "desc": "Abre una sesión tipo FTP dentro de ese share para navegar y descargar.",
            "usecase": "Ya sabes el nombre del share (ej. //IP/Users, //IP/backups) y quieres entrar a ver/bajar archivos.",
        },
    ]
    show_options(options)
    print(
        "\nEscribe tú el objetivo tal cual irá en el comando, justo detrás de\n"
        "'smbclient': para listar usa '-L //HOST' y para conectar usa\n"
        "'//HOST/Share' (mira los ejemplos de arriba)."
    )
    while True:
        target = ask_raw("smbclient ")
        if "//" in target:
            return [target]
        print(
            "  No parece un objetivo válido: falta el '//'. Escribe algo como\n"
            "  '-L //10.10.10.10' o '//10.10.10.10/backups'."
        )


def stage_auth(prefix):
    header("2) Autenticación")
    print(
        "En HTB casi siempre empiezas probando SIN credenciales (sesión nula /\n"
        "null session); si eso no da nada, vuelves con las credenciales que\n"
        "hayas conseguido."
    )
    options = [
        {
            "flag": "-N",
            "name": "Sesión nula / sin contraseña",
            "desc": "No pide contraseña. Combínalo con -U '' para intentar acceso anónimo.",
            "usecase": "Primer intento SIEMPRE: muchos servidores permiten listar shares sin auth.",
        },
        {
            "flag": "-U ''",
            "name": "Usuario vacío (anónimo)",
            "desc": "Usuario nulo. Junto a -N intenta la clásica sesión nula.",
            "usecase": "Enumeración anónima: smbclient -L //IP -N -U \"\".",
        },
        {
            "flag": "-U 'usuario%contraseña'",
            "name": "Usuario y contraseña en una línea",
            "desc": "El % separa usuario y contraseña; evita que te la pregunte de forma interactiva.",
            "usecase": "Ya tienes credenciales, ej: -U 'john%Password123!'. Cita todo entre comillas por si hay símbolos.",
        },
        {
            "flag": "-U 'DOMINIO\\\\usuario'",
            "name": "Usuario con dominio / workgroup",
            "desc": "Especifica el dominio del usuario. Alternativa: añadir -W DOMINIO por separado.",
            "usecase": "Entornos con Active Directory, ej: -U 'CORP\\\\administrator' (o -U 'administrator' -W CORP).",
        },
        {
            "flag": "--pw-nt-hash",
            "name": "Pass-the-Hash (hash NT en vez de contraseña)",
            "desc": "Interpreta lo que pones como contraseña en -U como un hash NT, no como texto plano.",
            "usecase": "Tienes el hash NT (no la contraseña), ej: -U 'admin%31d6cfe0...' --pw-nt-hash.",
        },
        {
            "flag": "-A fichero",
            "name": "Fichero de autenticación",
            "desc": "Lee usuario/contraseña/dominio de un fichero (username=, password=, domain=).",
            "usecase": "No dejar la contraseña en el historial de la shell ni a la vista en 'ps'.",
        },
        {
            "flag": "-k",
            "name": "Autenticación Kerberos",
            "desc": "Usa un ticket Kerberos (del caché, KRB5CCNAME) en vez de usuario/contraseña.",
            "usecase": "Pass-the-Ticket en AD: ya tienes un TGT y el objetivo se referencia por nombre (no por IP).",
        },
    ]
    return run_stage("2) Autenticación", None, options, prefix)


def stage_commands(prefix):
    intro = (
        "Por defecto smbclient abre una sesión INTERACTIVA (prompt 'smb: \\>').\n"
        "Con -c le pasas los comandos de golpe y no interactúas: ideal para\n"
        "scripts o para bajar un archivo de una sola tacada.\n\n"
        "Comandos útiles DENTRO de la sesión (o dentro de las comillas de -c),\n"
        "separados por ';':\n"
        "    ls / dir            listar el directorio actual\n"
        "    cd <carpeta>        cambiar de directorio\n"
        "    get <archivo>       descargar un archivo\n"
        "    put <archivo>       subir un archivo (si tienes escritura)\n"
        "    mget * / mput *     descargar/subir varios (usa 'prompt off' antes)\n"
        "    prompt off          no preguntar por cada archivo en mget/mput\n"
        "    recurse on          recorrer subdirectorios (combínalo con mget *)\n"
        "    mask \"\"              sin filtro de máscara al recorrer/recurse\n"
        "    !comando            ejecutar un comando en TU máquina local"
    )
    options = [
        {
            "flag": "-c 'ls'",
            "name": "Ejecutar comandos sin interactuar",
            "desc": "Lanza los comandos entre comillas y sale; varios separados por ';'.",
            "usecase": "Listar sin entrar: -c 'ls'. Bajar un archivo: -c 'get flag.txt'.",
        },
        {
            "flag": "-c 'prompt off; recurse on; mget *'",
            "name": "Descargar TODO el share recursivamente",
            "desc": "Combo típico para volcar un recurso entero a tu disco de una vez.",
            "usecase": "El share tiene muchos archivos/carpetas y quieres bajarlo completo para revisarlo offline.",
        },
    ]
    return run_stage("3) Comandos / acciones dentro del share", intro, options, prefix)


def stage_misc(prefix):
    intro = "Opciones adicionales de conexión y protocolo."
    options = [
        {
            "flag": "-p",
            "name": "Puerto",
            "desc": "Puerto SMB de destino (445 por defecto; 139 para NetBIOS antiguo).",
            "usecase": "El servicio está en un puerto no estándar, ej: -p 445.",
        },
        {
            "flag": "-m",
            "name": "Versión máxima del protocolo",
            "desc": "Fuerza el dialecto máximo: SMB2, SMB3, NT1 (SMB1)...",
            "usecase": "Servidores viejos que solo hablan SMB1: -m NT1. Errores de protocolo: prueba -m SMB2 o -m SMB3.",
        },
        {
            "flag": "-W",
            "name": "Workgroup / dominio",
            "desc": "Indica el workgroup o dominio por separado (alternativa a DOMINIO\\usuario).",
            "usecase": "Entornos AD, ej: -W CORP.",
        },
        {
            "flag": "-I",
            "name": "IP de destino explícita",
            "desc": "Fija la IP cuando en el //HOST usas un nombre NetBIOS que no resuelve.",
            "usecase": "Te conectas por nombre (//DC01/share) pero necesitas decirle la IP real: -I 10.10.10.10.",
        },
        {
            "flag": "-t",
            "name": "Timeout",
            "desc": "Segundos de espera de las operaciones antes de rendirse.",
            "usecase": "Objetivo lento o enlace inestable; subirlo evita cortes prematuros.",
        },
        {
            "flag": "-g",
            "name": "Salida 'grepable'",
            "desc": "Formato pensado para parsear con grep/scripts (una entrada por línea, con etiquetas).",
            "usecase": "Automatizar el listado de shares dentro de un script.",
        },
        {
            "flag": "-d",
            "name": "Nivel de depuración",
            "desc": "Sube el detalle de la traza (0-10) para ver qué pasa por debajo.",
            "usecase": "Diagnosticar por qué falla la autenticación o la negociación de protocolo, ej: -d 3.",
        },
    ]
    return run_stage("4) Opciones varias (protocolo, red, depuración)", intro, options, prefix)


NEEDS_VALUE = {
    "-L": "el host a listar (ej: -L //10.10.10.10)",
    "-U": "usuario o usuario%contraseña (ej: -U 'john%Pass123')",
    "-A": "la ruta a un fichero de autenticación",
    "-c": "los comandos entre comillas (ej: -c 'get flag.txt')",
    "-p": "un puerto (ej: -p 445)",
    "-m": "un dialecto (ej: -m SMB2)",
    "-W": "el workgroup/dominio (ej: -W CORP)",
    "-I": "una IP (ej: -I 10.10.10.10)",
    "-t": "segundos de timeout (ej: -t 10)",
    "-d": "un nivel de depuración 0-10 (ej: -d 3)",
}


def check_missing_values(parts):
    tokens = [tok for p in parts for tok in p.split()]
    warnings = []
    for i, tok in enumerate(tokens):
        if tok in NEEDS_VALUE:
            nxt = tokens[i + 1] if i + 1 < len(tokens) else None
            if nxt is None or nxt.startswith("-"):
                warnings.append((tok, NEEDS_VALUE[tok]))
    return warnings


def notes(parts):
    out = []
    cmd = build_command(parts)
    if "-N" not in cmd and "-U" not in cmd and "-A" not in cmd and "-k" not in cmd:
        out.append(
            "No has puesto autenticación. Si el share no es anónimo, smbclient "
            "te pedirá la contraseña de forma interactiva al ejecutarlo."
        )
    return out


def print_final(parts):
    header("COMANDO FINAL")
    print(build_command(parts))

    warnings = check_missing_values(parts)
    if warnings:
        print("\n⚠ AVISO: estos flags necesitan un valor justo después y no lo tienen:")
        for flag, hint in warnings:
            print(f"  - '{flag}' necesita {hint}")

    for note in notes(parts):
        print(f"\n⚠ AVISO: {note}")

    print(
        "\nCopia este comando y ejecútalo tú mismo cuando quieras.\n"
        "Este script no lo ha ejecutado ni lo ejecutará."
    )


def main():
    print(RULE)
    print(" ASISTENTE INTERACTIVO PARA CONSTRUIR COMANDOS SMBCLIENT")
    print(" (no ejecuta nada, solo te ayuda a escribir el comando paso a paso)")
    print(RULE)

    parts = stage_target()
    print_command(parts)

    for fn in (stage_auth, stage_commands, stage_misc):
        parts.extend(fn(flags_so_far(parts)))
        print_command(parts)

    print_final(parts)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n\nCancelado por el usuario.")
        sys.exit(0)
