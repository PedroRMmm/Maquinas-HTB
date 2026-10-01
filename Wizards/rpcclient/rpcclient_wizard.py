#!/usr/bin/env python3
"""
Asistente interactivo para CONSTRUIR (no ejecutar) comandos de rpcclient
(cliente MS-RPC para enumerar usuarios, grupos, política de contraseñas e
información del dominio a través de los pipes SAMR/LSA).

Misma filosofía que nmap_wizard.py, ffuf_wizard.py y nuclei_wizard.py: te
muestra, sección por sección, las opciones disponibles con su descripción y
caso de uso, y TÚ vas escribiendo el comando en continuación (el prompt te
muestra lo que ya llevas escrito y completas justo detrás), en el mismo orden
en que lo escribirías a mano: objetivo (host) -> autenticación -> comandos de
enumeración (-c) -> opciones varias.

OJO: en rpcclient el HOST va al FINAL del comando; el asistente lo coloca ahí
por ti. Para navegar y descargar de shares usa su asistente hermano
smbclient_wizard.py.

Este script NUNCA ejecuta rpcclient: solo construye el comando para que lo
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


def build_command(parts, host):
    tail = [host] if host else []
    return " ".join(["rpcclient", *[p for p in parts if p], *tail])


def flags_so_far(parts):
    """Flags tal y como van quedando (sin el host, que va al final), para usarlo
    como prefijo del prompt y que el usuario siga escribiendo en continuación."""
    return " ".join(["rpcclient", *[p for p in parts if p]])


def print_command(parts, host):
    print(f"\n>>> Comando hasta ahora:\n    {build_command(parts, host)}\n")


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
    header("1) Objetivo (host)")
    print(
        "rpcclient se conecta al servicio RPC del host para enumerar el dominio.\n"
        "La sintaxis general es (el host va al FINAL):\n"
        "    rpcclient -U 'usuario%contraseña' HOST\n"
        "    rpcclient -U '' -N HOST            (sesión nula, muy común en HTB)\n"
    )
    return ask_raw("Escribe el host/IP objetivo (ej. 10.10.10.10): ")


def stage_auth(prefix):
    header("2) Autenticación")
    print(
        "En HTB casi siempre empiezas probando una sesión nula (-U '' -N); si\n"
        "eso no da nada, vuelves con las credenciales que hayas conseguido."
    )
    options = [
        {
            "flag": "-N",
            "name": "Sin contraseña",
            "desc": "No pide contraseña. Combínalo con -U '' para la sesión nula.",
            "usecase": "Primer intento SIEMPRE: muchos DCs permiten enumerar usuarios sin auth.",
        },
        {
            "flag": "-U ''",
            "name": "Usuario vacío (anónimo)",
            "desc": "Usuario nulo. Junto a -N intenta la clásica sesión nula.",
            "usecase": "Enumeración anónima: rpcclient -U '' -N IP.",
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
    header("3) Comandos de enumeración (-c)")
    print(
        "rpcclient también es interactivo, pero lo normal es lanzar un comando\n"
        "concreto con -c 'comando' (varios separados por ';'). Aquí tienes los\n"
        "comandos de enumeración más útiles agrupados por objetivo. Copia el que\n"
        "quieras dentro de -c '...'.\n"
    )

    groups = [
        (
            "Información del servidor / dominio",
            [
                ("srvinfo", "Versión y rol del servidor (SO, tipo). Buena primera toma de contacto."),
                ("querydominfo", "Info del dominio: nombre, nº de usuarios, servidores, rol."),
                ("getdompwinfo", "Política de contraseñas del dominio (longitud mínima, complejidad)."),
                ("lsaquery", "SID del dominio y su nombre (útil para construir SIDs a mano)."),
            ],
        ),
        (
            "Usuarios",
            [
                ("enumdomusers", "Lista TODOS los usuarios del dominio con su RID. El comando estrella."),
                ("queryuser <RID>", "Detalle de un usuario por su RID (ej. queryuser 0x1f4 = 500 = Administrator)."),
                ("querydispinfo", "Como enumdomusers pero con descripción/comentario (a veces hay contraseñas ahí)."),
                ("getusrdompwinfo <RID>", "Política de contraseñas aplicada a un usuario concreto."),
            ],
        ),
        (
            "Grupos",
            [
                ("enumdomgroups", "Lista los grupos globales del dominio con su RID."),
                ("querygroup <RID>", "Detalle de un grupo por su RID."),
                ("querygroupmem <RID>", "Miembros (RIDs) de un grupo; cruza con queryuser para sacar nombres."),
                ("enumalsgroups builtin", "Grupos locales/BUILTIN (ej. Administrators, Remote Desktop Users)."),
            ],
        ),
        (
            "SIDs <-> nombres (LSA)",
            [
                ("lookupnames <nombre>", "Traduce un nombre (ej. administrator) a su SID."),
                ("lookupsids <SID>", "Traduce un SID a su nombre de cuenta."),
                ("lsaenumsid", "Enumera los SIDs que la política LSA conoce."),
            ],
        ),
        (
            "Recursos compartidos",
            [
                ("netshareenumall", "Lista los shares vía RPC (alternativa a 'smbclient -L')."),
                ("netsharegetinfo <share>", "Detalle y permisos de un share concreto."),
            ],
        ),
    ]

    for gi, (gname, cmds) in enumerate(groups, start=1):
        print(f"\n[{gi}] {gname}")
        for c, desc in cmds:
            print(f"      - {c}")
            print(f"        {desc}")

    print(
        "\nTruco RID<->numero: los RID salen en hex (0x1f4). El Administrator es\n"
        "siempre el RID 500 (0x1f4). Un flujo clásico es enumdomusers y luego\n"
        "queryuser sobre cada RID.\n\n"
        "Escribe el/los comando(s) de -c tal cual quieras que quede (ej:\n"
        "-c 'enumdomusers' o -c 'queryuser 0x1f4'). Deja vacío para omitir y\n"
        "conectarte en modo interactivo."
    )
    raw = ask_raw(f"{prefix} ", allow_empty=True)
    if not raw:
        return []
    return [raw]


def stage_misc(prefix):
    intro = "Opciones adicionales de conexión."
    options = [
        {
            "flag": "-p",
            "name": "Puerto",
            "desc": "Puerto del servicio RPC (135/445 según el transporte).",
            "usecase": "El servicio está en un puerto no estándar.",
        },
        {
            "flag": "-W",
            "name": "Workgroup / dominio",
            "desc": "Indica el dominio por separado (alternativa a DOMINIO\\usuario).",
            "usecase": "Entornos AD, ej: -W CORP.",
        },
        {
            "flag": "-d",
            "name": "Nivel de depuración",
            "desc": "Sube el detalle de la traza (0-10).",
            "usecase": "Diagnosticar fallos de autenticación o de conexión al pipe, ej: -d 3.",
        },
    ]
    return run_stage("4) Opciones varias", intro, options, prefix)


NEEDS_VALUE = {
    "-U": "usuario o usuario%contraseña (ej: -U 'john%Pass123')",
    "-A": "la ruta a un fichero de autenticación",
    "-c": "el comando entre comillas (ej: -c 'enumdomusers')",
    "-p": "un puerto (ej: -p 135)",
    "-W": "el workgroup/dominio (ej: -W CORP)",
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
    cmd = flags_so_far(parts)
    if "-N" not in cmd and "-U" not in cmd and "-A" not in cmd and "-k" not in cmd:
        out.append(
            "No has puesto autenticación. Para una sesión nula usa -U '' -N; "
            "si no, rpcclient te pedirá la contraseña de forma interactiva."
        )
    if "-U ''" in cmd and "-N" not in cmd:
        out.append(
            "Has puesto -U '' pero no -N: para la sesión nula clásica añade "
            "también -N (sin él te pedirá contraseña)."
        )
    return out


def print_final(parts, host):
    header("COMANDO FINAL")
    print(build_command(parts, host))

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
    print(" ASISTENTE INTERACTIVO PARA CONSTRUIR COMANDOS RPCCLIENT")
    print(" (no ejecuta nada, solo te ayuda a escribir el comando paso a paso)")
    print(RULE)

    host = stage_target()
    parts = []
    print_command(parts, host)

    for fn in (stage_auth, stage_commands, stage_misc):
        parts.extend(fn(flags_so_far(parts)))
        print_command(parts, host)

    print_final(parts, host)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n\nCancelado por el usuario.")
        sys.exit(0)
