# Git Tree Path Traversal → Arbitrary File Write (authorized_keys)

Exploit que abusa de los objetos de bajo nivel de Git para escribir un archivo
**fuera** del repositorio cuando un servidor hace checkout/clone del repo **como
root**. Uso típico: inyectar tu clave SSH pública en
`/root/.ssh/authorized_keys` y conseguir acceso root por SSH.

Origen: CTF **NEXUS**.

---

## Idea del ataque

Git materializa los archivos en disco según el **nombre** de las entradas de
árbol (tree entries). Los comandos de alto nivel (`git add`, `git checkout`)
rechazan nombres como `..`, pero si construyes los objetos a mano —blobs,
trees y commit— escribiéndolos directamente en `.git/objects`, te saltas esas
validaciones.

Metiendo entradas de árbol llamadas `..`, al extraerse el repo Git va subiendo
de directorio hasta salir del repo y llegar a `/`, y desde ahí baja a la ruta
objetivo (`root/.ssh/authorized_keys`).

Primitiva resultante: **escritura de archivo arbitraria** con los privilegios
del proceso que hace el checkout.

---

## Cómo funciona (resumen técnico)

- `write_obj(data, t)` — Replica `git hash-object -w`: cabecera
  `"<tipo> <len>\x00"` + contenido, SHA-1 de todo (nombre del objeto), y lo
  guarda comprimido con zlib en `.git/objects/ab/cdef…`. Sin validaciones.
- `entry(mode, name, sha)` — Entrada de árbol binaria:
  `"<modo> <nombre>\x00" + sha_bytes`. Modos: `100644` archivo, `40000` dir.
- Construye árboles anidados para la ruta `.ssh/authorized_keys` →
  `root/.ssh/…`, los envuelve en varias entradas `..` encadenadas, empaqueta
  todo en un commit y apunta `refs/heads/main` a él a mano.

El número de `..` está calibrado para la profundidad a la que el objetivo
extrae el repo. **Ese es el parámetro que tendrás que ajustar.**

---

## Requisitos

- Un objetivo que clone/checkout un repo controlado por ti y lo extraiga como
  root (o como el usuario cuyo `authorized_keys` quieras escribir).
- Ejecutar el script **dentro de un repo git** (`.git/` presente).
- Tu clave pública en `/tmp/.k.pub`.

---

## Uso

1. Genera el par de claves (el script te lo recuerda si falta):

   ```bash
   ssh-keygen -t ed25519 -f /tmp/.k -N ''
   ```

2. Crea/entra en un repo git vacío y lanza el script:

   ```bash
   git init repo && cd repo
   python3 build.py
   ```

   Imprime `Done: <sha-del-commit>`.

3. Sirve/entrega ese repo al objetivo (según el reto: push a un remoto,
   servirlo por HTTP, etc.) para que lo clone/extraiga.

4. Cuando el checkout se materialice, tu clave cae en
   `/root/.ssh/authorized_keys`. Conéctate:

   ```bash
   ssh -i /tmp/.k root@<objetivo>
   ```

---

## Ajustar la profundidad (`..`)

En el código:

```python
for i in range(4):
    fir=write_obj(entry("40000","..",fir),"tree")
```

Más el `..` del árbol raíz → **5 niveles** por defecto. Si el objetivo extrae
el repo en `/srv/app/checkout/<repo>/`, cuenta cuántos niveles hay hasta `/` y
ajusta el `range(n)` para salir justo a la raíz antes de bajar a `root/.ssh`.

Si apunta demasiado arriba/abajo, la escritura no cae donde quieres: prueba
±1 nivel.

---

## Notas / variantes

- La ruta objetivo (`root/.ssh/authorized_keys`) se cambia editando los nombres
  de las entradas de árbol. Cualquier ruta escribible por el proceso vale.
- Mismo primitivo sirve para sobrescribir otros archivos sensibles
  (`.bashrc`, cron, configs, webshell en un webroot…), no solo SSH.
- El README del blob (`# Template`) es relleno para que el repo parezca normal.

---

## Categoría

- **Principal:** File-write primitives → Path traversal
- **Secundaria:** Git internals abuse / SSH key injection
- **Tags:** `git`, `path-traversal`, `arbitrary-file-write`,
  `ssh-authorized_keys`, `privesc`, `low-level-git-objects`
