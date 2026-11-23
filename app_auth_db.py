import logging
import os
import re
import secrets
import sqlite3
import threading

import bcrypt
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db")

app = Flask(__name__)

logger = logging.getLogger("authapi")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    )
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)
logger.propagate = False

SECRET_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")


def _load_secret_key():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(key)
    return key


app.secret_key = _load_secret_key()

lock = threading.Lock()
failed_attempts = {}
MAX_FAILED = 5


def _es_formulario():
    """True si la peticion viene del formulario HTML (no de la API JSON)."""
    return bool(request.form) and not request.is_json


def _respuesta_auth(mensaje, status, tab="login", **contexto):
    """Respuesta de error como JSON (API) o como HTML (interfaz)."""
    if _es_formulario():
        return (
            render_template("login.html", error=mensaje, tab=tab, **contexto),
            status,
        )
    return jsonify({"error": mensaje}), status


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS Rol (
                id INTEGER PRIMARY KEY,
                nombre TEXT NOT NULL UNIQUE
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS Usuario (
                id INTEGER PRIMARY KEY,
                mail TEXT NOT NULL UNIQUE,
                clave TEXT NOT NULL,
                rol_id INTEGER NOT NULL,
                FOREIGN KEY (rol_id) REFERENCES Rol(id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS Tarea (
                id INTEGER PRIMARY KEY,
                titulo TEXT NOT NULL,
                descripcion TEXT NOT NULL DEFAULT '',
                estado TEXT NOT NULL DEFAULT 'pendiente',
                dni TEXT NOT NULL DEFAULT '',
                nombres TEXT NOT NULL DEFAULT '',
                owner_id INTEGER NOT NULL,
                creado_en TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (owner_id) REFERENCES Usuario(id)
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_tarea_owner ON Tarea(owner_id)"
        )
        conn.commit()

        cur.execute("PRAGMA table_info(Tarea)")
        columnas = [r[1] for r in cur.fetchall()]
        if "dni" not in columnas:
            cur.execute("ALTER TABLE Tarea ADD COLUMN dni TEXT NOT NULL DEFAULT ''")
        if "nombres" not in columnas:
            cur.execute("ALTER TABLE Tarea ADD COLUMN nombres TEXT NOT NULL DEFAULT ''")
        conn.commit()

        cur.execute("SELECT COUNT(*) FROM Rol")
        if cur.fetchone()[0] == 0:
            cur.executemany(
                "INSERT INTO Rol (id, nombre) VALUES (?, ?)",
                [(1, "Administrador"), (2, "Propietario"), (3, "User")],
            )
            conn.commit()
    finally:
        conn.close()


ESTADOS = [
    ("pendiente", "Pendiente"),
    ("en_progreso", "En progreso"),
    ("completada", "Completada"),
]
ESTADOS_VALORES = [v for v, _ in ESTADOS]


@app.route("/")
def index():
    if session.get("mail"):
        return redirect(url_for("dashboard"))
    return render_template("login.html")


def _owner_id():
    """Devuelve el id del usuario en sesion (lo resuelve y cachea si falta)."""
    uid = session.get("user_id")
    if uid:
        return uid
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM Usuario WHERE mail = ?", (session["mail"],))
        row = cur.fetchone()
        if row:
            session["user_id"] = row["id"]
            return row["id"]
    finally:
        conn.close()
    return None


CAMPOS_TAREA = ("titulo", "descripcion", "estado", "dni", "nombres")
CAMPOS_TEXTO = ("titulo", "descripcion", "dni", "nombres")

_LETRAS = "A-Za-z\u00C1\u00C9\u00CD\u00D3\u00DA\u00DC\u00D1\u00E1\u00E9\u00ED\u00F3\u00FA\u00FC\u00F1"
_RE_DNI = re.compile(r"\d{8}")
_RE_NOMBRES = re.compile(rf"^[{_LETRAS}]+(?: [{_LETRAS}]+)*$")


def _fallo(regla, parametro, mensaje):
    """Registra la regla violada sin guardar el payload completo."""
    logger.warning(
        "Validacion fallida: regla=%s parametro=%s", regla, str(parametro)[:40]
    )
    return mensaje


def _get_tareas(owner_id, q=""):
    conn = get_db()
    try:
        cur = conn.cursor()
        if q:
            patron = (
                "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            )
            cur.execute(
                """
                SELECT id, titulo, descripcion, estado, dni, nombres, creado_en
                FROM Tarea
                WHERE owner_id = ? AND titulo LIKE ? ESCAPE '\\'
                ORDER BY id DESC
                """,
                (owner_id, patron),
            )
        else:
            cur.execute(
                """
                SELECT id, titulo, descripcion, estado, dni, nombres, creado_en
                FROM Tarea
                WHERE owner_id = ?
                ORDER BY id DESC
                """,
                (owner_id,),
            )
        return cur.fetchall()
    finally:
        conn.close()


def _leer_campos_tarea():
    """Lee y sanea los campos; devuelve (datos, error)."""
    if _es_formulario():
        bruto = {k: request.form.get(k) for k in CAMPOS_TAREA}
        extra = set(request.form.keys()) - set(CAMPOS_TAREA)
    else:
        data = request.get_json(silent=True)
        if data is None:
            data = {}
        if not isinstance(data, dict):
            return None, _fallo("estructura", "body", "Cuerpo de peticion invalido")
        bruto = {k: data.get(k) for k in CAMPOS_TAREA}
        extra = set(data.keys()) - set(CAMPOS_TAREA)

    for campo in CAMPOS_TAREA:
        valor = bruto.get(campo)
        if valor is not None and not isinstance(valor, str):
            return None, _fallo(
                "tipo_dato", campo, "Tipo de dato invalido para: " + campo
            )

    datos = {k: (bruto.get(k) or "").strip() for k in CAMPOS_TAREA}

    if extra:
        nombres_extra = ", ".join(sorted(extra)[:3])[:60]
        return datos, _fallo(
            "campo_desconocido", nombres_extra, "Campos no permitidos: " + nombres_extra
        )

    return datos, None


def _validar_tarea(datos):
    titulo = datos["titulo"]
    descripcion = datos["descripcion"]
    estado = datos["estado"]
    dni = datos["dni"]
    nombres = datos["nombres"]

    if not titulo:
        return _fallo("requerido", "titulo", "El titulo es requerido")
    if len(titulo) < 3:
        return _fallo(
            "longitud_min", "titulo", "El titulo debe tener al menos 3 caracteres"
        )
    if len(titulo) > 120:
        return _fallo(
            "longitud_max", "titulo", "El titulo no puede superar los 120 caracteres"
        )
    if len(descripcion) > 1000:
        return _fallo(
            "longitud_max",
            "descripcion",
            "La descripcion no puede superar los 1000 caracteres",
        )
    if estado not in ESTADOS_VALORES:
        return _fallo(
            "valor_invalido",
            "estado",
            "Estado invalido. Usa: pendiente, en_progreso o completada",
        )
    if not dni:
        return _fallo("requerido", "dni", "El DNI es requerido")
    if not _RE_DNI.fullmatch(dni):
        return _fallo(
            "formato", "dni", "El DNI debe contener exactamente 8 digitos"
        )
    if not nombres:
        return _fallo("requerido", "nombres", "Los nombres son requeridos")
    if len(nombres) > 80:
        return _fallo(
            "longitud_max", "nombres", "Los nombres no pueden superar los 80 caracteres"
        )
    if not _RE_NOMBRES.fullmatch(nombres):
        return _fallo(
            "formato",
            "nombres",
            "Los nombres solo pueden contener letras y espacios",
        )
    return None


CAMPOS_ACTUALIZACION = ("titulo", "descripcion", "estado")


def _leer_campos_actualizacion():
    """Lee solo los campos enviados para actualizar; devuelve (datos, error)."""
    if request.is_json or not request.form:
        data = request.get_json(silent=True)
        if data is None:
            data = {}
        if not isinstance(data, dict):
            return None, _fallo("estructura", "body", "Cuerpo de peticion invalido")
        bruto = {k: data.get(k) for k in CAMPOS_ACTUALIZACION}
        extra = set(data.keys()) - set(CAMPOS_ACTUALIZACION)
    else:
        bruto = {k: request.form.get(k) for k in CAMPOS_ACTUALIZACION}
        extra = set(request.form.keys()) - set(CAMPOS_ACTUALIZACION)

    for campo in CAMPOS_ACTUALIZACION:
        valor = bruto.get(campo)
        if valor is not None and not isinstance(valor, str):
            return None, _fallo(
                "tipo_dato", campo, "Tipo de dato invalido para: " + campo
            )

    if extra:
        nombres_extra = ", ".join(sorted(extra)[:3])[:60]
        return None, _fallo(
            "campo_desconocido", nombres_extra, "Campos no permitidos: " + nombres_extra
        )

    datos = {}
    for campo in CAMPOS_ACTUALIZACION:
        valor = bruto.get(campo)
        if isinstance(valor, str):
            datos[campo] = valor.strip()

    if not datos:
        return None, _fallo(
            "sin_campos", "body", "Debe indicar al menos un campo a actualizar"
        )
    return datos, None


def _validar_actualizacion(datos):
    """Valida los campos presentes en la actualizacion parcial."""
    titulo = datos.get("titulo")
    if titulo is not None:
        if not titulo:
            return _fallo("requerido", "titulo", "El titulo es requerido")
        if len(titulo) < 3:
            return _fallo(
                "longitud_min", "titulo", "El titulo debe tener al menos 3 caracteres"
            )
        if len(titulo) > 120:
            return _fallo(
                "longitud_max",
                "titulo",
                "El titulo no puede superar los 120 caracteres",
            )
    if "descripcion" in datos and len(datos["descripcion"]) > 1000:
        return _fallo(
            "longitud_max",
            "descripcion",
            "La descripcion no puede superar los 1000 caracteres",
        )
    estado = datos.get("estado")
    if estado is not None and estado not in ESTADOS_VALORES:
        return _fallo(
            "valor_invalido",
            "estado",
            "Estado invalido. Usa: pendiente, en_progreso o completada",
        )
    return None


def _respuesta_tarea(mensaje, status):
    """Error de tareas como HTML (formulario) o JSON (API)."""
    if _es_formulario():
        ctx = _contexto_dashboard(error=mensaje)
        return render_template("dashboard.html", **ctx), status
    return jsonify({"error": mensaje}), status


def _no_sesion_tarea():
    """Sesion ausente/invalida en rutas de tareas."""
    if _es_formulario():
        return redirect(url_for("index"))
    return jsonify({"error": "Sesion requerida"}), 401


CAMPOS_API_TASK = ("title", "description", "status")
MAX_TASK_REQUEST_BYTES = 16 * 1024  # 16 KB


def _tiene_sesion_o_token():
    """Verifica sesion activa o token Bearer no vacio."""
    if session.get("mail") or session.get("user_id"):
        return True
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and auth_header[7:].strip():
        return True
    return False


def _resolver_owner_api():
    uid = session.get("user_id")
    if uid:
        return uid
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM Usuario ORDER BY id ASC LIMIT 1")
        row = cur.fetchone()
        return row["id"] if row else 1
    finally:
        conn.close()

@app.route("/tasks_insecure", methods=["POST"])
def tasks_insecure():
    """Version insegura: acepta cualquier dato y lo guarda sin validar."""
    data = request.get_json(silent=True) or request.form.to_dict()
    titulo = str(data.get("title", data.get("titulo", "")))
    descripcion = str(data.get("description", data.get("descripcion", "")))
    estado = str(data.get("status", data.get("estado", "pendiente")))
    owner_id = data.get("owner_id", _resolver_owner_api())

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO Tarea (titulo, descripcion, estado, dni, nombres, owner_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (titulo, descripcion, estado, "00000000", "Sin Validar", owner_id),
        )
        conn.commit()
        tarea_id = cur.lastrowid
    finally:
        conn.close()

    return (
        jsonify(
            {
                "id": tarea_id,
                "recibido": data,
                "aviso": "Guardado sin validacion en servidor",
            }
        ),
        201,
    )


@app.route("/tasks", methods=["POST"])
def create_task_api():
    """Endpoint seguro con validacion estricta en servidor y logging sin payload."""
    if not _tiene_sesion_o_token():
        msg = _fallo("autenticacion", "authorization", "Token o sesion requerida")
        return jsonify({"error": msg}), 401

    content_length = request.content_length
    if content_length is not None and content_length > MAX_TASK_REQUEST_BYTES:
        msg = _fallo("tamano_solicitud", "Content-Length", "Solicitud demasiado grande")
        return jsonify({"error": msg}), 413

    raw_body = request.get_data(cache=True)
    if len(raw_body) > MAX_TASK_REQUEST_BYTES:
        msg = _fallo("tamano_solicitud", "body", "Solicitud demasiado grande")
        return jsonify({"error": msg}), 413

    if request.is_json:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            msg = _fallo("estructura", "body", "Cuerpo JSON invalido")
            return jsonify({"error": msg}), 400
    else:
        payload = request.form.to_dict()

    extra_fields = set(payload.keys()) - set(CAMPOS_API_TASK)
    if extra_fields:
        campo_extra = sorted(extra_fields)[0]
        msg = _fallo(
            "campo_desconocido",
            campo_extra,
            f"Campo no permitido: {campo_extra}",
        )
        return jsonify({"error": msg}), 400

    raw_title = payload.get("title")
    if not isinstance(raw_title, str):
        msg = _fallo("tipo_dato", "title", "El campo title es obligatorio y debe ser texto")
        return jsonify({"error": msg}), 400

    title = re.sub(r"\s+", " ", raw_title).strip()
    if not title:
        msg = _fallo("requerido", "title", "El campo title no puede estar vacio")
        return jsonify({"error": msg}), 400
    if len(title) < 3:
        msg = _fallo("longitud_min", "title", "El campo title debe tener al menos 3 caracteres")
        return jsonify({"error": msg}), 400
    if len(title) > 120:
        msg = _fallo("longitud_max", "title", "El campo title no puede superar 120 caracteres")
        return jsonify({"error": msg}), 400

    raw_description = payload.get("description", "")
    if raw_description is None:
        raw_description = ""
    if not isinstance(raw_description, str):
        msg = _fallo("tipo_dato", "description", "El campo description debe ser texto")
        return jsonify({"error": msg}), 400

    description = raw_description.strip()
    if len(description) > 1000:
        msg = _fallo(
            "longitud_max",
            "description",
            "El campo description no puede superar 1000 caracteres",
        )
        return jsonify({"error": msg}), 400

    raw_status = payload.get("status")
    if not isinstance(raw_status, str) or raw_status not in ESTADOS_VALORES:
        msg = _fallo(
            "valor_invalido",
            "status",
            "Estado invalido. Valores permitidos: pendiente, en_progreso, completada",
        )
        return jsonify({"error": msg}), 400

    owner_id = _resolver_owner_api()
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO Tarea (titulo, descripcion, estado, dni, nombres, owner_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (title, description, raw_status, "00000000", "API Task", owner_id),
        )
        conn.commit()
        tarea_id = cur.lastrowid
    finally:
        conn.close()

    return (
        jsonify(
            {
                "id": tarea_id,
                "title": title,
                "description": description,
                "status": raw_status,
            }
        ),
        201,
    )


def _contexto_dashboard(error=None, ok=None, form=None, q=""):
    owner_id = _owner_id()
    form = form or {}
    return dict(
        mail=session.get("mail", ""),
        rol=session.get("rol", ""),
        user_id=owner_id,
        tareas=_get_tareas(owner_id, q) if owner_id else [],
        q=q,
        estados=ESTADOS,
        estado_labels=dict(ESTADOS),
        error=error,
        ok=ok,
        form_titulo=form.get("titulo", ""),
        form_descripcion=form.get("descripcion", ""),
        form_estado=form.get("estado", "pendiente"),
        form_dni=form.get("dni", ""),
        form_nombres=form.get("nombres", ""),
    )


@app.route("/dashboard")
def dashboard():
    if not session.get("mail"):
        return redirect(url_for("index"))
    ctx = _contexto_dashboard(
        ok=request.args.get("ok"),
        q=request.args.get("q", "").strip(),
    )
    return render_template("dashboard.html", **ctx)


@app.route("/tareas", methods=["POST"])
def crear_tarea():
    if not session.get("mail"):
        if _es_formulario():
            return redirect(url_for("index"))
        return jsonify({"error": "Sesion requerida"}), 401

    owner_id = _owner_id()
    if not owner_id:
        if _es_formulario():
            return redirect(url_for("index"))
        return jsonify({"error": "Sesion invalida"}), 401

    datos, error = _leer_campos_tarea()
    if error:
        if _es_formulario():
            ctx = _contexto_dashboard(error=error, form=datos or {})
            return render_template("dashboard.html", **ctx), 400
        return jsonify({"error": error}), 400

    error = _validar_tarea(datos)
    if error:
        if _es_formulario():
            ctx = _contexto_dashboard(error=error, form=datos)
            return render_template("dashboard.html", **ctx), 400
        return jsonify({"error": error}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO Tarea (titulo, descripcion, estado, dni, nombres, owner_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datos["titulo"],
                datos["descripcion"],
                datos["estado"],
                datos["dni"],
                datos["nombres"],
                owner_id,
            ),
        )
        conn.commit()
        tarea_id = cur.lastrowid
    finally:
        conn.close()

    if _es_formulario():
        return redirect(url_for("dashboard", ok="1"))

    return (
        jsonify(
            {
                "id": tarea_id,
                "titulo": datos["titulo"],
                "descripcion": datos["descripcion"],
                "estado": datos["estado"],
                "dni": datos["dni"],
                "nombres": datos["nombres"],
                "owner_id": owner_id,
            }
        ),
        201,
    )


@app.route("/tareas/<int:tarea_id>", methods=["PUT"])
@app.route("/tareas/<int:tarea_id>/actualizar", methods=["POST"])
def actualizar_tarea(tarea_id):
    """Actualiza titulo/descripcion/estado solo si la tarea pertenece al usuario."""
    if not session.get("mail") or not _owner_id():
        return _no_sesion_tarea()

    owner_id = _owner_id()

    datos, error = _leer_campos_actualizacion()
    if error:
        return _respuesta_tarea(error, 400)

    error = _validar_actualizacion(datos)
    if error:
        return _respuesta_tarea(error, 400)

    campos = [c for c in CAMPOS_ACTUALIZACION if c in datos]
    asignaciones = ", ".join(c + " = ?" for c in campos)
    valores = [datos[c] for c in campos]

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM Tarea WHERE id = ? AND owner_id = ?",
            (tarea_id, owner_id),
        )
        if cur.fetchone() is None:
            return _respuesta_tarea("No tienes permiso sobre esta tarea", 403)

        cur.execute(
            "UPDATE Tarea SET " + asignaciones + " WHERE id = ? AND owner_id = ?",
            tuple(valores) + (tarea_id, owner_id),
        )
        conn.commit()
    finally:
        conn.close()

    if _es_formulario():
        return redirect(url_for("dashboard", ok="actualizada"))
    return (
        jsonify(
            {
                "id": tarea_id,
                "actualizada": True,
                "campos": {c: datos[c] for c in campos},
            }
        ),
        200,
    )


@app.route("/tareas/<int:tarea_id>", methods=["DELETE"])
@app.route("/tareas/<int:tarea_id>/eliminar", methods=["POST"])
def eliminar_tarea(tarea_id):
    """Elimina solo la tarea del usuario autenticado."""
    if not session.get("mail") or not _owner_id():
        return _no_sesion_tarea()

    owner_id = _owner_id()

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM Tarea WHERE id = ? AND owner_id = ?",
            (tarea_id, owner_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            return _respuesta_tarea("No tienes permiso sobre esta tarea", 403)
    finally:
        conn.close()

    if _es_formulario():
        return redirect(url_for("dashboard", ok="eliminada"))
    return jsonify({"id": tarea_id, "eliminada": True}), 200


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/api/registro", methods=["POST"])
def registro():
    if _es_formulario():
        mail = request.form.get("mail")
        clave = request.form.get("clave")
    else:
        data = request.get_json(silent=True) or {}
        mail = data.get("mail")
        clave = data.get("clave")

    if not mail or not clave:
        return _respuesta_auth(
            "mail y clave son requeridos", 400, tab="registro", mail_form=mail
        )

    clave_hash = bcrypt.hashpw(clave.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO Usuario (mail, clave, rol_id) VALUES (?, ?, ?)",
            (mail, clave_hash, 3),
        )
        conn.commit()
        user_id = cur.lastrowid
        cur.execute("SELECT nombre FROM Rol WHERE id = 3")
        rol_nombre = cur.fetchone()["nombre"]
    except sqlite3.IntegrityError:
        return _respuesta_auth(
            "El mail ya esta registrado", 409, tab="registro", mail_form=mail
        )
    finally:
        conn.close()

    session.clear()
    session["mail"] = mail
    session["rol"] = rol_nombre
    session["user_id"] = user_id

    if _es_formulario():
        return redirect(url_for("dashboard"))

    return jsonify({"rol": rol_nombre}), 201


@app.route("/api/login", methods=["POST"])
def login():
    ip = request.remote_addr

    with lock:
        if failed_attempts.get(ip, 0) >= MAX_FAILED:
            return _respuesta_auth(
                "Demasiados intentos fallidos. Intenta mas tarde", 429
            )

    if _es_formulario():
        mail = request.form.get("mail")
        clave = request.form.get("clave")
    else:
        data = request.get_json(silent=True) or {}
        mail = data.get("mail")
        clave = data.get("clave")

    if not mail or not clave:
        return _respuesta_auth("Credenciales invalidas", 401, mail_form=mail)

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT u.id, u.mail, u.clave, r.nombre AS rol_nombre
            FROM Usuario u
            JOIN Rol r ON u.rol_id = r.id
            WHERE u.mail = ?
            """,
            (mail,),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if row is None:
        with lock:
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        return _respuesta_auth("Credenciales invalidas", 401, mail_form=mail)

    clave_valida = bcrypt.checkpw(
        clave.encode("utf-8"), row["clave"].encode("utf-8")
    )

    if not clave_valida:
        with lock:
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        return _respuesta_auth("Credenciales invalidas", 401, mail_form=mail)

    with lock:
        failed_attempts[ip] = 0

    token = secrets.token_hex(32)

    session.clear()
    session["mail"] = row["mail"]
    session["rol"] = row["rol_nombre"]
    session["user_id"] = row["id"]

    if _es_formulario():
        return redirect(url_for("dashboard"))

    return jsonify({"token": token, "rol": row["rol_nombre"]}), 200


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)