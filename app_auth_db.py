import hashlib
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from datetime import timedelta

import bcrypt
from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db")

app = Flask(__name__)

logger = logging.getLogger("taskguard")
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

# --- Parametros de seguridad de sesion y autenticacion (Ejercicio 1.2) ---
SESSION_TTL = 30 * 60          # la sesion web expira a los 30 min
TOKEN_TTL = 30 * 60            # el token Bearer expira a los 30 min
RESET_TTL = 15 * 60            # el token de recuperacion expira a los 15 min
MAX_FAILED = 5                 # fallos antes de bloquear
BLOQUEO_BASE = 60              # primer bloqueo: 60 s, luego 120, 240... (progresivo)
BLOQUEO_MAX = 60 * 60          # tope del bloqueo: 1 hora
VENTANA_FALLOS = 15 * 60       # fallos mas antiguos que esto se olvidan

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=SESSION_TTL),
)

# --- Roles del sistema ---
ROL_ADMIN, ROL_DOCENTE, ROL_ESTUDIANTE = 1, 2, 3
ROLES = {ROL_ADMIN: "Administrador", ROL_DOCENTE: "Docente", ROL_ESTUDIANTE: "Estudiante"}
ROLES_POR_NOMBRE = {v.lower(): k for k, v in ROLES.items()}

_RE_MAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$")


def _ahora():
    """Reloj del sistema (aislado para poder simular el paso del tiempo en pruebas)."""
    return time.time()


def _hash_token(token):
    """Los tokens se guardan como SHA-256: si roban la BD, no sirven."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _enmascarar(mail):
    """Para logs: 'juan@unsaac.edu.pe' -> 'ju***@unsaac.edu.pe'."""
    mail = str(mail or "")
    if "@" not in mail:
        return mail[:2] + "***"
    usuario, dominio = mail.split("@", 1)
    return usuario[:2] + "***@" + dominio[:40]


class LimitadorIntentos:
    """Cuenta fallos por clave (IP o cuenta) y aplica bloqueo temporal progresivo."""

    def __init__(self):
        self._datos = {}
        self._lock = threading.Lock()

    def segundos_bloqueo(self, clave):
        with self._lock:
            e = self._datos.get(clave)
            if e and e["hasta"] > _ahora():
                return int(e["hasta"] - _ahora()) + 1
            return 0

    def registrar_fallo(self, clave):
        """Devuelve la duracion del bloqueo si este fallo lo activa, si no 0."""
        with self._lock:
            ahora = _ahora()
            e = self._datos.setdefault(
                clave, {"fallos": 0, "nivel": 0, "hasta": 0, "ultimo": 0}
            )
            if ahora - e["ultimo"] > VENTANA_FALLOS:
                e["fallos"] = 0
            e["ultimo"] = ahora
            e["fallos"] += 1
            if e["fallos"] >= MAX_FAILED:
                duracion = min(BLOQUEO_BASE * (2 ** e["nivel"]), BLOQUEO_MAX)
                e["hasta"] = ahora + duracion
                e["nivel"] += 1
                e["fallos"] = 0
                return duracion
            return 0

    def limpiar(self, clave):
        with self._lock:
            self._datos.pop(clave, None)

    def reiniciar(self):
        with self._lock:
            self._datos.clear()


limite_ip = LimitadorIntentos()
limite_cuenta = LimitadorIntentos()

# Servicio de correo simulado: en produccion se reemplaza por SMTP.
BUZON_SIMULADO = []


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

        # Roles de la guia: Administrador, Docente, Estudiante.
        # (Migra los nombres antiguos Propietario/User conservando los ids.)
        for rol_id, nombre in ROLES.items():
            cur.execute("INSERT OR IGNORE INTO Rol (id, nombre) VALUES (?, ?)", (rol_id, nombre))
            cur.execute("UPDATE Rol SET nombre = ? WHERE id = ?", (nombre, rol_id))
        conn.commit()

        # version_sesion: al cambiar la clave se incrementa e invalida toda sesion previa.
        cur.execute("PRAGMA table_info(Usuario)")
        if "version_sesion" not in [r[1] for r in cur.fetchall()]:
            cur.execute(
                "ALTER TABLE Usuario ADD COLUMN version_sesion INTEGER NOT NULL DEFAULT 0"
            )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS TokenSesion (
                id INTEGER PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                usuario_id INTEGER NOT NULL,
                expira_en REAL NOT NULL,
                revocado INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (usuario_id) REFERENCES Usuario(id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS TokenRecuperacion (
                id INTEGER PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                usuario_id INTEGER NOT NULL,
                expira_en REAL NOT NULL,
                usado INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (usuario_id) REFERENCES Usuario(id)
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Identidad del usuario actual (sesion web o token Bearer)
# ---------------------------------------------------------------------------

def _usuario_por_id(usuario_id):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT u.id, u.mail, u.clave, u.rol_id, u.version_sesion, r.nombre AS rol
            FROM Usuario u JOIN Rol r ON u.rol_id = r.id
            WHERE u.id = ?
            """,
            (usuario_id,),
        )
        return cur.fetchone()
    finally:
        conn.close()


def _usuario_actual():
    """Devuelve el usuario autenticado o None.

    - Con cabecera Bearer: el token debe existir, no estar revocado ni expirado.
    - Con sesion web: la sesion no debe estar expirada y su version debe coincidir
      con la del usuario (si cambio la clave, la sesion queda revocada).
    """
    if "usuario" in g:
        return g.usuario
    g.usuario = None

    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        if token:
            conn = get_db()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT usuario_id, expira_en, revocado FROM TokenSesion WHERE token_hash = ?",
                    (_hash_token(token),),
                )
                fila = cur.fetchone()
            finally:
                conn.close()
            if fila and not fila["revocado"] and fila["expira_en"] > _ahora():
                g.usuario = _usuario_por_id(fila["usuario_id"])
            else:
                _fallo("token_invalido", "authorization", "")
        return g.usuario

    uid = session.get("user_id")
    if uid:
        usuario = _usuario_por_id(uid)
        vigente = _ahora() - session.get("login_at", 0) < SESSION_TTL
        if usuario and vigente and session.get("ver") == usuario["version_sesion"]:
            g.usuario = usuario
        else:
            session.clear()
    return g.usuario


def _iniciar_sesion(usuario):
    """Regenera la sesion tras autenticarse (evita fijacion de sesion)."""
    session.clear()
    session.permanent = True
    session["user_id"] = usuario["id"]
    session["mail"] = usuario["mail"]
    session["rol"] = usuario["rol"]
    session["ver"] = usuario["version_sesion"]
    session["login_at"] = _ahora()


def _emitir_token(usuario_id):
    token = secrets.token_urlsafe(32)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO TokenSesion (token_hash, usuario_id, expira_en) VALUES (?, ?, ?)",
            (_hash_token(token), usuario_id, _ahora() + TOKEN_TTL),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def _revocar_todo(conn, usuario_id):
    """Revoca todos los tokens y sesiones web del usuario."""
    conn.execute("UPDATE TokenSesion SET revocado = 1 WHERE usuario_id = ?", (usuario_id,))
    conn.execute(
        "UPDATE Usuario SET version_sesion = version_sesion + 1 WHERE id = ?",
        (usuario_id,),
    )


def _validar_clave_nueva(clave):
    if not isinstance(clave, str) or len(clave) < 8:
        return "La clave debe tener al menos 8 caracteres"
    if len(clave.encode("utf-8")) > 72:
        return "La clave no puede superar los 72 bytes"
    if not re.search(r"[A-Za-z]", clave) or not re.search(r"\d", clave):
        return "La clave debe incluir letras y numeros"
    return None


def _leer_json_estricto(permitidos):
    """Lee el cuerpo (JSON o formulario) y rechaza campos no esperados."""
    if _es_formulario():
        data = request.form.to_dict()
    else:
        data = request.get_json(silent=True)
        if data is None:
            data = {}
        if not isinstance(data, dict):
            return None, "Cuerpo de peticion invalido"
    extra = set(data) - set(permitidos)
    if extra:
        campo = sorted(extra)[0][:40]
        return None, _fallo("campo_desconocido", campo, "Campo no permitido: " + campo)
    for k in permitidos:
        if data.get(k) is not None and not isinstance(data[k], str):
            return None, _fallo("tipo_dato", k, "Tipo de dato invalido para: " + k)
    return data, None


ESTADOS = [
    ("pendiente", "Pendiente"),
    ("en_progreso", "En progreso"),
    ("completada", "Completada"),
]
ESTADOS_VALORES = [v for v, _ in ESTADOS]


@app.route("/")
def index():
    if _usuario_actual():
        return redirect(url_for("dashboard"))
    return render_template("login.html")


def _owner_id():
    """Id del usuario autenticado (sesion o token), o None."""
    usuario = _usuario_actual()
    return usuario["id"] if usuario else None


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


def _demo_insegura_habilitada():
    """El endpoint inseguro solo existe en pruebas o si se habilita a proposito."""
    return app.config.get("TESTING") or os.environ.get("HABILITAR_DEMO_INSEGURA") == "1"


@app.route("/tasks_insecure", methods=["POST"])
def tasks_insecure():
    """Version insegura (solo demostracion): acepta cualquier dato sin validar."""
    if not _demo_insegura_habilitada():
        abort(404)
    data = request.get_json(silent=True) or request.form.to_dict()
    titulo = str(data.get("title", data.get("titulo", "")))
    descripcion = str(data.get("description", data.get("descripcion", "")))
    estado = str(data.get("status", data.get("estado", "pendiente")))
    owner_id = data.get("owner_id", _owner_id() or 1)

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
    usuario = _usuario_actual()
    if not usuario:
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

    owner_id = usuario["id"]
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
    usuario = _usuario_actual()
    owner_id = usuario["id"] if usuario else None
    form = form or {}
    return dict(
        mail=usuario["mail"] if usuario else "",
        rol=usuario["rol"] if usuario else "",
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
    if not _usuario_actual():
        return redirect(url_for("index"))
    ctx = _contexto_dashboard(
        ok=request.args.get("ok"),
        q=request.args.get("q", "").strip(),
    )
    return render_template("dashboard.html", **ctx)


@app.route("/tareas", methods=["GET"])
def listar_tareas():
    """Lista las tareas del usuario. Docente/Administrador pueden pedir ?todas=1."""
    usuario = _usuario_actual()
    if not usuario:
        return jsonify({"error": "Sesion requerida"}), 401

    q = request.args.get("q", "").strip()[:80]
    if request.args.get("todas") == "1":
        if usuario["rol_id"] not in (ROL_ADMIN, ROL_DOCENTE):
            _fallo("autorizacion", "todas", "")
            return jsonify({"error": "No tienes permiso para ver todas las tareas"}), 403
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, titulo, descripcion, estado, owner_id, creado_en
                FROM Tarea ORDER BY id DESC
                """
            )
            filas = cur.fetchall()
        finally:
            conn.close()
    else:
        filas = _get_tareas(usuario["id"], q)

    return jsonify({"tareas": [dict(f) for f in filas]}), 200


@app.route("/tareas", methods=["POST"])
def crear_tarea():
    owner_id = _owner_id()
    if not owner_id:
        if _es_formulario():
            return redirect(url_for("index"))
        return jsonify({"error": "Sesion requerida"}), 401

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
    owner_id = _owner_id()
    if not owner_id:
        return _no_sesion_tarea()

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
            _fallo("autorizacion", "tarea_id", "")
            return _respuesta_tarea("No tienes permiso sobre esta tarea", 403)

        # 'asignaciones' solo contiene nombres de la lista blanca CAMPOS_ACTUALIZACION;
        # los valores van parametrizados.
        cur.execute(
            "UPDATE Tarea SET " + asignaciones + " WHERE id = ? AND owner_id = ?",
            tuple(valores) + (tarea_id, owner_id),
        )
        conn.commit()
    finally:
        conn.close()

    logger.info("Auditoria: tarea_actualizada tarea_id=%s usuario_id=%s", tarea_id, owner_id)

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
    """Elimina la tarea si es del usuario; el Administrador puede eliminar cualquiera."""
    usuario = _usuario_actual()
    if not usuario:
        return _no_sesion_tarea()

    owner_id = usuario["id"]
    es_admin = usuario["rol_id"] == ROL_ADMIN

    conn = get_db()
    try:
        cur = conn.cursor()
        if es_admin:
            cur.execute("DELETE FROM Tarea WHERE id = ?", (tarea_id,))
        else:
            cur.execute(
                "DELETE FROM Tarea WHERE id = ? AND owner_id = ?",
                (tarea_id, owner_id),
            )
        conn.commit()
        if cur.rowcount == 0:
            if es_admin:
                return _respuesta_tarea("La tarea no existe", 404)
            _fallo("autorizacion", "tarea_id", "")
            return _respuesta_tarea("No tienes permiso sobre esta tarea", 403)
    finally:
        conn.close()

    logger.info(
        "Auditoria: tarea_eliminada tarea_id=%s usuario_id=%s rol=%s",
        tarea_id, owner_id, usuario["rol"],
    )
    if _es_formulario():
        return redirect(url_for("dashboard", ok="eliminada"))
    return jsonify({"id": tarea_id, "eliminada": True}), 200


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Cierra la sesion web y revoca el token Bearer enviado (si lo hay)."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and auth[7:].strip():
        conn = get_db()
        try:
            conn.execute(
                "UPDATE TokenSesion SET revocado = 1 WHERE token_hash = ?",
                (_hash_token(auth[7:].strip()),),
            )
            conn.commit()
        finally:
            conn.close()
    session.clear()
    return jsonify({"mensaje": "Sesion cerrada"}), 200


# ---------------------------------------------------------------------------
# Autenticacion: registro, login, cambio y recuperacion de clave (Ejercicio 1.2)
# ---------------------------------------------------------------------------

# Hash ficticio: si el correo no existe igual se ejecuta bcrypt, para que el
# tiempo de respuesta no revele si la cuenta existe.
_HASH_FICTICIO = bcrypt.hashpw(b"clave-ficticia-123", bcrypt.gensalt()).decode("utf-8")


@app.route("/api/registro", methods=["POST"])
def registro():
    data, error = _leer_json_estricto(("mail", "clave"))
    if error:
        return _respuesta_auth(error, 400, tab="registro")

    mail = (data.get("mail") or "").strip().lower()
    clave = data.get("clave") or ""

    if not mail or not clave:
        return _respuesta_auth(
            "mail y clave son requeridos", 400, tab="registro", mail_form=mail
        )
    if len(mail) > 254 or not _RE_MAIL.fullmatch(mail):
        return _respuesta_auth("Formato de correo invalido", 400, tab="registro", mail_form=mail)
    error = _validar_clave_nueva(clave)
    if error:
        return _respuesta_auth(error, 400, tab="registro", mail_form=mail)

    clave_hash = bcrypt.hashpw(clave.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db()
    try:
        cur = conn.cursor()
        # El rol NUNCA viene del cliente: todo registro nuevo es Estudiante.
        cur.execute(
            "INSERT INTO Usuario (mail, clave, rol_id) VALUES (?, ?, ?)",
            (mail, clave_hash, ROL_ESTUDIANTE),
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return _respuesta_auth(
            "El mail ya esta registrado", 409, tab="registro", mail_form=mail
        )
    finally:
        conn.close()

    usuario = _usuario_por_id(user_id)
    _iniciar_sesion(usuario)
    logger.info("Auditoria: registro usuario_id=%s", user_id)

    if _es_formulario():
        return redirect(url_for("dashboard"))
    return jsonify({"rol": usuario["rol"]}), 201


def _respuesta_bloqueo(segundos):
    resp = app.make_response(
        _respuesta_auth("Demasiados intentos fallidos. Intenta mas tarde", 429)
    )
    resp.headers["Retry-After"] = str(segundos)
    return resp


@app.route("/api/login", methods=["POST"])
def login():
    ip = request.remote_addr or "desconocida"

    if _es_formulario():
        mail = request.form.get("mail")
        clave = request.form.get("clave")
    else:
        data = request.get_json(silent=True)
        data = data if isinstance(data, dict) else {}
        mail = data.get("mail")
        clave = data.get("clave")

    if not isinstance(mail, str) or not isinstance(clave, str) or not mail or not clave:
        return _respuesta_auth("Credenciales invalidas", 401)

    mail = mail.strip().lower()
    cuenta = "cuenta:" + mail

    # Limite por IP y por cuenta, con bloqueo temporal progresivo.
    espera = max(limite_ip.segundos_bloqueo(ip), limite_cuenta.segundos_bloqueo(cuenta))
    if espera:
        logger.warning("Login bloqueado: ip=%s cuenta=%s", ip, _enmascarar(mail))
        return _respuesta_bloqueo(espera)

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, clave FROM Usuario WHERE mail = ?", (mail,))
        row = cur.fetchone()
    finally:
        conn.close()

    hash_guardado = row["clave"] if row else _HASH_FICTICIO
    clave_valida = bcrypt.checkpw(clave.encode("utf-8"), hash_guardado.encode("utf-8"))

    if row is None or not clave_valida:
        b_ip = limite_ip.registrar_fallo(ip)
        b_cuenta = limite_cuenta.registrar_fallo(cuenta)
        # Se registra el intento fallido (RS-03) sin la clave ni el correo completo.
        logger.warning("Login fallido: ip=%s cuenta=%s", ip, _enmascarar(mail))
        if b_ip or b_cuenta:
            logger.warning(
                "Bloqueo temporal: ip=%s cuenta=%s duracion=%ss",
                ip, _enmascarar(mail), max(b_ip, b_cuenta),
            )
        # Mensaje generico: no revela si el correo existe.
        return _respuesta_auth("Credenciales invalidas", 401, mail_form=mail)

    limite_cuenta.limpiar(cuenta)

    usuario = _usuario_por_id(row["id"])
    _iniciar_sesion(usuario)
    token = _emitir_token(usuario["id"])
    logger.info("Auditoria: login_exitoso usuario_id=%s", usuario["id"])

    if _es_formulario():
        return redirect(url_for("dashboard"))
    return jsonify({"token": token, "expira_en": TOKEN_TTL, "rol": usuario["rol"]}), 200


@app.route("/api/cambiar-clave", methods=["POST"])
def cambiar_clave():
    """Cambia la clave y revoca TODAS las sesiones y tokens del usuario."""
    usuario = _usuario_actual()
    if not usuario:
        return jsonify({"error": "Sesion requerida"}), 401

    data, error = _leer_json_estricto(("clave_actual", "clave_nueva"))
    if error:
        return jsonify({"error": error}), 400

    actual = data.get("clave_actual") or ""
    nueva = data.get("clave_nueva") or ""
    if not actual or not bcrypt.checkpw(actual.encode("utf-8"), usuario["clave"].encode("utf-8")):
        _fallo("clave_actual_incorrecta", "clave_actual", "")
        return jsonify({"error": "La clave actual es incorrecta"}), 400
    error = _validar_clave_nueva(nueva)
    if error:
        return jsonify({"error": error}), 400

    nuevo_hash = bcrypt.hashpw(nueva.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn = get_db()
    try:
        conn.execute("UPDATE Usuario SET clave = ? WHERE id = ?", (nuevo_hash, usuario["id"]))
        _revocar_todo(conn, usuario["id"])
        conn.commit()
    finally:
        conn.close()

    session.clear()
    logger.info("Auditoria: cambio_clave usuario_id=%s sesiones_revocadas=si", usuario["id"])
    return jsonify({"mensaje": "Clave actualizada. Inicia sesion nuevamente"}), 200


def _enviar_correo(destino, asunto, cuerpo):
    """Servicio de correo SIMULADO. En produccion se usaria SMTP o un proveedor."""
    BUZON_SIMULADO.append({"para": destino, "asunto": asunto, "cuerpo": cuerpo})
    del BUZON_SIMULADO[:-50]
    logger.info("Correo enviado: destino=%s asunto=%s", _enmascarar(destino), asunto)


@app.route("/api/recuperar", methods=["POST"])
def solicitar_recuperacion():
    """Genera un token de un solo uso y lo 'envia' por correo.

    La respuesta es siempre la misma para no revelar si el correo existe.
    """
    data, error = _leer_json_estricto(("mail",))
    if error:
        return jsonify({"error": error}), 400
    mail = (data.get("mail") or "").strip().lower()

    respuesta = (
        jsonify({"mensaje": "Si el correo esta registrado, recibiras un enlace de recuperacion"}),
        200,
    )
    if not mail:
        return respuesta

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM Usuario WHERE mail = ?", (mail,))
        row = cur.fetchone()
        if row is None:
            return respuesta

        # Invalida los tokens anteriores antes de emitir uno nuevo.
        cur.execute(
            "UPDATE TokenRecuperacion SET usado = 1 WHERE usuario_id = ? AND usado = 0",
            (row["id"],),
        )
        token = secrets.token_urlsafe(32)
        cur.execute(
            "INSERT INTO TokenRecuperacion (token_hash, usuario_id, expira_en) VALUES (?, ?, ?)",
            (_hash_token(token), row["id"], _ahora() + RESET_TTL),
        )
        conn.commit()
    finally:
        conn.close()

    _enviar_correo(
        mail,
        "Recuperacion de clave",
        "Usa este codigo en /api/restablecer (expira en %d min): %s" % (RESET_TTL // 60, token),
    )
    # El evento se registra SIN el token.
    logger.info("Auditoria: recuperacion_solicitada usuario_id=%s", row["id"])
    return respuesta


@app.route("/api/restablecer", methods=["POST"])
def restablecer_clave():
    """Consume un token de recuperacion valido (un solo uso, expiracion corta)."""
    data, error = _leer_json_estricto(("token", "clave_nueva"))
    if error:
        return jsonify({"error": error}), 400
    token = data.get("token") or ""
    nueva = data.get("clave_nueva") or ""

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, usuario_id, expira_en, usado FROM TokenRecuperacion WHERE token_hash = ?",
            (_hash_token(token),),
        )
        fila = cur.fetchone()
        if not token or fila is None or fila["usado"] or fila["expira_en"] <= _ahora():
            _fallo("token_recuperacion_invalido", "token", "")
            return jsonify({"error": "Token invalido o expirado"}), 400

        error = _validar_clave_nueva(nueva)
        if error:
            return jsonify({"error": error}), 400

        nuevo_hash = bcrypt.hashpw(nueva.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cur.execute("UPDATE Usuario SET clave = ? WHERE id = ?", (nuevo_hash, fila["usuario_id"]))
        cur.execute(
            "UPDATE TokenRecuperacion SET usado = 1 WHERE usuario_id = ?",
            (fila["usuario_id"],),
        )
        _revocar_todo(conn, fila["usuario_id"])
        conn.commit()
    finally:
        conn.close()

    session.clear()
    logger.info("Auditoria: clave_restablecida usuario_id=%s", fila["usuario_id"])
    return jsonify({"mensaje": "Clave restablecida. Inicia sesion nuevamente"}), 200


# ---------------------------------------------------------------------------
# Administracion de roles
# ---------------------------------------------------------------------------

@app.route("/api/usuarios/<int:usuario_id>/rol", methods=["PUT"])
def cambiar_rol(usuario_id):
    """Solo el Administrador puede asignar roles."""
    usuario = _usuario_actual()
    if not usuario:
        return jsonify({"error": "Sesion requerida"}), 401
    if usuario["rol_id"] != ROL_ADMIN:
        _fallo("autorizacion", "rol", "")
        return jsonify({"error": "Solo un administrador puede cambiar roles"}), 403

    data, error = _leer_json_estricto(("rol",))
    if error:
        return jsonify({"error": error}), 400
    rol_id = ROLES_POR_NOMBRE.get((data.get("rol") or "").strip().lower())
    if rol_id is None:
        return jsonify({"error": "Rol invalido. Usa: Administrador, Docente o Estudiante"}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE Usuario SET rol_id = ? WHERE id = ?", (rol_id, usuario_id))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"error": "Usuario no encontrado"}), 404
    finally:
        conn.close()

    logger.info(
        "Auditoria: cambio_rol usuario_id=%s nuevo_rol=%s por=%s",
        usuario_id, ROLES[rol_id], usuario["id"],
    )
    return jsonify({"id": usuario_id, "rol": ROLES[rol_id]}), 200


def _promover_desde_consola(mail, nombre_rol):
    """Uso: python app_auth_db.py promover <mail> <Administrador|Docente|Estudiante>"""
    rol_id = ROLES_POR_NOMBRE.get(nombre_rol.lower())
    if rol_id is None:
        print("Rol invalido. Usa: Administrador, Docente o Estudiante")
        return 1
    init_db()
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE Usuario SET rol_id = ? WHERE mail = ?", (rol_id, mail.strip().lower()))
        conn.commit()
        if cur.rowcount == 0:
            print("No existe un usuario con ese correo")
            return 1
    finally:
        conn.close()
    print("%s ahora es %s" % (mail, ROLES[rol_id]))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "promover":
        sys.exit(_promover_desde_consola(sys.argv[2], sys.argv[3]))
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
