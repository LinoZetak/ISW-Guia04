import re
import sqlite3
from flask import Flask, request, jsonify
from markupsafe import escape

app = Flask(__name__)

_RE_BUSQUEDA = re.compile(r"^[A-Za-z0-9 ÁÉÍÓÚÜÑáéíóúüñ_-]+$")
MAX_SEARCH_LEN = 80


def get_db_connection():
    conn = sqlite3.connect("reservas.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/api/reserva", methods=["GET"])
def obtener_reserva():
    id_reserva = request.args.get("id")
    user_id_session = request.args.get("user_id")

    # Validacion de entrada en servidor
    if not id_reserva or not id_reserva.isdigit() or not user_id_session:
        return jsonify({"error": "Parametros invalidos o sesion no provista"}), 400

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # 1. Mitigacion SQLi: consulta parametrizada con marcador '?'
        query = "SELECT * FROM reservas WHERE id = ?"
        reserva = cursor.execute(query, (id_reserva,)).fetchone()
    finally:
        conn.close()

    if reserva is None:
        return jsonify({"error": "Reserva no encontrada"}), 404

    # 2. Mitigacion IDOR: verificacion estricta de propiedad del objeto
    if str(reserva["usuario_id"]) != str(user_id_session):
        return jsonify({"error": "Acceso prohibido al recurso solicitante"}), 403

    return jsonify(dict(reserva)), 200


@app.route("/bienvenida", methods=["GET"])
def bienvenida():
    nombre = request.args.get("nombre", "")
    # 3. Mitigacion XSS: escapado explicito de entidades HTML
    nombre_seguro = escape(nombre)
    return f"<h1>Bienvenido, {nombre_seguro}!</h1>"


@app.route("/api/tasks/search_insecure", methods=["GET"])
def search_tasks_insecure():
    """Version insegura: concatena directamente el parametro de busqueda en SQL."""
    search = request.args.get("q", "")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Inseguro: un valor controlado por el usuario altera la estructura SQL
        query = "SELECT * FROM tasks WHERE title LIKE '%" + search + "%'"
        rows = cursor.execute(query).fetchall()
        return jsonify({"results": [dict(r) for r in rows]}), 200
    finally:
        conn.close()


@app.route("/api/tasks/search", methods=["GET"])
def search_tasks_secure():
    """Version segura: consulta parametrizada + validacion de longitud y caracteres."""
    search = request.args.get("q")
    if search is None or not search.strip():
        return jsonify({"error": "El parametro de busqueda 'q' es obligatorio"}), 400

    q = search.strip()
    if len(q) > MAX_SEARCH_LEN:
        return jsonify({"error": f"La busqueda no puede superar {MAX_SEARCH_LEN} caracteres"}), 400

    if not _RE_BUSQUEDA.fullmatch(q):
        return jsonify({"error": "La busqueda contiene caracteres no permitidos"}), 400

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Consulta parametrizada (?) separando datos de la sentencia SQL
        query = "SELECT * FROM tasks WHERE title LIKE ? ESCAPE '\\'"
        patron = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = cursor.execute(query, (patron,)).fetchall()
        return jsonify({"results": [dict(r) for r in rows]}), 200
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(debug=False, port=5000)