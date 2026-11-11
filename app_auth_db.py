import os
import secrets
import sqlite3
import threading

import bcrypt
from flask import Flask, request, jsonify

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db")

app = Flask(__name__)

lock = threading.Lock()
failed_attempts = {}
MAX_FAILED = 5


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


@app.route("/api/registro", methods=["POST"])
def registro():
    data = request.get_json(silent=True) or {}
    mail = data.get("mail")
    clave = data.get("clave")

    if not mail or not clave:
        return jsonify({"error": "mail y clave son requeridos"}), 400

    clave_hash = bcrypt.hashpw(clave.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO Usuario (mail, clave, rol_id) VALUES (?, ?, ?)",
            (mail, clave_hash, 3),
        )
        conn.commit()
        cur.execute("SELECT nombre FROM Rol WHERE id = 3")
        rol_nombre = cur.fetchone()["nombre"]
    except sqlite3.IntegrityError:
        return jsonify({"error": "El mail ya esta registrado"}), 409
    finally:
        conn.close()

    return jsonify({"rol": rol_nombre}), 201


@app.route("/api/login", methods=["POST"])
def login():
    ip = request.remote_addr

    with lock:
        if failed_attempts.get(ip, 0) >= MAX_FAILED:
            return jsonify({"error": "Demasiados intentos fallidos. Intenta mas tarde"}), 429

    data = request.get_json(silent=True) or {}
    mail = data.get("mail")
    clave = data.get("clave")

    if not mail or not clave:
        return jsonify({"error": "Credenciales invalidas"}), 401

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
        return jsonify({"error": "Credenciales invalidas"}), 401

    clave_valida = bcrypt.checkpw(
        clave.encode("utf-8"), row["clave"].encode("utf-8")
    )

    if not clave_valida:
        with lock:
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        return jsonify({"error": "Credenciales invalidas"}), 401

    with lock:
        failed_attempts[ip] = 0

    token = secrets.token_hex(32)
    return jsonify({"token": token, "rol": row["rol_nombre"]}), 200


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
