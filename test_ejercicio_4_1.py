import os
import sqlite3
import unittest
from app_segura import app


class TestEjercicioPropuesto41(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reservas.db")
        conn = sqlite3.connect(db_file)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL
                )
                """
            )
            cur.execute("DELETE FROM tasks")
            cur.executemany(
                "INSERT INTO tasks (title) VALUES (?)",
                [
                    ("Auditoria de seguridad",),
                    ("Revisión de logs y SQLi",),
                ],
            )
            conn.commit()
        finally:
            conn.close()

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_01_busqueda_normal(self):
        resp = self.client.get("/api/tasks/search?q=Auditoria")
        self.assertEqual(resp.status_code, 200)
        print("[4.1-01 Normal OK]:", resp.get_json())

    def test_02_cadena_muy_larga(self):
        resp = self.client.get("/api/tasks/search?q=" + ("a" * 81))
        self.assertEqual(resp.status_code, 400)
        print("[4.1-02 Cadena larga 400 OK]:", resp.get_json())

    def test_03_comillas_y_sqli(self):
        resp = self.client.get("/api/tasks/search?q=' OR '1'='1")
        self.assertEqual(resp.status_code, 400)
        print("[4.1-03 Comillas/SQLi 400 OK]:", resp.get_json())

    def test_04_caracteres_especiales(self):
        resp = self.client.get("/api/tasks/search?q=<script>alert(1)</script>")
        self.assertEqual(resp.status_code, 400)
        print("[4.1-04 Caracteres especiales 400 OK]:", resp.get_json())

    def test_05_valor_nulo_o_vacio(self):
        resp = self.client.get("/api/tasks/search")
        self.assertEqual(resp.status_code, 400)
        print("[4.1-05 Sin parametro/nulo 400 OK]:", resp.get_json())


if __name__ == "__main__":
    unittest.main(verbosity=2)