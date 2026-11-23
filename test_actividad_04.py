import os
import sqlite3
import unittest
from app_segura import app


class TestActividad04(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reservas.db")
        conn = sqlite3.connect(db_file)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS reservas (
                    id INTEGER PRIMARY KEY,
                    usuario_id INTEGER NOT NULL,
                    detalle TEXT NOT NULL
                )
                """
            )
            cur.execute("DELETE FROM reservas WHERE id IN (1, 105)")
            cur.executemany(
                "INSERT INTO reservas (id, usuario_id, detalle) VALUES (?, ?, ?)",
                [
                    (1, 10, "Reserva de prueba 1"),
                    (105, 10, "Reserva privada del usuario 10"),
                ],
            )
            conn.commit()
        finally:
            conn.close()

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_pr01_sqli_rechazada(self):
        resp = self.client.get("/api/reserva?id=1%20OR%201=1&user_id=10")
        self.assertIn(resp.status_code, (400, 404))
        print("[PR-01 SQLi OK]: status=", resp.status_code, "body=", resp.get_json())

    def test_pr02_idor_denegado_403(self):
        resp = self.client.get("/api/reserva?id=105&user_id=99")
        self.assertEqual(resp.status_code, 403)
        print("[PR-02 IDOR OK]: status=", resp.status_code, "body=", resp.get_json())

    def test_pr03_xss_escapado(self):
        resp = self.client.get("/bienvenida?nombre=<script>alert(1)</script>")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        print("[PR-03 XSS OK]: html=", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)