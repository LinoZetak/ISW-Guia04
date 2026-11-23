import unittest
from app_auth_db import app, init_db


class TestEjercicioPropuesto31(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def _autenticar(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["mail"] = "tester@unsaac.edu.pe"
            sess["rol"] = "User"

    def test_01_sin_autenticacion_rechazada(self):
        resp = self.client.post(
            "/tasks",
            json={"title": "Tarea sin auth", "description": "Prueba", "status": "pendiente"},
        )
        self.assertEqual(resp.status_code, 401)
        print("[401 OK - Sin auth]:", resp.get_json())

    def test_02_campo_vacio_rechazado(self):
        self._autenticar()
        resp = self.client.post(
            "/tasks",
            json={"title": "   ", "description": "Sin titulo", "status": "pendiente"},
        )
        self.assertEqual(resp.status_code, 400)
        print("[400 OK - Titulo vacio]:", resp.get_json())

    def test_03_campo_demasiado_largo_rechazado(self):
        self._autenticar()
        resp_title = self.client.post(
            "/tasks",
            json={"title": "T" * 121, "description": "Valida", "status": "pendiente"},
        )
        self.assertEqual(resp_title.status_code, 400)

        resp_desc = self.client.post(
            "/tasks",
            json={
                "title": "Titulo valido",
                "description": "D" * 1001,
                "status": "en_progreso",
            },
        )
        self.assertEqual(resp_desc.status_code, 400)
        print("[400 OK - Longitud excedida]:", resp_title.get_json(), "|", resp_desc.get_json())

    def test_04_estado_invalido_rechazado(self):
        self._autenticar()
        resp = self.client.post(
            "/tasks",
            json={"title": "Tarea estado malo", "description": "", "status": "cancelada"},
        )
        self.assertEqual(resp.status_code, 400)
        print("[400 OK - Estado invalido]:", resp.get_json())

    def test_05_campo_inyectado_role_admin_rechazado(self):
        self._autenticar()
        resp = self.client.post(
            "/tasks",
            json={
                "title": "Intento escalacion",
                "description": "Inyectando campo extra",
                "status": "pendiente",
                "role": "admin",
            },
        )
        self.assertEqual(resp.status_code, 400)
        print("[400 OK - Campo extra role]:", resp.get_json())

    def test_06_unicode_y_espacios_aceptado(self):
        self._autenticar()
        resp = self.client.post(
            "/tasks",
            json={
                "title": "   Auditoria   de   seguridad — Ñandú & Cusco   ",
                "description": "Soporte de tildes áéíóú, ñ y espacios múltiples.",
                "status": "completada",
            },
        )
        self.assertEqual(resp.status_code, 201)
        print("[201 OK - Unicode y espacios]:", resp.get_json())

    def test_07_endpoint_inseguro_acepta_campo_extra(self):
        resp = self.client.post(
            "/tasks_insecure",
            json={"title": "Colado", "status": "pendiente", "role": "admin"},
        )
        self.assertEqual(resp.status_code, 201)
        print("[201 INSEGURO - Acepta role=admin]:", resp.get_json())


if __name__ == "__main__":
    unittest.main(verbosity=2)