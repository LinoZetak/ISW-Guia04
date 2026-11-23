"""Ejercicio Propuesto 1.2 + roles: pruebas de seguridad de autenticacion y sesion.

Cubre: credenciales invalidas, fuerza bruta simulada (bloqueo progresivo por IP
y por cuenta), reutilizacion de token, sesion y token expirados, revocacion al
cambiar la clave, recuperacion de clave y control de acceso por rol.
"""
import os
import tempfile
import time
import unittest
from unittest import mock

import app_auth_db
from app_auth_db import ROL_ADMIN, ROL_DOCENTE, app, init_db

CLAVE = "Segura2026"


class BaseSeguridad(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._db_original = app_auth_db.DB_PATH
        app_auth_db.DB_PATH = os.path.join(self._tmp.name, "test_1_2.db")
        init_db()
        app.config["TESTING"] = True
        app_auth_db.limite_ip.reiniciar()
        app_auth_db.limite_cuenta.reiniciar()
        app_auth_db.BUZON_SIMULADO.clear()

    def tearDown(self):
        app_auth_db.DB_PATH = self._db_original
        app_auth_db.limite_ip.reiniciar()
        app_auth_db.limite_cuenta.reiniciar()
        self._tmp.cleanup()

    # --- utilidades ---
    def registrar(self, mail, clave=CLAVE, rol_id=None):
        cliente = app.test_client()
        resp = cliente.post("/api/registro", json={"mail": mail, "clave": clave})
        self.assertEqual(resp.status_code, 201, resp.get_json())
        if rol_id is not None:
            conn = app_auth_db.get_db()
            conn.execute("UPDATE Usuario SET rol_id = ? WHERE mail = ?", (rol_id, mail))
            conn.commit()
            conn.close()
        return self.id_de(mail)

    def id_de(self, mail):
        conn = app_auth_db.get_db()
        fila = conn.execute("SELECT id FROM Usuario WHERE mail = ?", (mail,)).fetchone()
        conn.close()
        return fila["id"]

    def login(self, mail, clave=CLAVE, cliente=None, ip="10.0.0.1"):
        cliente = cliente or app.test_client()
        return cliente.post(
            "/api/login",
            json={"mail": mail, "clave": clave},
            environ_base={"REMOTE_ADDR": ip},
        )

    def token(self, mail, clave=CLAVE):
        resp = self.login(mail, clave)
        self.assertEqual(resp.status_code, 200)
        return resp.get_json()["token"]

    @staticmethod
    def bearer(token):
        return {"Authorization": "Bearer " + token}


class TestCredencialesYFuerzaBruta(BaseSeguridad):
    def test_01_credenciales_invalidas_mensaje_generico(self):
        self.registrar("ana@unsaac.edu.pe")
        r_clave = self.login("ana@unsaac.edu.pe", "ClaveMala99")
        r_mail = self.login("noexiste@unsaac.edu.pe", "ClaveMala99")
        self.assertEqual(r_clave.status_code, 401)
        self.assertEqual(r_mail.status_code, 401)
        # Mismo mensaje: no revela si el correo existe.
        self.assertEqual(r_clave.get_json(), r_mail.get_json())
        print("[1.2-01 401 generico OK]:", r_clave.get_json())

    def test_02_fuerza_bruta_bloquea_con_429(self):
        self.registrar("ana@unsaac.edu.pe")
        for _ in range(app_auth_db.MAX_FAILED):
            self.assertEqual(self.login("ana@unsaac.edu.pe", "Intento000").status_code, 401)
        # Incluso con la clave correcta, la cuenta queda bloqueada temporalmente.
        resp = self.login("ana@unsaac.edu.pe", CLAVE)
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)
        print("[1.2-02 Fuerza bruta 429 OK]: Retry-After =", resp.headers["Retry-After"])

    def test_03_bloqueo_temporal_progresivo(self):
        self.registrar("ana@unsaac.edu.pe")
        t0 = time.time()
        with mock.patch.object(app_auth_db, "_ahora", return_value=t0):
            for _ in range(app_auth_db.MAX_FAILED):
                self.login("ana@unsaac.edu.pe", "Intento000")
            primer = int(self.login("ana@unsaac.edu.pe", CLAVE).headers["Retry-After"])
        # Pasado el primer bloqueo, se puede intentar de nuevo...
        t1 = t0 + app_auth_db.BLOQUEO_BASE + 1
        with mock.patch.object(app_auth_db, "_ahora", return_value=t1):
            for _ in range(app_auth_db.MAX_FAILED):
                self.assertEqual(self.login("ana@unsaac.edu.pe", "Intento000").status_code, 401)
            segundo = int(self.login("ana@unsaac.edu.pe", CLAVE).headers["Retry-After"])
        # ...pero el segundo bloqueo dura el doble.
        self.assertGreater(segundo, primer)
        self.assertAlmostEqual(segundo, 2 * app_auth_db.BLOQUEO_BASE, delta=2)
        print("[1.2-03 Bloqueo progresivo OK]: %ss -> %ss" % (primer, segundo))

    def test_04_limite_por_cuenta_aunque_cambie_la_ip(self):
        self.registrar("ana@unsaac.edu.pe")
        for i in range(app_auth_db.MAX_FAILED):
            self.login("ana@unsaac.edu.pe", "Intento000", ip="10.0.0.%d" % (i + 10))
        resp = self.login("ana@unsaac.edu.pe", CLAVE, ip="10.9.9.9")
        self.assertEqual(resp.status_code, 429)
        print("[1.2-04 Limite por cuenta OK]: 429 desde una IP nueva")

    def test_05_limite_por_ip_aunque_cambie_la_cuenta(self):
        self.registrar("ana@unsaac.edu.pe")
        for i in range(app_auth_db.MAX_FAILED):
            self.login("victima%d@unsaac.edu.pe" % i, "Intento000", ip="10.6.6.6")
        resp = self.login("ana@unsaac.edu.pe", CLAVE, ip="10.6.6.6")
        self.assertEqual(resp.status_code, 429)
        print("[1.2-05 Limite por IP OK]: 429 para la IP atacante")

    def test_06_login_fallido_queda_en_log_sin_la_clave(self):
        self.registrar("ana@unsaac.edu.pe")
        with self.assertLogs("taskguard", level="WARNING") as logs:
            self.login("ana@unsaac.edu.pe", "ClaveSecretaXYZ1")
        salida = "\n".join(logs.output)
        self.assertIn("Login fallido", salida)
        self.assertNotIn("ClaveSecretaXYZ1", salida)
        self.assertNotIn("ana@unsaac.edu.pe", salida)
        print("[1.2-06 Log de intento fallido OK]:", logs.output[0])


class TestTokensYSesiones(BaseSeguridad):
    def test_07_token_falso_rechazado(self):
        resp = app.test_client().get("/tareas", headers=self.bearer("token-inventado"))
        self.assertEqual(resp.status_code, 401)
        print("[1.2-07 Token falso 401 OK]")

    def test_08_token_valido_accede(self):
        self.registrar("ana@unsaac.edu.pe")
        tok = self.token("ana@unsaac.edu.pe")
        resp = app.test_client().get("/tareas", headers=self.bearer(tok))
        self.assertEqual(resp.status_code, 200)
        print("[1.2-08 Token valido 200 OK]")

    def test_09_token_expirado_rechazado(self):
        self.registrar("ana@unsaac.edu.pe")
        tok = self.token("ana@unsaac.edu.pe")
        futuro = time.time() + app_auth_db.TOKEN_TTL + 1
        with mock.patch.object(app_auth_db, "_ahora", return_value=futuro):
            resp = app.test_client().get("/tareas", headers=self.bearer(tok))
        self.assertEqual(resp.status_code, 401)
        print("[1.2-09 Token expirado 401 OK]")

    def test_10_reutilizacion_de_token_tras_logout(self):
        self.registrar("ana@unsaac.edu.pe")
        tok = self.token("ana@unsaac.edu.pe")
        cliente = app.test_client()
        self.assertEqual(cliente.post("/api/logout", headers=self.bearer(tok)).status_code, 200)
        resp = cliente.get("/tareas", headers=self.bearer(tok))
        self.assertEqual(resp.status_code, 401)
        print("[1.2-10 Reutilizacion de token 401 OK]")

    def test_11_sesion_web_expirada(self):
        self.registrar("ana@unsaac.edu.pe")
        cliente = app.test_client()
        self.login("ana@unsaac.edu.pe", cliente=cliente)
        self.assertEqual(cliente.get("/tareas").status_code, 200)
        futuro = time.time() + app_auth_db.SESSION_TTL + 1
        with mock.patch.object(app_auth_db, "_ahora", return_value=futuro):
            self.assertEqual(cliente.get("/tareas").status_code, 401)
        print("[1.2-11 Sesion expirada 401 OK]")

    def test_12_sesion_regenerada_tras_login(self):
        self.registrar("ana@unsaac.edu.pe")
        cliente = app.test_client()
        with cliente.session_transaction() as sess:
            sess["dato_fijado_por_atacante"] = "x"
        self.login("ana@unsaac.edu.pe", cliente=cliente)
        with cliente.session_transaction() as sess:
            self.assertNotIn("dato_fijado_por_atacante", sess)
            self.assertIn("login_at", sess)
        print("[1.2-12 Regeneracion de sesion OK]")

    def test_13_cambio_de_clave_revoca_todas_las_sesiones(self):
        self.registrar("ana@unsaac.edu.pe")
        tok_viejo = self.token("ana@unsaac.edu.pe")
        navegador = app.test_client()
        self.login("ana@unsaac.edu.pe", cliente=navegador)

        resp = app.test_client().post(
            "/api/cambiar-clave",
            json={"clave_actual": CLAVE, "clave_nueva": "NuevaClave2026"},
            headers=self.bearer(tok_viejo),
        )
        self.assertEqual(resp.status_code, 200)
        # Token y sesion web anteriores quedan revocados.
        self.assertEqual(app.test_client().get("/tareas", headers=self.bearer(tok_viejo)).status_code, 401)
        self.assertEqual(navegador.get("/tareas").status_code, 401)
        # La clave vieja ya no sirve; la nueva si.
        self.assertEqual(self.login("ana@unsaac.edu.pe", CLAVE).status_code, 401)
        self.assertEqual(self.login("ana@unsaac.edu.pe", "NuevaClave2026").status_code, 200)
        print("[1.2-13 Revocacion al cambiar clave OK]")

    def test_14_cambio_de_clave_exige_clave_actual(self):
        self.registrar("ana@unsaac.edu.pe")
        tok = self.token("ana@unsaac.edu.pe")
        resp = app.test_client().post(
            "/api/cambiar-clave",
            json={"clave_actual": "NoEsMiClave1", "clave_nueva": "NuevaClave2026"},
            headers=self.bearer(tok),
        )
        self.assertEqual(resp.status_code, 400)
        print("[1.2-14 Clave actual incorrecta 400 OK]")


class TestRecuperacion(BaseSeguridad):
    def _pedir_token(self, mail):
        resp = app.test_client().post("/api/recuperar", json={"mail": mail})
        self.assertEqual(resp.status_code, 200)
        return app_auth_db.BUZON_SIMULADO[-1]["cuerpo"].rsplit(": ", 1)[1]

    def test_15_respuesta_generica_si_el_correo_no_existe(self):
        self.registrar("ana@unsaac.edu.pe")
        r1 = app.test_client().post("/api/recuperar", json={"mail": "ana@unsaac.edu.pe"})
        r2 = app.test_client().post("/api/recuperar", json={"mail": "nadie@unsaac.edu.pe"})
        self.assertEqual(r1.get_json(), r2.get_json())
        self.assertEqual(len(app_auth_db.BUZON_SIMULADO), 1)
        print("[1.2-15 Recuperacion generica OK]:", r1.get_json())

    def test_16_token_de_un_solo_uso(self):
        self.registrar("ana@unsaac.edu.pe")
        tok = self._pedir_token("ana@unsaac.edu.pe")
        c = app.test_client()
        r1 = c.post("/api/restablecer", json={"token": tok, "clave_nueva": "Recuperada2026"})
        r2 = c.post("/api/restablecer", json={"token": tok, "clave_nueva": "OtraClave2026"})
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 400)
        self.assertEqual(self.login("ana@unsaac.edu.pe", "Recuperada2026").status_code, 200)
        print("[1.2-16 Token un solo uso OK]: segundo uso ->", r2.get_json())

    def test_17_token_de_recuperacion_expira(self):
        self.registrar("ana@unsaac.edu.pe")
        tok = self._pedir_token("ana@unsaac.edu.pe")
        futuro = time.time() + app_auth_db.RESET_TTL + 1
        with mock.patch.object(app_auth_db, "_ahora", return_value=futuro):
            resp = app.test_client().post(
                "/api/restablecer", json={"token": tok, "clave_nueva": "Recuperada2026"}
            )
        self.assertEqual(resp.status_code, 400)
        print("[1.2-17 Token expirado 400 OK]")

    def test_18_nuevo_token_invalida_los_anteriores(self):
        self.registrar("ana@unsaac.edu.pe")
        viejo = self._pedir_token("ana@unsaac.edu.pe")
        nuevo = self._pedir_token("ana@unsaac.edu.pe")
        c = app.test_client()
        self.assertEqual(
            c.post("/api/restablecer", json={"token": viejo, "clave_nueva": "Recuperada2026"}).status_code,
            400,
        )
        self.assertEqual(
            c.post("/api/restablecer", json={"token": nuevo, "clave_nueva": "Recuperada2026"}).status_code,
            200,
        )
        print("[1.2-18 Invalidacion de tokens anteriores OK]")

    def test_19_evento_registrado_sin_exponer_el_token(self):
        self.registrar("ana@unsaac.edu.pe")
        with self.assertLogs("taskguard", level="INFO") as logs:
            tok = self._pedir_token("ana@unsaac.edu.pe")
        salida = "\n".join(logs.output)
        self.assertIn("recuperacion_solicitada", salida)
        self.assertNotIn(tok, salida)
        print("[1.2-19 Log sin token OK]")

    def test_20_restablecer_revoca_sesiones_abiertas(self):
        self.registrar("ana@unsaac.edu.pe")
        tok_sesion = self.token("ana@unsaac.edu.pe")
        tok = self._pedir_token("ana@unsaac.edu.pe")
        app.test_client().post("/api/restablecer", json={"token": tok, "clave_nueva": "Recuperada2026"})
        resp = app.test_client().get("/tareas", headers=self.bearer(tok_sesion))
        self.assertEqual(resp.status_code, 401)
        print("[1.2-20 Restablecer revoca sesiones OK]")


class TestRegistro(BaseSeguridad):
    def test_21_registro_rechaza_role_admin(self):
        resp = app.test_client().post(
            "/api/registro",
            json={"mail": "eva@unsaac.edu.pe", "clave": CLAVE, "rol": "Administrador"},
        )
        self.assertEqual(resp.status_code, 400)
        print("[1.2-21 role=admin en registro 400 OK]:", resp.get_json())

    def test_22_registro_rechaza_clave_debil_y_mail_invalido(self):
        c = app.test_client()
        self.assertEqual(c.post("/api/registro", json={"mail": "eva@unsaac.edu.pe", "clave": "1234"}).status_code, 400)
        self.assertEqual(c.post("/api/registro", json={"mail": "eva@unsaac.edu.pe", "clave": "solotexto"}).status_code, 400)
        self.assertEqual(c.post("/api/registro", json={"mail": "no-es-correo", "clave": CLAVE}).status_code, 400)
        print("[1.2-22 Clave debil / mail invalido 400 OK]")

    def test_23_registro_asigna_rol_estudiante(self):
        resp = app.test_client().post("/api/registro", json={"mail": "eva@unsaac.edu.pe", "clave": CLAVE})
        self.assertEqual(resp.get_json()["rol"], "Estudiante")
        print("[1.2-23 Rol por defecto Estudiante OK]")


class TestRoles(BaseSeguridad):
    def setUp(self):
        super().setUp()
        self.est_id = self.registrar("est@unsaac.edu.pe")
        self.registrar("doc@unsaac.edu.pe", rol_id=ROL_DOCENTE)
        self.registrar("adm@unsaac.edu.pe", rol_id=ROL_ADMIN)
        self.tok_est = self.token("est@unsaac.edu.pe")
        self.tok_doc = self.token("doc@unsaac.edu.pe")
        self.tok_adm = self.token("adm@unsaac.edu.pe")
        resp = app.test_client().post(
            "/tasks",
            json={"title": "Tarea del estudiante", "description": "", "status": "pendiente"},
            headers=self.bearer(self.tok_est),
        )
        self.tarea_est = resp.get_json()["id"]

    def test_24_tarea_por_token_queda_a_nombre_del_usuario(self):
        conn = app_auth_db.get_db()
        owner = conn.execute("SELECT owner_id FROM Tarea WHERE id = ?", (self.tarea_est,)).fetchone()[0]
        conn.close()
        self.assertEqual(owner, self.est_id)
        print("[R-24 owner_id = usuario del token OK]")

    def test_25_estudiante_no_ve_todas_las_tareas(self):
        resp = app.test_client().get("/tareas?todas=1", headers=self.bearer(self.tok_est))
        self.assertEqual(resp.status_code, 403)
        print("[R-25 Estudiante ?todas=1 403 OK]")

    def test_26_docente_ve_todas_las_tareas(self):
        resp = app.test_client().get("/tareas?todas=1", headers=self.bearer(self.tok_doc))
        self.assertEqual(resp.status_code, 200)
        ids = [t["id"] for t in resp.get_json()["tareas"]]
        self.assertIn(self.tarea_est, ids)
        print("[R-26 Docente ve todas 200 OK]")

    def test_27_listado_normal_solo_muestra_lo_propio(self):
        resp = app.test_client().get("/tareas", headers=self.bearer(self.tok_doc))
        self.assertEqual(resp.get_json()["tareas"], [])
        print("[R-27 Listado propio OK]")

    def test_28_docente_no_puede_borrar_tarea_ajena(self):
        resp = app.test_client().delete("/tareas/%d" % self.tarea_est, headers=self.bearer(self.tok_doc))
        self.assertEqual(resp.status_code, 403)
        print("[R-28 Docente borra ajena 403 OK]")

    def test_29_administrador_puede_borrar_tarea_ajena(self):
        resp = app.test_client().delete("/tareas/%d" % self.tarea_est, headers=self.bearer(self.tok_adm))
        self.assertEqual(resp.status_code, 200)
        print("[R-29 Admin borra ajena 200 OK]")

    def test_30_solo_admin_cambia_roles(self):
        url = "/api/usuarios/%d/rol" % self.est_id
        r_est = app.test_client().put(url, json={"rol": "Administrador"}, headers=self.bearer(self.tok_est))
        r_doc = app.test_client().put(url, json={"rol": "Administrador"}, headers=self.bearer(self.tok_doc))
        r_adm = app.test_client().put(url, json={"rol": "Docente"}, headers=self.bearer(self.tok_adm))
        self.assertEqual(r_est.status_code, 403)
        self.assertEqual(r_doc.status_code, 403)
        self.assertEqual(r_adm.status_code, 200)
        print("[R-30 Solo admin cambia roles OK]:", r_adm.get_json())


class TestDemoInsegura(BaseSeguridad):
    def test_31_endpoint_inseguro_deshabilitado_en_produccion(self):
        app.config["TESTING"] = False
        try:
            with mock.patch.dict(os.environ, {"HABILITAR_DEMO_INSEGURA": "0"}):
                resp = app.test_client().post("/tasks_insecure", json={"title": "x"})
        finally:
            app.config["TESTING"] = True
        self.assertEqual(resp.status_code, 404)
        print("[31 /tasks_insecure 404 en produccion OK]")


if __name__ == "__main__":
    unittest.main(verbosity=2)
