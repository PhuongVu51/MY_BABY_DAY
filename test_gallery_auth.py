import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

import gallery_server


class GalleryAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_directory = tempfile.TemporaryDirectory()
        cls.original_database_path = gallery_server.DATABASE_PATH
        gallery_server.DATABASE_PATH = Path(cls.temp_directory.name) / "responses.sqlite3"
        gallery_server.initialize_database()
        cls.server = gallery_server.ThreadingHTTPServer(
            ("127.0.0.1", 0), gallery_server.GalleryHandler
        )
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.session_tokens = []

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()
        with gallery_server._sessions_lock:
            for token in cls.session_tokens:
                gallery_server._sessions.pop(token, None)
        gallery_server.DATABASE_PATH = cls.original_database_path
        cls.temp_directory.cleanup()

    def _request(self, method, path, payload=None, cookie=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if cookie is not None:
            headers["Cookie"] = cookie

        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        response_headers = {
            name.lower(): value for name, value in response.getheaders()
        }
        connection.close()
        return response.status, response_headers, response_body

    def _login(self, password):
        status, headers, _ = self._request(
            "POST", "/api/login", payload={"password": password}
        )
        if status == 200:
            cookie = headers["set-cookie"].split(";", 1)[0]
            self.session_tokens.append(cookie.split("=", 1)[1])
        return status, headers

    def test_index_and_its_stylesheet_are_public(self):
        index_status, _, index_body = self._request("GET", "/")
        stylesheet_status, _, _ = self._request("GET", "/style.css")

        self.assertEqual(index_status, 200)
        self.assertIn(b"Vault Deep Access", index_body)
        self.assertEqual(stylesheet_status, 200)

    def test_unauthenticated_private_pages_and_images_redirect_to_index(self):
        for path in (
            "/vault.html",
            "/appointment.html",
            "/polaroid-images/cafe.jpg",
            "/polaroid-images/Xem%20phim.jpg",
            "/polaroid-images/nh%C3%A0%20h%C3%A0ng%201.jpg",
        ):
            with self.subTest(path=path):
                status, headers, _ = self._request("GET", path)
                self.assertEqual(status, 302)
                self.assertEqual(headers["location"], "/index.html")

    def test_authenticated_session_can_load_appointment_images_from_gallery(self):
        _, login_headers = self._login("050105")
        cookie = login_headers["set-cookie"].split(";", 1)[0]

        for path in (
            "/polaroid-images/cafe.jpg",
            "/polaroid-images/Xem%20phim.jpg",
            "/polaroid-images/nh%C3%A0%20h%C3%A0ng%201.jpg",
        ):
            with self.subTest(path=path):
                status, headers, body = self._request("GET", path, cookie=cookie)
                self.assertEqual(status, 200)
                self.assertEqual(headers["content-type"], "image/jpeg")
                self.assertTrue(body)

    def test_private_apis_reject_unauthenticated_requests(self):
        response_status, _, _ = self._request("GET", "/api/appointment-response")
        photos_status, _, _ = self._request("GET", "/api/photos")
        save_status, _, _ = self._request(
            "POST",
            "/api/appointment-response",
            payload={"activity": "movie"},
        )

        self.assertEqual(response_status, 401)
        self.assertEqual(photos_status, 401)
        self.assertEqual(save_status, 401)

    def test_authenticated_session_can_save_and_read_appointment_response(self):
        login_status, login_headers = self._login("050105")
        cookie = login_headers["set-cookie"].split(";", 1)[0]
        save_status, _, saved_body = self._request(
            "POST",
            "/api/appointment-response",
            payload={"activity": "movie", "answer": "accept"},
            cookie=cookie,
        )
        read_status, _, read_body = self._request(
            "GET", "/api/appointment-response", cookie=cookie
        )

        self.assertEqual(login_status, 200)
        self.assertEqual(save_status, 200)
        self.assertEqual(read_status, 200)
        self.assertEqual(
            json.loads(saved_body)["response"]["activity"],
            "movie",
        )
        self.assertEqual(
            json.loads(read_body)["response"]["answer"],
            "accept",
        )

    def test_existing_and_test_passwords_create_authenticated_sessions(self):
        for password in ("150306", "050105"):
            with self.subTest(password=password):
                status, headers = self._login(password)
                cookie = headers["set-cookie"].split(";", 1)[0]
                page_status, _, _ = self._request(
                    "GET", "/vault.html", cookie=cookie
                )
                photos_status, _, _ = self._request(
                    "GET", "/api/photos", cookie=cookie
                )

                self.assertEqual(status, 200)
                self.assertIn("httponly", headers["set-cookie"].lower())
                self.assertIn("samesite=lax", headers["set-cookie"].lower())
                self.assertEqual(page_status, 200)
                self.assertEqual(photos_status, 200)

    def test_invalid_password_does_not_authorize_access(self):
        status, _ = self._login("999999")
        page_status, headers, _ = self._request("GET", "/vault.html")

        self.assertEqual(status, 401)
        self.assertEqual(page_status, 302)
        self.assertEqual(headers["location"], "/index.html")


if __name__ == "__main__":
    unittest.main()
