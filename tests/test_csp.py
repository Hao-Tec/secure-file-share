import unittest
from app import app

class TestCSP(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_csp_header_no_unsafe_inline(self):
        response = self.app.get('/')
        csp = response.headers.get('Content-Security-Policy', '')
        print(f"\nCSP Header: {csp}")
        self.assertIn("style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com", csp)
        self.assertNotIn("'unsafe-inline'", csp.split("style-src")[1].split(";")[0])

if __name__ == '__main__':
    unittest.main()
