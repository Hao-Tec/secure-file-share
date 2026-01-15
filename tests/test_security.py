import unittest
from unittest.mock import patch, MagicMock
from app import app
import database

class TestSecurity(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    @patch('database.get_db_connection')
    def test_health_check(self, mock_db_conn):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_db_conn.return_value.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)

    def test_security_headers(self):
        response = self.app.get('/')
        headers = response.headers
        self.assertIn('X-Frame-Options', headers)
        self.assertEqual(headers['X-Frame-Options'], 'DENY')
        self.assertIn('Content-Security-Policy', headers)
        self.assertIn("default-src 'self'", headers['Content-Security-Policy'])

if __name__ == '__main__':
    unittest.main()
