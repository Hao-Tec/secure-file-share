import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Mock psycopg2 before importing database
mock_psycopg2 = MagicMock()
sys.modules["psycopg2"] = mock_psycopg2
sys.modules["psycopg2.extras"] = MagicMock()

# Add parent directory to path to import database
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database

class TestOptimization(unittest.TestCase):
    def test_list_files_query(self):
        # Patch the global variable DATABASE_URL in database module
        with patch('database.DATABASE_URL', 'postgres://fake:5432/db'):
            mock_conn = MagicMock()
            mock_psycopg2.connect.return_value = mock_conn
            mock_cur = MagicMock()
            mock_conn.cursor.return_value = mock_cur

            # Mock fetchall to return empty list
            mock_cur.fetchall.return_value = []

            database.list_files()

            # Verify the query
            calls = mock_cur.execute.call_args_list
            found = False
            for call in calls:
                query = call[0][0]
                # Normalize whitespace for comparison
                query_norm = " ".join(query.split())
                if "ORDER BY metadata->>'expires_at' DESC" in query_norm:
                    found = True
                    break

            self.assertTrue(found, "Query does not contain 'ORDER BY metadata->>'expires_at' DESC'")
            print("\n✅ Verification passed: Query contains optimization ORDER BY clause.")

if __name__ == '__main__':
    unittest.main()
