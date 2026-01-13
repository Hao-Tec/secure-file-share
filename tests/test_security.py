
import unittest
import sys
import os

# Add parent directory to path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_metadata, app

class TestSecurity(unittest.TestCase):
    def test_share_token_entropy(self):
        """Test that share tokens have sufficient length/entropy."""
        with app.app_context():
            metadata = create_metadata("test_file.txt")
            token = metadata['share_token']

            # Check length: 16 bytes base64 encoded is approx 22 chars
            self.assertGreater(len(token), 16, "Token should be longer than 16 characters")

            # Check for URL safety (alphanumeric + - _)
            import re
            self.assertTrue(re.match(r'^[a-zA-Z0-9\-_]+$', token), "Token must be URL safe")

            # Check randomness (generate multiple and check uniqueness)
            tokens = set()
            for _ in range(100):
                m = create_metadata("test.txt")
                tokens.add(m['share_token'])

            self.assertEqual(len(tokens), 100, "Tokens must be unique")

if __name__ == '__main__':
    unittest.main()
