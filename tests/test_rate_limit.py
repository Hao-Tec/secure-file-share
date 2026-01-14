import unittest
import sys
import os
import time
from unittest.mock import MagicMock, patch

# Add parent directory to path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock database before importing app
sys.modules['database'] = MagicMock()
sys.modules['database'].list_files.return_value = []
sys.modules['database'].cleanup_expired.return_value = 0

from app import app, limiter

class RateLimitTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        # Enable rate limiting for testing
        app.config['RATELIMIT_ENABLED'] = True
        app.config['RATELIMIT_STORAGE_URI'] = "memory://"
        # Reset limiter
        limiter.reset()

    def test_list_files_rate_limited(self):
        """Test that list_files IS rate limited."""
        status_codes = []
        # Limit is 30 per minute. Send 35 requests.
        for i in range(35):
            response = self.app.get('/api/files')
            status_codes.append(response.status_code)

        # We expect some 429s
        self.assertIn(429, status_codes, "Should be rate limited")

        # Count 429s
        blocked_count = status_codes.count(429)
        print(f"Made {len(status_codes)} requests. Blocked: {blocked_count}")
        self.assertGreater(blocked_count, 0)

if __name__ == '__main__':
    unittest.main()
