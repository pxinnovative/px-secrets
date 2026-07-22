"""browse_host() decides which hostname goes in the URL we open.

This matters for every install, not just the default one. WebAuthn refuses an IP
literal as a Relying Party ID, so a page served from http://127.0.0.1 can never
enrol a credential. Rewriting loopback to `localhost` fixes that. Rewriting a
DELIBERATE LAN bind would be a regression: the window would point at a socket the
server is not listening on.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from px_secrets import browse_host, LOOPBACK_BROWSE_HOST  # noqa: E402


class TestBrowseHost(unittest.TestCase):

    def test_default_loopback_becomes_localhost(self):
        # The out-of-the-box case: without this, biometric enrolment is impossible.
        self.assertEqual(browse_host("127.0.0.1"), LOOPBACK_BROWSE_HOST)

    def test_any_loopback_address_becomes_localhost(self):
        for h in ("127.0.0.1", "127.0.0.2", "127.1.2.3", "::1"):
            self.assertEqual(browse_host(h), LOOPBACK_BROWSE_HOST, h)

    def test_bind_all_interfaces_becomes_localhost(self):
        # 0.0.0.0 includes loopback, so localhost reaches it and WebAuthn works.
        for h in ("0.0.0.0", "::"):
            self.assertEqual(browse_host(h), LOOPBACK_BROWSE_HOST, h)

    def test_unset_host_becomes_localhost(self):
        for h in (None, ""):
            self.assertEqual(browse_host(h), LOOPBACK_BROWSE_HOST)

    def test_deliberate_lan_bind_is_preserved(self):
        # Regression guard: rewriting these to localhost would open a dead URL for
        # anyone who bound to a specific interface on purpose.
        for h in ("192.168.1.50", "10.0.0.7", "172.16.4.2"):
            self.assertEqual(browse_host(h), h, h)

    def test_hostname_is_preserved(self):
        for h in ("localhost", "secrets.example.internal", "my-nas"):
            self.assertEqual(browse_host(h), h, h)


if __name__ == "__main__":
    unittest.main()
