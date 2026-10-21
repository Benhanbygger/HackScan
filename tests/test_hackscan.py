import unittest
from unittest.mock import patch
import hackscan

class RedirectTests(unittest.TestCase):
    def fetcher(self, mapping):
        return lambda url: mapping[url]

    def test_cross_domain(self):
        result = hackscan.inspect('example.dk', self.fetcher({'https://example.dk/': (302, 'https://other.dk/'), 'https://other.dk/': (200, None)}))
        self.assertEqual(result[:2], ('https://other.dk/', 'review'))

    def test_www_and_https(self):
        result = hackscan.inspect('example.dk', self.fetcher({'https://example.dk/': (301, 'https://www.example.dk/'), 'https://www.example.dk/': (200, None)}))
        self.assertEqual(result[1], 'ok')

    def test_relative_redirect(self):
        self.assertEqual(hackscan.follow('https://example.dk/', self.fetcher({'https://example.dk/': (302, '/home'), 'https://example.dk/home': (200, None)}))[0], 'https://example.dk/home')

    def test_loop(self):
        with self.assertRaisesRegex(ValueError, 'løkke'):
            hackscan.follow('https://example.dk/', lambda url: (301, '/'))

    def test_private_address_rejected(self):
        with patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 0))]):
            with self.assertRaises(ValueError):
                hackscan.public_address('example.dk')

    def test_unsafe_scheme(self):
        with self.assertRaises(ValueError):
            hackscan.request('file:///etc/passwd')

    def test_http_error(self):
        self.assertEqual(hackscan.inspect('example.dk', lambda url: (503, None))[1], 'http_error')

    def test_http_fallback(self):
        def fetch(url):
            if url.startswith('https:'): raise OSError('connection refused')
            return 200, None
        self.assertEqual(hackscan.inspect('example.dk', fetch)[0], 'http://example.dk/')

if __name__ == '__main__': unittest.main()
