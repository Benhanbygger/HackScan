"""HackScan: passive homepage redirect checks, using only Python's standard library."""
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import threading
import time
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import urlopen, getproxies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = Path(os.environ.get('HACKSCAN_DB', str(Path(__file__).parent / '.local' / 'hackscan.sqlite3')))
LOCK = threading.Lock()
STATE = {'running': False, 'checked': 0, 'error': None}
USER_AGENT = 'HackScan/0.1 (passive homepage redirect research)'


def connection():
    DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute('CREATE TABLE IF NOT EXISTS results (domain TEXT PRIMARY KEY, final_url TEXT, status TEXT, detail TEXT, checked_at TEXT DEFAULT CURRENT_TIMESTAMP)')
    return c


def normalize(host):
    host = host.lower().rstrip('.')
    return host[4:] if host.startswith('www.') else host


def public_address(host):
    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError('Domænet har ingen IP-adresse')
    ips = [a[4][0] for a in addresses]
    if any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise ValueError('Private eller reserverede IP-adresser tillades ikke')
    return ips[0]


def request(url):
    p = urlsplit(url)
    if p.scheme not in ('https', 'http') or not p.hostname or p.username or p.password:
        raise ValueError('Ugyldig destinationsadresse')
    port = p.port or (443 if p.scheme == 'https' else 80)
    if port not in (80, 443):
        raise ValueError('Kun port 80 og 443 tillades')
    host = p.hostname.encode('idna').decode('ascii')
    ip = public_address(host)
    # Connect to the validated IP directly; retain hostname for TLS verification.
    proxy = getproxies().get(p.scheme)
    if proxy:
        proxy_url = urlsplit(proxy)
        if proxy_url.scheme != 'http':
            raise ValueError('Kun HTTP CONNECT-proxy understøttes')
        tunnel = http.client.HTTPConnection(proxy_url.hostname, proxy_url.port or 80, timeout=10)
        tunnel.set_tunnel(ip, port)
        tunnel.connect()
        sock = tunnel.sock
    else:
        sock = socket.create_connection((ip, port), timeout=10)
    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        conn.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host) if p.scheme == 'https' else sock
        path = p.path or '/'
        if p.query:
            path += '?' + p.query
        conn.request('GET', path, headers={'Host': host, 'User-Agent': USER_AGENT, 'Accept': 'text/html', 'Connection': 'close'})
        response = conn.getresponse()
        return response.status, response.getheader('Location')
    finally:
        conn.close()
        sock.close()


def follow(url, fetch=request):
    seen = set()
    for _ in range(11):
        if url in seen:
            raise ValueError('Viderestillingsløkke')
        seen.add(url)
        status, location = fetch(url)
        if status in (301, 302, 303, 307, 308) and location:
            url = urljoin(url, location)
            continue
        return url, status
    raise ValueError('For mange viderestillinger')


def inspect(domain, fetch=request):
    # HTTP fallback only when the initial HTTPS connection cannot be established.
    try:
        first = fetch('https://' + domain + '/')
        initial = 'https://' + domain + '/'
    except (OSError, http.client.HTTPException):
        initial = 'http://' + domain + '/'
        first = fetch(initial)
    def cached(url):
        return first if url == initial else fetch(url)
    final, code = follow(initial, cached)
    changed = normalize(urlsplit(final).hostname or '') != normalize(domain)
    return final, 'review' if changed else ('ok' if code < 400 else 'http_error'), f'HTTP {code}'


def discover(limit=50):
    # Sample one page; try the previous index if the newest is unavailable.
    with urlopen('https://index.commoncrawl.org/collinfo.json', timeout=30) as r:
        indexes = json.load(r)
    query = urlencode({'url': '*.dk', 'output': 'json', 'pageSize': 1, 'page': 0})
    last_error = None
    for index in indexes[:2]:
        endpoint = index['cdx-api']
        if not endpoint.startswith('https://index.commoncrawl.org/'):
            raise ValueError('Uventet indeksadresse')
        found = set()
        try:
            with urlopen(endpoint + '?' + query, timeout=20) as response:
                total = 0
                for raw in response:
                    total += len(raw)
                    if total > 8_000_000:
                        break
                    record = json.loads(raw)
                    p = urlsplit(record.get('url', ''))
                    host = normalize(p.hostname or '')
                    if host.endswith('.dk') and p.path in ('', '/') and not p.query:
                        found.add(host)
                        if len(found) >= limit:
                            break
            if found:
                return sorted(found)
        except (OSError, ValueError) as e:
            last_error = e
    raise ValueError('Common Crawl kunne ikke levere domæner: ' + str(last_error or 'ingen forsider fundet'))


def scan():
    try:
        domains = discover()
        for domain in domains:
            try:
                final, status, detail = inspect(domain)
            except Exception as e:
                final, status, detail = '', 'error', str(e)[:250]
            with connection() as c:
                c.execute('INSERT OR REPLACE INTO results(domain, final_url, status, detail) VALUES(?,?,?,?)', (domain, final, status, detail))
            with LOCK:
                STATE['checked'] += 1
            time.sleep(1)
    except Exception as e:
        with LOCK:
            STATE['error'] = str(e)[:250]
    finally:
        with LOCK:
            STATE['running'] = False


class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, content_type='application/json; charset=utf-8'):
        raw = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/api/results':
            with connection() as c:
                rows = [dict(r) for r in c.execute('SELECT * FROM results ORDER BY checked_at DESC, domain LIMIT 1000')]
            with LOCK:
                state = dict(STATE)
            self.send(200, json.dumps({'state': state, 'results': rows}))
        elif path in ('/', '/app.js', '/style.css'):
            name = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}[path]
            kind = {'/': 'text/html', '/app.js': 'text/javascript', '/style.css': 'text/css'}[path]
            self.send(200, (Path(__file__).parent / 'web' / name).read_text(), kind + '; charset=utf-8')
        else:
            self.send(404, '{}')

    def do_POST(self):
        if self.path != '/api/scan':
            return self.send(404, '{}')
        # Require a custom header and same-origin browser calls to prevent cross-site starts.
        if self.headers.get('X-HackScan') != '1' or self.headers.get('Sec-Fetch-Site') == 'cross-site':
            return self.send(403, '{}')
        with LOCK:
            if STATE['running']:
                return self.send(409, json.dumps({'error': 'En scanning kører allerede'}))
            STATE.update(running=True, checked=0, error=None)
        threading.Thread(target=scan, daemon=True).start()
        self.send(202, json.dumps({'started': True}))


if __name__ == '__main__':
    with connection():
        pass
    ThreadingHTTPServer(('127.0.0.1', int(os.environ.get('PORT', '8000'))), Handler).serve_forever()
