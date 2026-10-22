import requests

RELEVANT = ['www-authenticate', 'set-cookie', 'access-control-allow-origin', 'access-control-allow-credentials']

def probe(url, timeout=10):
    resp = requests.get(url, timeout=timeout)
    findings = []
    for h in RELEVANT:
        if h in resp.headers:
            findings.append({'header': h, 'value': resp.headers[h]})
    issues = []
    sc = [v for f in findings for k, v in [(f['header'], f['value'])] if k == 'set-cookie']
    for cookie in sc:
        low = cookie.lower()
        if 'httponly' not in low:
            issues.append('set-cookie missing HttpOnly')
        if 'secure' not in low and url.startswith('https'):
            issues.append('set-cookie missing Secure')
        if 'samesite' not in low:
            issues.append('set-cookie missing SameSite')
    acao = resp.headers.get('access-control-allow-origin', '')
    if acao == '*' and resp.headers.get('access-control-allow-credentials', '').lower() == 'true':
        issues.append('ACO wildcard with credentials allowed')
    return {'status': resp.status_code, 'headers': findings, 'issues': issues}
