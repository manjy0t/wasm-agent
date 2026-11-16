"""Read-only identity connectivity probe, runnable with just Python's stdlib.

The installer sends this code and a public CA certificate over SSH. It does not
need an initialized service, signing dependencies, tokens, or private keys.
"""
import http.client
import json
import ssl
import sys
from urllib.parse import urlsplit


def probe_identity(url, ca_pem, timeout=5):
    conn = None
    try:
        p = urlsplit(url)
        if (p.scheme != 'https' or not p.hostname or p.username or p.password
                or p.path not in ('', '/') or p.query or p.fragment or not 0 < timeout <= 30):
            raise ValueError('Use an HTTPS origin and a timeout between 0 and 30 seconds')
        context = ssl.create_default_context(cadata=ca_pem)
        conn = http.client.HTTPSConnection(p.hostname, p.port, context=context, timeout=timeout)
        conn.request('GET', '/v1/trust', headers={'Accept': 'application/json', 'Connection': 'close'})
        response = conn.getresponse()
        if response.status != 200:
            return dict(ok=False, error_kind='http_error', error='Identity trust endpoint returned HTTP ' + str(response.status))
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('Identity trust response exceeds size limit')
        result = json.loads(raw)
        if (not isinstance(result, dict) or not isinstance(result.get('payload'), str)
                or not isinstance(result.get('signature'), str)):
            raise ValueError('Expected the identity service public trust response')
        # This is a reachability/TLS check. Initialization still verifies the
        # authorization signature and the separately pinned issuer fingerprint.
        return dict(ok=True, tls_verified=True, trust_endpoint_reachable=True)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return dict(ok=False, error_kind=type(exc).__name__,
                    error=str(exc).replace('\n', ' ').replace('\r', ' ')[:240])
    finally:
        if conn is not None:
            conn.close()


if __name__ == '__main__':
    settings = json.load(sys.stdin)
    print(json.dumps(probe_identity(settings['url'], settings['ca_pem'], settings.get('timeout', 5))))
