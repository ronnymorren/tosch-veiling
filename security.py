"""Small, independently tested security boundaries for the auction application."""
import http.client
import ipaddress
import re
import socket
import ssl
from decimal import Decimal, InvalidOperation
from urllib.parse import unquote, urljoin, urlsplit

from fastapi import HTTPException

MAX_BODY_BYTES = 65536
MAX_IMAGE_BYTES = 5 * 1024 * 1024
IMAGE_HOSTS = ('bing.net', 'bing.com')


def local_redirect(value: str, default='/veilingen') -> str:
    if not isinstance(value, str) or len(value) > 2048:
        return default
    # Inspect decoding too: browsers/proxies differ in handling encoded slashes.
    decoded = value
    for _ in range(3):
        if (not decoded.startswith('/') or decoded.startswith('//') or '\\' in decoded
                or any(ord(c) < 32 or ord(c) == 127 for c in decoded)):
            return default
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return value


def valid_email(value) -> str:
    if not isinstance(value, str):
        raise HTTPException(400, 'Ongeldig e-mailadres')
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}", value):
        raise HTTPException(400, 'Ongeldig e-mailadres')
    return value


def money(value, *, positive=False) -> float:
    try:
        if isinstance(value, bool):
            raise ValueError()
        number = Decimal(str(value))
        if (not number.is_finite() or number < 0 or number > 10000000
                or (positive and number <= 0) or number != number.quantize(Decimal('.01'))):
            raise ValueError()
        return float(number)
    except (InvalidOperation, ValueError, TypeError):
        raise HTTPException(400, 'Ongeldig bedrag: gebruik maximaal twee decimalen en een bedrag tot € 10.000.000')


def image_target(url, allow_external=False):
    """Validate every redirect and resolve once; the actual connection uses this IP."""
    try:
        p = urlsplit(url)
        host = (p.hostname or '').lower()
        if (len(url) > 4096 or p.scheme != 'https' or not host or p.username is not None
                or p.password is not None or p.port not in (None, 443)
                or '\\' in url or any(ord(c) < 32 for c in url)):
            raise ValueError()
        if not allow_external and not any(host == suffix or host.endswith('.' + suffix) for suffix in IMAGE_HOSTS):
            raise HTTPException(403, 'Afbeeldingsbron niet toegestaan')
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)})
        if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            raise ValueError()
        return host, addresses[0], p.path or '/', p.query
    except HTTPException:
        raise
    except (ValueError, OSError):
        raise HTTPException(400, 'Ongeldige of niet-publieke afbeeldingsbron')


def raster_type(data):
    if data.startswith(b'\x89PNG\r\n\x1a\n'): return 'image/png'
    if data.startswith(b'\xff\xd8\xff'): return 'image/jpeg'
    if data[:6] in (b'GIF87a', b'GIF89a'): return 'image/gif'
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP': return 'image/webp'
    if data[4:8] == b'ftyp' and data[8:12] in (b'avif', b'avis'): return 'image/avif'
    raise HTTPException(400, 'Alleen PNG-, JPEG-, GIF-, WebP- en AVIF-afbeeldingen zijn toegestaan')


def fetch_image(url, allow_external=False):
    for _ in range(4):
        host, ip, path, query = image_target(url, allow_external)
        conn = http.client.HTTPSConnection(host, timeout=8, context=ssl.create_default_context())
        try:
            # Pin validated IP, keeping the hostname for certificate verification/SNI.
            sock = socket.create_connection((ip,443),timeout=8)
            try:
                conn.sock = ssl.create_default_context().wrap_socket(sock,server_hostname=host)
            except Exception:
                sock.close()
                raise
            conn.request('GET',path + ('?' + query if query else ''),headers={
                'User-Agent':'Mozilla/5.0','Accept':'image/avif,image/webp,image/png,image/jpeg,image/gif',
                'Referer':'https://www.bing.com/'})
            response = conn.getresponse()
            if response.status in (301,302,303,307,308):
                location = response.getheader('Location')
                if not location: raise HTTPException(400, 'Ongeldige afbeeldingsredirect')
                url = urljoin(url,location)
                continue
            if response.status != 200:
                raise HTTPException(404, 'Afbeelding niet beschikbaar')
            content = response.read(MAX_IMAGE_BYTES + 1)
            if len(content) > MAX_IMAGE_BYTES:
                raise HTTPException(413, 'Afbeelding is te groot')
            return content, raster_type(content)
        except HTTPException:
            raise
        except (OSError, http.client.HTTPException):
            raise HTTPException(404, 'Afbeelding niet beschikbaar')
        finally:
            conn.close()
    raise HTTPException(400, 'Te veel afbeeldingsredirects')
