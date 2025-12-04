import re
import socket


class WhoisClient:
    """Whois-клиент без внешних библиотек для получения AS-номера."""

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def _query(self, server: str, query: str) -> str:
        """Отправляет whois-запрос на сервер и возвращает ответ в виде строки."""
        with socket.create_connection((server, 43), self.timeout) as conn:
            conn.sendall((query + "\r\n").encode("ascii", errors="ignore"))
            response = bytearray()
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        return response.decode("utf-8", errors="ignore")

    def _discover_server(self, ip: str) -> str | None:
        """Определяет, к какому региональному регистратору отправлять запрос."""
        try:
            response = self._query("whois.iana.org", ip)
        except OSError:
            return None
        for line in response.splitlines():
            if line.lower().startswith("refer:"):
                return line.split(":", 1)[1].strip()
        return None

    _asn_pattern = re.compile(r"AS?(\d+)", re.IGNORECASE)

    def _parse_asn(self, response: str) -> str | None:
        """Извлекает номер AS из текста ответа."""
        matches = self._asn_pattern.findall(response)
        if matches:
            return matches[0]
        return None

    def lookup_asn(self, ip: str) -> str | None:
        """Возвращает номер AS для IP или None при ошибке/отсутствии данных."""
        server = self._discover_server(ip) or "whois.arin.net"
        query = f"n + {ip}" if "arin" in server else ip
        try:
            resp = self._query(server, query)
        except OSError:
            resp = ""
        asn = self._parse_asn(resp)
        if not asn and server != "whois.arin.net":
            try:
                fallback = self._query("whois.arin.net", f"n + {ip}")
                asn = self._parse_asn(fallback)
            except OSError:
                return None
        return asn
