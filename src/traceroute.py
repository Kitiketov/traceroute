import socket
import time
from typing import Any, cast

from scapy.all import (
    ICMP,
    ICMPv6DestUnreach,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IP,
    IPv6,
    TCP,
    UDP,
    Raw,
    sr1,
)

from src.defaults import (
    DEFAULT_INTERVAL,
    DEFAULT_MAX_HOPS,
    DEFAULT_PACKET_SIZE,
    DEFAULT_QUERIES,
    DEFAULT_TCP_PORT,
    DEFAULT_TIMEOUT,
    DEFAULT_UDP_PORT,
    PROTOCOL_ICMP,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
)
from src.whois_client import WhoisClient


def resolve_target(target: str, port: int | None) -> tuple[str, bool]:
    """Разрешает хост в IP и возвращает IP и флаг IPv6."""
    try:
        addrinfo = socket.getaddrinfo(
            target, port or 0, socket.AF_UNSPEC, socket.SOCK_DGRAM
        )
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve {target}") from exc
    chosen = None
    for info in addrinfo:
        if info[0] == socket.AF_INET:
            chosen = info
            break
    if chosen is None:
        chosen = addrinfo[0]
    address = cast(str, chosen[4][0])
    return address, chosen[0] == socket.AF_INET6


class Traceroute:
    def __init__(
            self,
            target: str,
            protocol: str = PROTOCOL_ICMP,
            *,
            max_hops: int = DEFAULT_MAX_HOPS,
            packet_size: int = DEFAULT_PACKET_SIZE,
            timeout: float = DEFAULT_TIMEOUT,
            queries: int = DEFAULT_QUERIES,
            interval: float = DEFAULT_INTERVAL,
            port: int | None = None,
            as_lookup: bool = False,
    ):
        """Инициализирует параметры трассировки."""
        self.target = target
        self.protocol = protocol.lower()
        self.max_hops = max_hops
        self.packet_size = max(packet_size, 8)
        self.timeout = timeout
        self.queries = max(1, queries)
        self.interval = max(0.0, interval)
        self.port = port
        self.as_lookup = as_lookup
        self.packet_id = int(time.time()) & 0xFFFF
        self.target_ip, self.ipv6 = resolve_target(target, port)
        self.whois = WhoisClient(timeout=self.timeout)

    def _payload_size(self, packet) -> int:
        """Вычисляет, сколько байт добавить до требуемого размера пакета."""
        base_len = len(bytes(packet))
        return max(self.packet_size - base_len, 0)

    def _build_packet(self, ttl: int, seq: int) -> object:
        """Собирает пакет выбранного протокола с заданным TTL/HLIM и seq."""
        base = (
            IPv6(dst=self.target_ip, hlim=ttl)
            if self.ipv6
            else IP(dst=self.target_ip, ttl=ttl)
        )
        if self.protocol == "icmp":
            if self.ipv6:
                icmp_layer = ICMPv6EchoRequest(id=self.packet_id, seq=seq)
            else:
                icmp_layer = ICMP()
                icmp_layer.id = self.packet_id & 0xFFFF
                icmp_layer.seq = seq
            pkt = base / icmp_layer
            payload_len = self._payload_size(pkt)
            if payload_len:
                pkt = pkt / Raw(load=b"\x00" * payload_len)
            return pkt
        if self.protocol == PROTOCOL_UDP:
            dport = self.port or DEFAULT_UDP_PORT
            pkt = base / UDP(dport=dport)
            payload_len = self._payload_size(pkt)
            if payload_len:
                pkt = pkt / Raw(load=b"\x00" * payload_len)
            return pkt
        dport = self.port or DEFAULT_TCP_PORT
        pkt = base / TCP(dport=dport, flags="S")
        payload_len = self._payload_size(pkt)
        if payload_len:
            pkt = pkt / Raw(load=b"\x00" * payload_len)
        return pkt

    def _reached_destination(self, reply) -> bool:
        """Проверяет, достигнут ли целевой хост по ответу."""
        if reply is None or reply.src != self.target_ip:
            return False
        if self.protocol == PROTOCOL_ICMP:
            if (
                    self.ipv6
                    and reply.haslayer(ICMPv6EchoReply)
                    and reply.getlayer(ICMPv6EchoReply).id == self.packet_id
            ):
                return True
            if (
                    not self.ipv6
                    and reply.haslayer(ICMP)
                    and reply.getlayer(ICMP).type in (0, 129)
                    and reply.getlayer(ICMP).id == self.packet_id
            ):
                return True
        if self.protocol == PROTOCOL_UDP:
            if self.ipv6 and reply.haslayer(ICMPv6DestUnreach):
                return True
            if reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 3:
                return True
        if self.protocol == PROTOCOL_TCP and reply.haslayer(TCP):
            flags = reply.getlayer(TCP).flags
            if flags & 0x04 or flags & 0x12:
                return True
        return False

    def _probe_once(self, ttl: int, seq: int) -> tuple[Any, float]:
        """Отправляет один пробный пакет и возвращает ответ и время."""
        pkt = self._build_packet(ttl, seq)
        start = time.time()
        reply = sr1(pkt, verbose=0, timeout=self.timeout)
        elapsed = (time.time() - start) * 1000
        return reply, elapsed

    def _format_line(self, ttl: int, hop_ip: str | None, samples: list[str]) -> str:
        """Формирует строку вывода для хопа."""
        if hop_ip is None:
            return f"{ttl} " + " ".join(samples)
        as_part = ""
        if self.as_lookup:
            asn = self.whois.lookup_asn(hop_ip)
            as_part = f"{asn} " if asn else "? "
        return f"{ttl} {hop_ip} {as_part}" + " ".join(samples)

    def trace(self) -> None:
        """Выполняет трассировку и печатает строки хопов."""
        seq_counter = 1
        for ttl in range(1, self.max_hops + 1):
            hop_ip: str | None = None
            samples: list[str] = []
            reached = False
            for attempt in range(self.queries):
                reply, elapsed = self._probe_once(ttl, seq_counter)
                if reply:
                    hop_ip = hop_ip or reply.src
                    samples.append(f"{elapsed:.2f} ms")
                    if self._reached_destination(reply):
                        reached = True
                else:
                    samples.append("*")
                seq_counter += 1
                if attempt < self.queries - 1 and self.interval:
                    time.sleep(self.interval)

            print(self._format_line(ttl, hop_ip, samples))
            if reached:
                break
