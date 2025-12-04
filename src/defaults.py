"""Константы с дефолтными значениями параметров traceroute."""

DEFAULT_TIMEOUT: float = 2.0
DEFAULT_MAX_HOPS: int = 30
DEFAULT_QUERIES: int = 3
DEFAULT_INTERVAL: float = 0.1
DEFAULT_PACKET_SIZE: int = 40

DEFAULT_UDP_PORT: int = 33434
DEFAULT_TCP_PORT: int = 80

PROTOCOL_ICMP: str = "icmp"
PROTOCOL_TCP: str = "tcp"
PROTOCOL_UDP: str = "udp"
PROTOCOL_CHOICES: list[str] = [PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP]
