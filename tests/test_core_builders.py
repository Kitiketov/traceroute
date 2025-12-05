import pytest
from scapy.packet import Packet

from src.defaults import PROTOCOL_ICMP, PROTOCOL_TCP, PROTOCOL_UDP
from src.traceroute import Traceroute


def test_resolve_localhost_ip() -> None:
    tracer = Traceroute("localhost")
    assert tracer.target_ip in ("127.0.0.1", "::1")


@pytest.mark.parametrize("protocol", [PROTOCOL_ICMP, PROTOCOL_UDP, PROTOCOL_TCP])
def test_build_packet_size(protocol: str) -> None:
    tracer = Traceroute("localhost", protocol=protocol, packet_size=60)
    pkt: Packet = tracer._build_packet(ttl=1, seq=1)
    assert len(bytes(pkt)) >= 60
