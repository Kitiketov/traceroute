from _pytest.capture import CaptureFixture
from _pytest.monkeypatch import MonkeyPatch
from scapy.all import ICMP, IP  # type: ignore[attr-defined]
from scapy.packet import Packet

from src.traceroute import Traceroute


def test_trace_icmp_ipv4_reaches_destination(monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]) -> None:
    tracer = Traceroute("1.1.1.1", protocol="icmp", max_hops=5, queries=2, interval=0)

    def fake_sr1(pkt: Packet, verbose: int = 0, timeout: float | None = None) -> Packet:
        return IP(src=tracer.target_ip) / ICMP(type=0, id=tracer.packet_id)  # type: ignore[no-any-return]

    monkeypatch.setattr("src.core.sr1", fake_sr1)
    tracer.trace()

    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("1 1.1.1.1")
    assert "*" not in lines[0]


def test_trace_udp_ipv4_timeouts(monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]) -> None:
    tracer = Traceroute("1.1.1.1", protocol="udp", max_hops=1, queries=2, interval=0, timeout=0.1)
    monkeypatch.setattr("src.core.sr1", lambda *args, **kwargs: None)

    tracer.trace()
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("1")
    assert lines[0].count("*") >= tracer.queries
