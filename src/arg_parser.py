import argparse

from src.defaults import (
    DEFAULT_INTERVAL,
    DEFAULT_MAX_HOPS,
    DEFAULT_PACKET_SIZE,
    DEFAULT_QUERIES,
    DEFAULT_TIMEOUT,
    PROTOCOL_CHOICES,
    PROTOCOL_ICMP,
)


def build_parser() -> argparse.ArgumentParser:
    """Создаёт и настраивает парсер аргументов командной строки."""
    parser = argparse.ArgumentParser(description="Traceroute")
    parser.add_argument(
        "-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="Таймаут ожидания ответа (сек)"
    )
    parser.add_argument("-p", "--port", type=int, help="Порт (для TCP или UDP)")
    parser.add_argument(
        "-n",
        "--max-requests",
        dest="max_hops",
        type=int,
        default=DEFAULT_MAX_HOPS,
        help="Максимальное число хопов (TTL)",
    )
    parser.add_argument(
        "-q", "--queries", type=int, default=DEFAULT_QUERIES, help="Количество запросов на хоп (N)"
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help="Интервал между запросами (сек)",
    )
    parser.add_argument(
        "-s", "--packet-size", type=int, default=DEFAULT_PACKET_SIZE, help="Размер пакета (байт)"
    )
    parser.add_argument(
        "-v",
        "--asn",
        dest="asn",
        action="store_true",
        help="Вывод AS-номера через whois",
    )
    parser.add_argument("destination", help="IP-адрес или хост")
    parser.add_argument(
        "protocol",
        choices=PROTOCOL_CHOICES,
        nargs="?",
        default=PROTOCOL_ICMP,
        help="Протокол: tcp, udp или icmp (по умолчанию icmp)",
    )
    return parser


def parse_args() -> argparse.Namespace:
    """Парсит аргументы командной строки и возвращает Namespace."""
    return build_parser().parse_args()
