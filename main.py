import sys

from src.arg_parser import parse_args
from src.traceroute import Traceroute


def main() -> None:
    args = parse_args()
    try:
        tracer = Traceroute(
            args.destination,
            protocol=args.protocol,
            timeout=args.timeout,
            port=args.port,
            max_hops=args.max_hops,
            packet_size=args.packet_size,
            queries=args.queries,
            interval=args.interval,
            as_lookup=args.asn,
        )
        tracer.trace()
    except ValueError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
