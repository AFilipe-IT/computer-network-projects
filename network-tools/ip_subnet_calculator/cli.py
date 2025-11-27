"""Command-line interface for the IP subnetting calculator.

This CLI supports an interactive mode: if the user does not provide `--hosts`
or `--subnets` on the command line, the program will prompt for inputs.
The user can press Enter to skip optional inputs (hosts / subnets / CIDR list).
"""
import argparse
import json
from . import calculator
import ipaddress


def parse_hosts(s: str):
    parts = [p.strip() for p in s.split(",") if p.strip()]
    return [int(p) for p in parts]


def prompt_optional(prompt_text: str):
    try:
        return input(prompt_text).strip()
    except EOFError:
        return ""


def interactive_mode(provided_network: str = None):
    # ask for base network if not provided
    if not provided_network:
        print("\n-- IP Subnetting interactive mode --")
        print("Provide the base network and either host requirements or a subnet count.")
        print("You can press Enter to skip optional inputs.")
        provided_network = prompt_optional("\nEnter base network in CIDR (e.g. 192.168.0.0/24): ")
    if not provided_network:
        raise SystemExit("No network provided. Exiting.")

    # validate network
    try:
        ipaddress.ip_network(provided_network, strict=False)
    except Exception as e:
        raise SystemExit(f"Invalid network: {e}")

    # Ask for hosts list (optional)
    hosts_input = prompt_optional("Enter host requirements separated by commas (e.g. 500,100,20). Press Enter to skip: ")
    hosts = []
    if hosts_input:
        try:
            hosts = parse_hosts(hosts_input)
        except Exception:
            raise SystemExit("Invalid hosts list. Use comma-separated integers.")

    # Ask for equal subnets count (optional)
    subnets_input = prompt_optional("Enter number of equal subnets to produce (e.g. 4). Press Enter to skip: ")
    subnets_count = None
    if subnets_input:
        try:
            subnets_count = int(subnets_input)
            if subnets_count <= 0:
                raise ValueError()
        except Exception:
            raise SystemExit("Invalid subnets count. Enter a positive integer.")

    # Ask for explicit CIDR list (optional)
    cidr_input = prompt_optional("Enter explicit subnets as CIDR separated by commas (e.g. 10.0.0.0/24,10.0.1.0/24). Press Enter to skip: ")
    cidr_list = []
    if cidr_input:
        parts = [p.strip() for p in cidr_input.split(",") if p.strip()]
        for p in parts:
            try:
                cidr_list.append(ipaddress.ip_network(p, strict=False))
            except Exception:
                raise SystemExit(f"Invalid CIDR: {p}")

    # Decide what to run. Priority: explicit CIDRs -> hosts-based VLSM -> equal subnets
    rows = []
    if cidr_list:
        for s in cidr_list:
            rows.append({
                "cidr": str(s),
                "network": str(s.network_address),
                "prefix": s.prefixlen,
                "netmask": str(s.netmask),
                "broadcast": str(s.broadcast_address),
                "usable_hosts": calculator.usable_hosts(s.prefixlen),
                "requested_hosts": None,
                "first_usable": None if s.prefixlen >= 31 else str(ipaddress.IPv4Address(int(s.network_address) + 1)),
                "last_usable": None if s.prefixlen >= 31 else str(ipaddress.IPv4Address(int(s.broadcast_address) - 1)),
                "usable_range": "N/A" if s.prefixlen >= 31 else f"{str(ipaddress.IPv4Address(int(s.network_address) + 1))} - {str(ipaddress.IPv4Address(int(s.broadcast_address) - 1))}",
            })
        return provided_network, rows

    if hosts:
        try:
            allocs = calculator.vlsm_allocate(provided_network, hosts)
        except ValueError as e:
            raise SystemExit(f"Error: {e}")

        rows = [calculator.format_allocation(a) for a in allocs]
        return provided_network, rows

    if subnets_count:
        subs = calculator.equal_subnets(provided_network, subnets_count)
        for s in subs:
            rows.append({
                "cidr": str(s),
                "network": str(s.network_address),
                "prefix": s.prefixlen,
                "netmask": str(s.netmask),
                "broadcast": str(s.broadcast_address),
                "usable_hosts": calculator.usable_hosts(s.prefixlen),
                "requested_hosts": None,
                "first_usable": None if s.prefixlen >= 31 else str(ipaddress.IPv4Address(int(s.network_address) + 1)),
                "last_usable": None if s.prefixlen >= 31 else str(ipaddress.IPv4Address(int(s.broadcast_address) - 1)),
                "usable_range": "N/A" if s.prefixlen >= 31 else f"{str(ipaddress.IPv4Address(int(s.network_address) + 1))} - {str(ipaddress.IPv4Address(int(s.broadcast_address) - 1))}",
            })
        return provided_network, rows

    # nothing provided
    raise SystemExit("No inputs provided (hosts, subnets or explicit CIDRs). Exiting.")


def main():
    parser = argparse.ArgumentParser(description="IP subnetting & VLSM calculator")
    parser.add_argument("--network", required=False, help="Base network in CIDR (e.g. 192.168.0.0/24)")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--hosts", help="Comma-separated list of host requirements, e.g. 100,50,10")
    group.add_argument("--subnets", type=int, help="Number of equal subnets to produce")
    parser.add_argument("--json", action="store_true", help="Output JSON")

    args = parser.parse_args()

    if args.hosts or args.subnets:
        # non-interactive mode
        if not args.network:
            raise SystemExit("--network is required when using --hosts or --subnets")

        if args.hosts:
            hosts = parse_hosts(args.hosts)
            try:
                allocs = calculator.vlsm_allocate(args.network, hosts)
            except ValueError as e:
                print(f"Error: {e}")
                raise SystemExit(1)

            rows = [calculator.format_allocation(a) for a in allocs]

        else:
            subs = calculator.equal_subnets(args.network, args.subnets)
            rows = []
            for s in subs:
                rows.append({
                    "cidr": str(s),
                    "network": str(s.network_address),
                    "prefix": s.prefixlen,
                    "netmask": str(s.netmask),
                    "broadcast": str(s.broadcast_address),
                    "usable_hosts": calculator.usable_hosts(s.prefixlen),
                    "requested_hosts": None,
                })

        base_network = args.network

    else:
        # interactive mode
        base_network, rows = interactive_mode(provided_network=args.network)

    if args.json:
        print(json.dumps(rows, indent=2))
        return

    # pretty print table with aligned columns and additional fields
    header_map = [
        ("CIDR", "cidr"),
        ("Network", "network"),
        ("Prefix", "prefix"),
        ("Netmask", "netmask"),
        ("Broadcast", "broadcast"),
        ("Usable Range", "usable_range"),
        ("Usable", "usable_hosts"),
        ("Requested", "requested_hosts"),
    ]

    # compute column widths
    col_widths = {}
    for title, key in header_map:
        max_w = len(title)
        for r in rows:
            v = r.get(key)
            s = "" if v is None else str(v)
            if len(s) > max_w:
                max_w = len(s)
        col_widths[key] = max_w

    print(f"\nPlan de endereçamento para {base_network}\n")
    # header
    header_parts = [f"{title:<{col_widths[key]}}" for title, key in header_map]
    print("  ".join(header_parts))
    # separator
    sep_parts = ["-" * col_widths[key] for _, key in header_map]
    print("  ".join(sep_parts))

    for r in rows:
        parts = []
        for _, key in header_map:
            v = r.get(key)
            s = "" if v is None else str(v)
            parts.append(f"{s:<{col_widths[key]}}")
        print("  ".join(parts))


if __name__ == "__main__":
    main()
