"""Core subnetting and VLSM calculator functions."""
from typing import List, Tuple
import ipaddress
import math


def usable_hosts(prefix: int) -> int:
    """Return number of usable hosts for an IPv4 prefix (naive: -2 for network/broadcast)."""
    if prefix >= 31:
        return 0
    return max(0, (2 ** (32 - prefix)) - 2)


def smallest_prefix_for_hosts(hosts: int) -> int:
    """Return smallest prefix length that can accomodate `hosts` usable hosts."""
    if hosts <= 0:
        return 32
    needed = hosts + 2
    bits = math.ceil(math.log2(needed))
    prefix = 32 - bits
    return max(0, prefix)


def equal_subnets(network: str, count: int) -> List[ipaddress.IPv4Network]:
    net = ipaddress.ip_network(network, strict=False)
    if count <= 0:
        raise ValueError("count must be > 0")
    # calculate how many bits to split
    extra = math.ceil(math.log2(count))
    new_prefix = net.prefixlen + extra
    if new_prefix > 32:
        raise ValueError("Cannot split network into that many subnets")
    subnets = list(net.subnets(new_prefix=new_prefix))
    # return only requested count (may be power of two rounding)
    return subnets[:count]


def vlsm_allocate(network: str, host_requirements: List[int]) -> List[Tuple[ipaddress.IPv4Network, int]]:
    """Allocate subnets using VLSM for given host requirements.

    Returns list of tuples (allocated_network, requested_hosts)
    """
    net = ipaddress.ip_network(network, strict=False)
    # sort descending to place largest first
    reqs = sorted(host_requirements, reverse=True)
    allocations: List[Tuple[ipaddress.IPv4Network, int]] = []
    next_ip = int(net.network_address)

    for h in reqs:
        prefix = smallest_prefix_for_hosts(h)
        # ensure that prefix is not less specific than the base network
        if prefix < net.prefixlen:
            prefix = net.prefixlen
        # find candidate subnet starting at next_ip with that prefix
        try:
            candidate = ipaddress.ip_network((ipaddress.IPv4Address(next_ip), prefix), strict=False)
        except Exception as e:
            raise ValueError(f"Allocation failed for hosts={h}: {e}")
        # if candidate outside base network, try to align within base
        if candidate.network_address < net.network_address or candidate.broadcast_address > net.broadcast_address:
            raise ValueError(f"Not enough address space in {net} for requirement {h} hosts (tried {candidate})")

        allocations.append((candidate, h))
        # advance next_ip to the address after the broadcast of candidate
        next_ip = int(candidate.broadcast_address) + 1
        # if next_ip beyond net, future allocations will fail
        if next_ip > int(net.broadcast_address):
            # if there are still remaining requirements, fail
            if len(allocations) < len(reqs):
                # but only raise when we actually need more
                pass

    return allocations


def format_allocation(alloc: Tuple[ipaddress.IPv4Network, int]) -> dict:
    net, req = alloc
    prefix = net.prefixlen
    # compute usable IP range
    if prefix >= 31:
        first_usable = None
        last_usable = None
        usable_range = "N/A"
    else:
        first_addr = ipaddress.IPv4Address(int(net.network_address) + 1)
        last_addr = ipaddress.IPv4Address(int(net.broadcast_address) - 1)
        first_usable = str(first_addr)
        last_usable = str(last_addr)
        usable_range = f"{first_usable} - {last_usable}"

    return {
        "network": str(net.network_address),
        "prefix": prefix,
        "netmask": str(net.netmask),
        "broadcast": str(net.broadcast_address),
        "usable_hosts": usable_hosts(prefix),
        "requested_hosts": req,
        "cidr": str(net),
        "first_usable": first_usable,
        "last_usable": last_usable,
        "usable_range": usable_range,
    }


if __name__ == "__main__":
    # small demo
    import json
    allocs = vlsm_allocate("192.168.0.0/24", [100, 50, 10])
    print(json.dumps([format_allocation(a) for a in allocs], indent=2))
