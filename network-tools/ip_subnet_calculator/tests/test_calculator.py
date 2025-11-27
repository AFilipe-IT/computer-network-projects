import ipaddress
from ip_subnet_calculator import calculator


def test_smallest_prefix_for_hosts():
    assert calculator.smallest_prefix_for_hosts(1) == 30  # 2 usable -> /30
    assert calculator.smallest_prefix_for_hosts(2) == 29


def test_equal_subnets():
    subs = calculator.equal_subnets("192.168.0.0/24", 4)
    assert len(subs) == 4
    assert subs[0] == ipaddress.ip_network("192.168.0.0/26")


def test_vlsm_allocate_basic():
    allocs = calculator.vlsm_allocate("192.168.0.0/24", [100, 50, 10])
    # should allocate three subnets
    assert len(allocs) == 3
    # largest should be /25 or /26 depending on calculation
    nets = [a[0] for a in allocs]
    assert all(isinstance(n, ipaddress.IPv4Network) for n in nets)
