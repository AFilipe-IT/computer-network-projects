"""
Pacote de módulos do Network Analyzer Pro.

Este pacote contém todos os módulos de análise de rede.
Cada módulo pode ser importado individualmente.

Exemplo de uso:
    from network_analyzer.modules import ping
    from network_analyzer.modules import dns_analyzer
    from network_analyzer.modules import port_scanner
    
    # Ping
    stats = ping.ping("google.com", count=5)
    print(f"Latência média: {stats.avg_ms}ms")
    
    # DNS
    dns = dns_analyzer.DNSAnalyzer()
    result = dns.lookup("google.com")
    print(f"IPs: {result.values}")
    
    # Port Scanner
    scanner = port_scanner.PortScanner()
    result = scanner.scan_range("127.0.0.1", range(1, 100))

Módulos disponíveis:
    - ping: Testes de ping com estatísticas
    - traceroute: Traceroute de rede
    - dns_analyzer: Análise DNS
    - http_analyzer: Análise HTTP/HTTPS
    - network_info: Informações de interfaces
    - port_scanner: Scanner de portas TCP
    - whois_lookup: Consultas WHOIS
    - connection_monitor: Monitor de conexões
    - bandwidth: Teste de velocidade
    - arp_scanner: Descoberta de hosts
    - mtu_discovery: Descoberta de Path MTU
"""

# Importar submódulos para facilitar acesso
from . import ping
from . import traceroute
from . import dns_analyzer
from . import http_analyzer
from . import network_info
from . import port_scanner
from . import whois_lookup
from . import connection_monitor
from . import bandwidth
from . import arp_scanner
from . import mtu_discovery

# Versão
__version__ = "2.0.0"

# Lista de módulos disponíveis
__all__ = [
    "ping",
    "traceroute", 
    "dns_analyzer",
    "http_analyzer",
    "network_info",
    "port_scanner",
    "whois_lookup",
    "connection_monitor",
    "bandwidth",
    "arp_scanner",
    "mtu_discovery",
]
