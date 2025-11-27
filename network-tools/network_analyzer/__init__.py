"""
Network Analyzer Pro - Ferramenta completa de análise de rede.

Uma ferramenta abrangente para diagnóstico e análise de redes,
incluindo múltiplos módulos especializados.

Módulos disponíveis:
    - modules.ping: Testes de ping avançados
    - modules.traceroute: Traceroute com geolocalização
    - modules.dns_analyzer: Análise DNS
    - modules.http_analyzer: Análise HTTP/HTTPS
    - modules.network_info: Informações de interfaces
    - modules.port_scanner: Scanner de portas
    - modules.whois_lookup: Consultas WHOIS
    - modules.connection_monitor: Monitor de conexões
    - modules.bandwidth: Teste de velocidade
    - modules.arp_scanner: Descoberta de hosts
    - modules.mtu_discovery: Descoberta de MTU

Exemplo de uso:
    from network_analyzer import modules
    
    # Ping
    stats = modules.ping.ping("google.com", count=5)
    print(f"Latência: {stats.avg_ms}ms")
    
    # DNS
    dns = modules.dns_analyzer.DNSAnalyzer()
    result = dns.lookup("google.com")
    
    # Port scan
    scanner = modules.port_scanner.PortScanner()
    result = scanner.scan_range("192.168.1.1", range(1, 100))

Para a interface gráfica:
    from network_analyzer.gui import NetworkAnalyzerGUI
    app = NetworkAnalyzerGUI()
    app.run()
"""

__version__ = "2.0.0"
__author__ = "Network Analyzer Team"

# Importar módulo core legado
from . import core

# Importar submódulos
from . import modules
