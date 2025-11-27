"""
Módulo Network Info - Network Analyzer Pro.

Este módulo fornece informações detalhadas sobre interfaces de rede locais:
- Lista de interfaces de rede
- Endereços IP (IPv4 e IPv6)
- Endereços MAC
- Gateway padrão
- Servidores DNS configurados
- Estatísticas de tráfego por interface
- Detecção de tipo de interface (Ethernet, Wi-Fi, etc.)

Exemplo de uso:
    from network_analyzer.modules.network_info import NetworkInfo
    
    net = NetworkInfo()
    
    # Listar interfaces
    interfaces = net.get_interfaces()
    for iface in interfaces:
        print(f"{iface.name}: {iface.ipv4}")
    
    # Informação do sistema
    info = net.get_system_info()
    print(f"Hostname: {info.hostname}")
"""

import socket
import platform
import subprocess
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime

# Tentar importar psutil para informações detalhadas
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class InterfaceStats:
    """
    Estatísticas de tráfego de uma interface.
    
    Attributes:
        bytes_sent: Total de bytes enviados
        bytes_recv: Total de bytes recebidos
        packets_sent: Total de pacotes enviados
        packets_recv: Total de pacotes recebidos
        errors_in: Erros de entrada
        errors_out: Erros de saída
        drop_in: Pacotes descartados (entrada)
        drop_out: Pacotes descartados (saída)
    """
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    errors_in: int = 0
    errors_out: int = 0
    drop_in: int = 0
    drop_out: int = 0
    
    @property
    def bytes_sent_human(self) -> str:
        """Bytes enviados em formato legível."""
        return self._format_bytes(self.bytes_sent)
    
    @property
    def bytes_recv_human(self) -> str:
        """Bytes recebidos em formato legível."""
        return self._format_bytes(self.bytes_recv)
    
    def _format_bytes(self, size: int) -> str:
        """Formata bytes para unidades legíveis."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"


@dataclass
class NetworkInterface:
    """
    Informação de uma interface de rede.
    
    Attributes:
        name: Nome da interface
        display_name: Nome amigável
        type: Tipo (Ethernet, Wi-Fi, Loopback, etc.)
        mac: Endereço MAC
        ipv4: Endereço IPv4
        ipv4_netmask: Máscara de rede IPv4
        ipv6: Endereço IPv6
        ipv6_netmask: Máscara de rede IPv6
        is_up: Se está activa
        is_loopback: Se é loopback
        speed_mbps: Velocidade em Mbps
        mtu: Maximum Transmission Unit
        stats: Estatísticas de tráfego
    """
    name: str
    display_name: str = ""
    type: str = "Unknown"
    mac: str = ""
    ipv4: str = ""
    ipv4_netmask: str = ""
    ipv6: str = ""
    ipv6_netmask: str = ""
    is_up: bool = True
    is_loopback: bool = False
    speed_mbps: int = 0
    mtu: int = 0
    stats: Optional[InterfaceStats] = None


@dataclass
class SystemNetworkInfo:
    """
    Informação de rede do sistema.
    
    Attributes:
        hostname: Nome do computador
        fqdn: Fully Qualified Domain Name
        local_ip: IP local principal
        public_ip: IP público (se disponível)
        gateway: Gateway padrão
        dns_servers: Lista de servidores DNS
        interfaces_count: Número de interfaces
        active_interfaces: Interfaces activas
    """
    hostname: str = ""
    fqdn: str = ""
    local_ip: str = ""
    public_ip: str = ""
    gateway: str = ""
    dns_servers: List[str] = field(default_factory=list)
    interfaces_count: int = 0
    active_interfaces: int = 0


# =============================================================================
# CLASSE PRINCIPAL
# =============================================================================

class NetworkInfo:
    """
    Fornece informações detalhadas sobre a rede local.
    
    Esta classe permite obter informações sobre interfaces de rede,
    configurações do sistema e estatísticas de tráfego.
    
    Exemplo:
        >>> net = NetworkInfo()
        >>> print(f"Hostname: {net.get_hostname()}")
        >>> for iface in net.get_interfaces():
        ...     print(f"{iface.name}: {iface.ipv4}")
    """
    
    def __init__(self):
        """Inicializa o módulo de informação de rede."""
        self._interfaces_cache = None
        self._cache_time = None
    
    def get_hostname(self) -> str:
        """
        Retorna o nome do computador.
        
        Returns:
            Nome do host
        """
        return socket.gethostname()
    
    def get_fqdn(self) -> str:
        """
        Retorna o Fully Qualified Domain Name.
        
        Returns:
            FQDN do host
        """
        return socket.getfqdn()
    
    def get_local_ip(self) -> str:
        """
        Retorna o endereço IP local principal.
        
        Conecta a um servidor externo para determinar
        qual interface seria usada para tráfego de Internet.
        
        Returns:
            Endereço IP local
        """
        try:
            # Conectar a servidor público para descobrir IP local
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    def get_public_ip(self) -> Optional[str]:
        """
        Retorna o endereço IP público.
        
        Usa um serviço externo para determinar o IP público.
        Pode falhar se não houver conexão à Internet.
        
        Returns:
            Endereço IP público ou None
        """
        import urllib.request
        
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
        ]
        
        for service in services:
            try:
                with urllib.request.urlopen(service, timeout=5) as response:
                    return response.read().decode().strip()
            except Exception:
                continue
        
        return None
    
    def get_gateway(self) -> str:
        """
        Retorna o gateway padrão.
        
        Returns:
            Endereço IP do gateway
        """
        system = platform.system().lower()
        
        try:
            if system == "windows":
                # Usar ipconfig /all
                result = subprocess.run(
                    ["ipconfig", "/all"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # Procurar Default Gateway
                match = re.search(
                    r"Default Gateway[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)",
                    result.stdout
                )
                if match:
                    return match.group(1)
                    
            else:
                # Usar ip route
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
                if match:
                    return match.group(1)
                    
        except Exception:
            pass
        
        return ""
    
    def get_dns_servers(self) -> List[str]:
        """
        Retorna a lista de servidores DNS configurados.
        
        Returns:
            Lista de endereços IP dos servidores DNS
        """
        dns_servers = []
        system = platform.system().lower()
        
        try:
            if system == "windows":
                result = subprocess.run(
                    ["ipconfig", "/all"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # Procurar DNS Servers
                matches = re.findall(
                    r"DNS Servers[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)",
                    result.stdout
                )
                dns_servers.extend(matches)
                
                # Capturar linhas subsequentes que podem ter mais DNS
                for match in re.finditer(
                    r"DNS Servers.*?:\s*(\d+\.\d+\.\d+\.\d+)(?:\s*\n\s*(\d+\.\d+\.\d+\.\d+))?",
                    result.stdout
                ):
                    for group in match.groups():
                        if group and group not in dns_servers:
                            dns_servers.append(group)
                            
            else:
                # Ler /etc/resolv.conf
                try:
                    with open("/etc/resolv.conf", "r") as f:
                        for line in f:
                            if line.startswith("nameserver"):
                                parts = line.split()
                                if len(parts) > 1:
                                    dns_servers.append(parts[1])
                except FileNotFoundError:
                    pass
                    
        except Exception:
            pass
        
        return list(set(dns_servers))  # Remover duplicados
    
    def get_interfaces(self) -> List[NetworkInterface]:
        """
        Retorna lista de todas as interfaces de rede.
        
        Returns:
            Lista de NetworkInterface
            
        Exemplo:
            >>> for iface in net.get_interfaces():
            ...     if iface.is_up and not iface.is_loopback:
            ...         print(f"{iface.name}: {iface.ipv4}")
        """
        interfaces = []
        
        if PSUTIL_AVAILABLE:
            interfaces = self._get_interfaces_psutil()
        else:
            interfaces = self._get_interfaces_fallback()
        
        return interfaces
    
    def _get_interfaces_psutil(self) -> List[NetworkInterface]:
        """Obtém interfaces usando psutil."""
        interfaces = []
        
        # Obter endereços
        addrs = psutil.net_if_addrs()
        
        # Obter estatísticas
        stats = psutil.net_if_stats()
        
        # Obter contadores
        counters = psutil.net_io_counters(pernic=True)
        
        for name, addr_list in addrs.items():
            iface = NetworkInterface(name=name)
            
            # Determinar tipo de interface
            name_lower = name.lower()
            if "loopback" in name_lower or name_lower == "lo":
                iface.type = "Loopback"
                iface.is_loopback = True
            elif "wi-fi" in name_lower or "wireless" in name_lower or "wlan" in name_lower:
                iface.type = "Wi-Fi"
            elif "ethernet" in name_lower or "eth" in name_lower:
                iface.type = "Ethernet"
            elif "vpn" in name_lower or "tun" in name_lower:
                iface.type = "VPN"
            elif "bluetooth" in name_lower:
                iface.type = "Bluetooth"
            elif "docker" in name_lower or "veth" in name_lower:
                iface.type = "Virtual"
            
            # Processar endereços
            for addr in addr_list:
                if addr.family == socket.AF_INET:  # IPv4
                    iface.ipv4 = addr.address
                    iface.ipv4_netmask = addr.netmask or ""
                elif addr.family == socket.AF_INET6:  # IPv6
                    iface.ipv6 = addr.address
                    iface.ipv6_netmask = addr.netmask or ""
                elif addr.family == psutil.AF_LINK:  # MAC
                    iface.mac = addr.address
            
            # Obter stats da interface
            if name in stats:
                st = stats[name]
                iface.is_up = st.isup
                iface.speed_mbps = st.speed
                iface.mtu = st.mtu
            
            # Obter contadores de tráfego
            if name in counters:
                ct = counters[name]
                iface.stats = InterfaceStats(
                    bytes_sent=ct.bytes_sent,
                    bytes_recv=ct.bytes_recv,
                    packets_sent=ct.packets_sent,
                    packets_recv=ct.packets_recv,
                    errors_in=ct.errin,
                    errors_out=ct.errout,
                    drop_in=ct.dropin,
                    drop_out=ct.dropout
                )
            
            interfaces.append(iface)
        
        return interfaces
    
    def _get_interfaces_fallback(self) -> List[NetworkInterface]:
        """Fallback quando psutil não está disponível."""
        interfaces = []
        system = platform.system().lower()
        
        try:
            if system == "windows":
                result = subprocess.run(
                    ["ipconfig", "/all"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # Parse simples do ipconfig
                current_iface = None
                
                for line in result.stdout.split("\n"):
                    # Nova interface
                    if "adapter" in line.lower() and ":" in line:
                        name = line.split(":")[0].strip()
                        if "Ethernet" in name:
                            name_clean = name.replace("Ethernet adapter ", "")
                            iface_type = "Ethernet"
                        elif "Wireless" in name or "Wi-Fi" in name:
                            name_clean = name.replace("Wireless LAN adapter ", "")
                            iface_type = "Wi-Fi"
                        else:
                            name_clean = name
                            iface_type = "Unknown"
                        
                        current_iface = NetworkInterface(
                            name=name_clean,
                            type=iface_type
                        )
                        interfaces.append(current_iface)
                        
                    elif current_iface:
                        # IPv4
                        if "IPv4" in line and ":" in line:
                            ip = line.split(":")[-1].strip()
                            ip = re.sub(r"\(.*\)", "", ip).strip()
                            current_iface.ipv4 = ip
                        # MAC
                        elif "Physical Address" in line and ":" in line:
                            mac = line.split(":")[-1].strip()
                            mac = ":".join(line.split(":")[-6:]).strip()
                            current_iface.mac = mac
                            
            else:
                # Linux: usar ip addr
                result = subprocess.run(
                    ["ip", "addr"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                current_iface = None
                
                for line in result.stdout.split("\n"):
                    # Nova interface
                    match = re.match(r"^\d+:\s+(\w+):", line)
                    if match:
                        name = match.group(1)
                        current_iface = NetworkInterface(name=name)
                        
                        if "loopback" in line.lower() or name == "lo":
                            current_iface.type = "Loopback"
                            current_iface.is_loopback = True
                        elif "wl" in name:
                            current_iface.type = "Wi-Fi"
                        else:
                            current_iface.type = "Ethernet"
                        
                        current_iface.is_up = "UP" in line
                        interfaces.append(current_iface)
                        
                    elif current_iface:
                        # IPv4
                        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                        if match:
                            current_iface.ipv4 = match.group(1)
                        # MAC
                        match = re.search(r"link/ether ([\da-f:]+)", line)
                        if match:
                            current_iface.mac = match.group(1)
                            
        except Exception:
            pass
        
        return interfaces
    
    def get_system_info(self) -> SystemNetworkInfo:
        """
        Retorna informação de rede do sistema.
        
        Returns:
            SystemNetworkInfo com todas as informações
            
        Exemplo:
            >>> info = net.get_system_info()
            >>> print(f"Hostname: {info.hostname}")
            >>> print(f"Gateway: {info.gateway}")
        """
        interfaces = self.get_interfaces()
        active = [i for i in interfaces if i.is_up and not i.is_loopback]
        
        return SystemNetworkInfo(
            hostname=self.get_hostname(),
            fqdn=self.get_fqdn(),
            local_ip=self.get_local_ip(),
            public_ip=self.get_public_ip() or "",
            gateway=self.get_gateway(),
            dns_servers=self.get_dns_servers(),
            interfaces_count=len(interfaces),
            active_interfaces=len(active)
        )
    
    def get_interface_by_ip(self, ip: str) -> Optional[NetworkInterface]:
        """
        Encontra interface por endereço IP.
        
        Args:
            ip: Endereço IP a procurar
            
        Returns:
            NetworkInterface ou None
        """
        for iface in self.get_interfaces():
            if iface.ipv4 == ip or iface.ipv6 == ip:
                return iface
        return None


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    print("=== Teste do módulo Network Info ===\n")
    
    if not PSUTIL_AVAILABLE:
        print("⚠ psutil não instalado. Funcionalidades limitadas.")
        print("  Instale com: pip install psutil\n")
    
    net = NetworkInfo()
    
    # Informação do sistema
    print("--- Informação do Sistema ---")
    info = net.get_system_info()
    print(f"Hostname: {info.hostname}")
    print(f"FQDN: {info.fqdn}")
    print(f"IP Local: {info.local_ip}")
    print(f"IP Público: {info.public_ip or 'N/A'}")
    print(f"Gateway: {info.gateway}")
    print(f"DNS: {', '.join(info.dns_servers) or 'N/A'}")
    print(f"Interfaces: {info.interfaces_count} ({info.active_interfaces} activas)")
    
    # Interfaces
    print("\n--- Interfaces de Rede ---")
    for iface in net.get_interfaces():
        if iface.is_up and not iface.is_loopback:
            print(f"\n{iface.name} ({iface.type})")
            print(f"  MAC: {iface.mac}")
            print(f"  IPv4: {iface.ipv4}")
            if iface.ipv6:
                print(f"  IPv6: {iface.ipv6}")
            if iface.speed_mbps:
                print(f"  Velocidade: {iface.speed_mbps} Mbps")
            if iface.stats:
                print(f"  TX: {iface.stats.bytes_sent_human}")
                print(f"  RX: {iface.stats.bytes_recv_human}")
