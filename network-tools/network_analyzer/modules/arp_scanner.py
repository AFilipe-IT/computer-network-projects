"""
Módulo ARP Scanner - Network Analyzer Pro.

Este módulo fornece funcionalidades para descoberta de hosts na rede local:
- Scan ARP da rede local
- Descoberta de dispositivos ativos
- Identificação de fabricantes (OUI)
- Mapeamento IP-MAC

Nota: Algumas funcionalidades requerem privilégios de administrador.

Exemplo de uso:
    from network_analyzer.modules.arp_scanner import ARPScanner
    
    scanner = ARPScanner()
    hosts = scanner.scan("192.168.1.0/24")
    for host in hosts:
        print(f"{host.ip} - {host.mac} ({host.vendor})")
"""

import socket
import struct
import subprocess
import re
import platform
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class Host:
    """
    Representa um host descoberto na rede.
    
    Attributes:
        ip: Endereço IP
        mac: Endereço MAC
        hostname: Nome do host (se resolvido)
        vendor: Fabricante (baseado no OUI)
        response_time: Tempo de resposta em ms
        is_alive: Se está ativo
    """
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    response_time: float = 0.0
    is_alive: bool = True


@dataclass
class ScanResult:
    """
    Resultado de um scan ARP.
    
    Attributes:
        network: Rede escaneada
        hosts: Lista de hosts descobertos
        scan_time: Tempo total de scan
        total_ips: Total de IPs escaneados
    """
    network: str
    hosts: List[Host] = field(default_factory=list)
    scan_time: float = 0.0
    total_ips: int = 0
    
    @property
    def hosts_found(self) -> int:
        """Número de hosts descobertos."""
        return len(self.hosts)


# =============================================================================
# BASE DE DADOS OUI (PARCIAL)
# =============================================================================

# Prefixos MAC para fabricantes comuns
OUI_DATABASE = {
    "00:00:0C": "Cisco",
    "00:1A:2B": "Cisco",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1C:42": "Parallels",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3E": "Xen",
    "00:03:FF": "Microsoft",
    "00:17:F2": "Apple",
    "00:1E:C2": "Apple",
    "00:25:00": "Apple",
    "3C:5A:B4": "Google",
    "00:1A:11": "Google",
    "F8:1A:67": "TP-Link",
    "14:CC:20": "TP-Link",
    "00:1F:33": "Netgear",
    "C0:FF:D4": "Netgear",
    "00:26:F2": "Netgear",
    "00:24:B2": "Netgear",
    "00:14:BF": "Linksys",
    "00:18:F8": "Linksys",
    "00:21:29": "Linksys",
    "00:1E:58": "D-Link",
    "00:22:B0": "D-Link",
    "1C:7E:E5": "D-Link",
    "00:04:4B": "Nvidia",
    "00:26:B9": "Dell",
    "00:14:22": "Dell",
    "00:21:9B": "Dell",
    "00:25:64": "Dell",
    "00:1A:A0": "Dell",
    "00:0D:56": "Dell",
    "00:1E:4F": "Dell",
    "00:23:AE": "Dell",
    "3C:D9:2B": "HP",
    "00:1A:4B": "HP",
    "00:25:B3": "HP",
    "94:57:A5": "HP",
    "00:14:38": "HP",
    "00:21:5A": "HP",
    "00:1C:C4": "HP",
    "3C:D9:2B": "HP",
    "EC:B1:D7": "HP",
    "00:1B:21": "Intel",
    "00:1F:3B": "Intel",
    "00:13:02": "Intel",
    "00:1E:65": "Intel",
    "00:13:20": "Intel",
    "00:02:B3": "Intel",
    "00:03:47": "Intel",
    "00:0E:35": "Intel",
    "00:0E:0C": "Intel",
    "00:A0:C9": "Intel",
    "DC:A6:32": "Raspberry Pi Foundation",
    "B8:27:EB": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "D8:3A:DD": "Raspberry Pi Foundation",
    "28:CD:C1": "Raspberry Pi Foundation",
    "2C:CF:67": "Raspberry Pi Foundation",
    "00:23:24": "Samsung",
    "00:12:47": "Samsung",
    "00:15:99": "Samsung",
    "00:21:D1": "Samsung",
    "00:24:54": "Samsung",
    "00:26:37": "Samsung",
    "34:23:BA": "Samsung",
    "4C:BC:98": "Samsung",
    "10:1D:C0": "Samsung",
    "00:1B:63": "Apple",
    "00:1E:52": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:BB": "Apple",
    "28:37:37": "Apple",
    "3C:07:54": "Apple",
    "40:A6:D9": "Apple",
    "54:26:96": "Apple",
    "60:C5:47": "Apple",
    "70:56:81": "Apple",
    "78:CA:39": "Apple",
    "7C:6D:62": "Apple",
    "84:38:35": "Apple",
    "88:C6:63": "Apple",
    "90:84:0D": "Apple",
    "98:01:A7": "Apple",
    "A8:86:DD": "Apple",
    "AC:87:A3": "Apple",
    "B0:34:95": "Apple",
    "B8:17:C2": "Apple",
    "BC:52:B7": "Apple",
    "C8:2A:14": "Apple",
    "D0:23:DB": "Apple",
    "D4:9A:20": "Apple",
    "D8:30:62": "Apple",
    "E0:5F:45": "Apple",
    "E4:8B:7F": "Apple",
    "F0:D1:A9": "Apple",
    "F8:1E:DF": "Apple",
    "FC:FC:48": "Apple",
}


def get_vendor(mac: str) -> str:
    """
    Obtém o fabricante baseado no prefixo MAC (OUI).
    
    Args:
        mac: Endereço MAC (qualquer formato)
        
    Returns:
        Nome do fabricante ou "Unknown"
    """
    # Normalizar MAC para XX:XX:XX
    mac_clean = re.sub(r'[^0-9A-Fa-f]', '', mac)
    if len(mac_clean) >= 6:
        prefix = f"{mac_clean[0:2]}:{mac_clean[2:4]}:{mac_clean[4:6]}".upper()
        return OUI_DATABASE.get(prefix, "Unknown")
    return "Unknown"


# =============================================================================
# CLASSE PRINCIPAL
# =============================================================================

class ARPScanner:
    """
    Scanner de rede local usando ARP.
    
    Descobre hosts ativos na rede local através de ping
    e consulta à tabela ARP do sistema.
    
    Attributes:
        timeout: Tempo limite para ping
        threads: Número de threads paralelas
        
    Exemplo:
        >>> scanner = ARPScanner()
        >>> result = scanner.scan("192.168.1.0/24")
        >>> for host in result.hosts:
        ...     print(f"{host.ip}: {host.mac} ({host.vendor})")
    """
    
    def __init__(
        self,
        timeout: float = 1.0,
        threads: int = 50
    ):
        """
        Inicializa o scanner.
        
        Args:
            timeout: Tempo limite para ping
            threads: Número de threads
        """
        self.timeout = timeout
        self.threads = threads
        self._is_windows = platform.system().lower() == "windows"
    
    def _ping_host(self, ip: str) -> Tuple[str, float, bool]:
        """
        Faz ping a um host.
        
        Args:
            ip: Endereço IP
            
        Returns:
            Tupla (ip, tempo_resposta, está_ativo)
        """
        if self._is_windows:
            cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), ip]
        
        try:
            start = time.perf_counter()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 1
            )
            elapsed = (time.perf_counter() - start) * 1000
            
            success = result.returncode == 0
            return (ip, elapsed if success else 0, success)
            
        except Exception:
            return (ip, 0, False)
    
    def _get_arp_table(self) -> Dict[str, str]:
        """
        Obtém a tabela ARP do sistema.
        
        Returns:
            Dicionário {IP: MAC}
        """
        arp_table = {}
        
        try:
            if self._is_windows:
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            else:
                result = subprocess.run(
                    ["arp", "-n"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            
            # Padrões para extrair IP e MAC
            if self._is_windows:
                # 192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic
                pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F-]{17})"
            else:
                # 192.168.1.1    ether   aa:bb:cc:dd:ee:ff
                pattern = r"(\d+\.\d+\.\d+\.\d+).*?([\da-fA-F:]{17})"
            
            for match in re.finditer(pattern, result.stdout):
                ip = match.group(1)
                mac = match.group(2).upper().replace("-", ":")
                arp_table[ip] = mac
                
        except Exception:
            pass
        
        return arp_table
    
    def _resolve_hostname(self, ip: str) -> str:
        """
        Resolve hostname de um IP.
        
        Args:
            ip: Endereço IP
            
        Returns:
            Hostname ou string vazia
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return ""
    
    def scan(
        self,
        network: str,
        resolve_hostnames: bool = False,
        callback: Optional[callable] = None
    ) -> ScanResult:
        """
        Escaneia uma rede em busca de hosts.
        
        Args:
            network: Rede em formato CIDR (ex: 192.168.1.0/24)
            resolve_hostnames: Se deve resolver hostnames
            callback: Função chamada com (ip, found, progress)
            
        Returns:
            ScanResult com hosts descobertos
            
        Exemplo:
            >>> result = scanner.scan("192.168.1.0/24")
            >>> print(f"Encontrados {result.hosts_found} hosts")
        """
        result = ScanResult(network=network)
        start_time = time.perf_counter()
        
        # Gerar lista de IPs
        try:
            net = ipaddress.ip_network(network, strict=False)
            ips = [str(ip) for ip in net.hosts()]
            result.total_ips = len(ips)
        except Exception as e:
            return result
        
        # Fase 1: Ping paralelo
        alive_ips = []
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._ping_host, ip): ip for ip in ips}
            
            for future in as_completed(futures):
                completed += 1
                ip, response_time, is_alive = future.result()
                
                if is_alive:
                    alive_ips.append((ip, response_time))
                
                if callback:
                    progress = completed / len(ips)
                    callback(ip, is_alive, progress)
        
        # Fase 2: Obter tabela ARP
        time.sleep(0.5)  # Esperar tabela ARP atualizar
        arp_table = self._get_arp_table()
        
        # Fase 3: Construir lista de hosts
        for ip, response_time in sorted(alive_ips, key=lambda x: list(map(int, x[0].split('.')))):
            host = Host(
                ip=ip,
                response_time=response_time,
                is_alive=True
            )
            
            # Adicionar MAC se disponível
            if ip in arp_table:
                host.mac = arp_table[ip]
                host.vendor = get_vendor(host.mac)
            
            # Resolver hostname se solicitado
            if resolve_hostnames:
                host.hostname = self._resolve_hostname(ip)
            
            result.hosts.append(host)
        
        result.scan_time = time.perf_counter() - start_time
        return result
    
    def quick_scan(self, network: Optional[str] = None) -> ScanResult:
        """
        Scan rápido da rede local.
        
        Args:
            network: Rede (detecta automaticamente se None)
            
        Returns:
            ScanResult
        """
        if network is None:
            # Tentar detectar rede local
            try:
                import psutil
                for name, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            if not addr.address.startswith("127."):
                                # Assumir /24 para simplicidade
                                parts = addr.address.split(".")
                                network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                                break
                    if network:
                        break
            except Exception:
                network = "192.168.1.0/24"  # Default
        
        return self.scan(network, resolve_hostnames=False)
    
    def get_local_arp(self) -> List[Host]:
        """
        Obtém hosts da tabela ARP local (sem scan).
        
        Returns:
            Lista de hosts na tabela ARP
        """
        hosts = []
        arp_table = self._get_arp_table()
        
        for ip, mac in arp_table.items():
            host = Host(
                ip=ip,
                mac=mac,
                vendor=get_vendor(mac),
                is_alive=True
            )
            hosts.append(host)
        
        return hosts


def scan_network(
    network: str,
    timeout: float = 1.0,
    threads: int = 50,
    resolve_hostnames: bool = False
) -> ScanResult:
    """
    Função conveniente para scan de rede.
    
    Args:
        network: Rede em CIDR
        timeout: Tempo limite
        threads: Threads paralelas
        resolve_hostnames: Resolver nomes
        
    Returns:
        ScanResult
    """
    scanner = ARPScanner(timeout=timeout, threads=threads)
    return scanner.scan(network, resolve_hostnames)


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    print("=== Teste do módulo ARP Scanner ===\n")
    
    scanner = ARPScanner(timeout=0.5, threads=100)
    
    # Tabela ARP local
    print("--- Tabela ARP Local ---")
    arp_hosts = scanner.get_local_arp()
    
    if arp_hosts:
        for host in arp_hosts:
            print(f"  {host.ip:15} {host.mac:17} {host.vendor}")
    else:
        print("  Tabela ARP vazia ou sem acesso")
    
    # Scan rápido
    print("\n--- Scan Rápido ---")
    print("A escanear rede local...")
    
    def progress(ip, found, pct):
        print(f"\r  Progresso: {pct*100:.0f}%", end="", flush=True)
    
    result = scanner.quick_scan()
    print()
    
    print(f"\nRede: {result.network}")
    print(f"IPs testados: {result.total_ips}")
    print(f"Hosts encontrados: {result.hosts_found}")
    print(f"Tempo: {result.scan_time:.2f}s")
    
    if result.hosts:
        print("\nHosts descobertos:")
        for host in result.hosts:
            vendor = f"({host.vendor})" if host.vendor != "Unknown" else ""
            mac = host.mac if host.mac else "N/A"
            print(f"  {host.ip:15} {mac:17} {vendor}")
