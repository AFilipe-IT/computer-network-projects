"""
Módulo Port Scanner - Network Analyzer Pro.

Este módulo fornece funcionalidades completas de scanning de portas:
- Scan TCP connect
- Detecção de serviços comuns
- Banner grabbing
- Scan de ranges de portas
- Threading para velocidade
- Detecção de estado de porta (aberta, fechada, filtrada)

Exemplo de uso:
    from network_analyzer.modules.port_scanner import PortScanner
    
    scanner = PortScanner()
    
    # Scan de portas comuns
    result = scanner.scan("192.168.1.1", ports="common")
    for port in result.open_ports:
        print(f"Porta {port.number} aberta: {port.service}")
    
    # Scan de range específico
    result = scanner.scan("192.168.1.1", ports="1-1024")
"""

import socket
import threading
import queue
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Union, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# =============================================================================
# SERVIÇOS CONHECIDOS
# =============================================================================

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Portas mais comuns para scan rápido
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
             993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class PortResult:
    """
    Resultado do scan de uma porta.
    
    Attributes:
        number: Número da porta
        state: Estado (open, closed, filtered)
        service: Nome do serviço
        banner: Banner capturado (se disponível)
        response_time_ms: Tempo de resposta
    """
    number: int
    state: str
    service: str = ""
    banner: str = ""
    response_time_ms: float = 0.0
    
    @property
    def is_open(self) -> bool:
        """Retorna True se a porta está aberta."""
        return self.state == "open"


@dataclass
class ScanResult:
    """
    Resultado completo de um scan.
    
    Attributes:
        host: Host scanneado
        ip: Endereço IP resolvido
        ports_scanned: Total de portas verificadas
        open_ports: Lista de portas abertas
        closed_ports: Número de portas fechadas
        filtered_ports: Número de portas filtradas
        scan_time_ms: Tempo total do scan
        timestamp: Momento do scan
    """
    host: str
    ip: str
    ports_scanned: int = 0
    open_ports: List[PortResult] = field(default_factory=list)
    closed_ports: int = 0
    filtered_ports: int = 0
    scan_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def open_count(self) -> int:
        """Número de portas abertas."""
        return len(self.open_ports)


# =============================================================================
# CLASSE PRINCIPAL
# =============================================================================

class PortScanner:
    """
    Scanner de portas TCP completo.
    
    Fornece métodos para verificar portas abertas em hosts remotos,
    com suporte a threading, detecção de serviços e banner grabbing.
    
    Attributes:
        timeout: Tempo limite para conexão por porta
        threads: Número de threads paralelas
        grab_banner: Se deve tentar capturar banner
        
    Exemplo:
        >>> scanner = PortScanner(timeout=1.0, threads=100)
        >>> result = scanner.scan("192.168.1.1", ports="1-1024")
        >>> print(f"Portas abertas: {result.open_count}")
    """
    
    def __init__(
        self,
        timeout: float = 1.0,
        threads: int = 100,
        grab_banner: bool = True
    ):
        """
        Inicializa o scanner.
        
        Args:
            timeout: Tempo limite para cada porta em segundos
            threads: Número de threads para scan paralelo
            grab_banner: Se deve tentar capturar banners
        """
        self.timeout = timeout
        self.threads = threads
        self.grab_banner = grab_banner
    
    def scan(
        self,
        host: str,
        ports: Union[str, List[int]] = "common",
        callback: Optional[Callable[[PortResult], None]] = None
    ) -> ScanResult:
        """
        Executa scan de portas no host especificado.
        
        Args:
            host: Host ou IP a scanear
            ports: Portas a verificar:
                   - "common": Portas mais comuns (~20)
                   - "top100": Top 100 portas
                   - "1-1024": Range de portas
                   - [80, 443, 8080]: Lista específica
            callback: Função chamada ao encontrar porta aberta
            
        Returns:
            ScanResult com todas as portas encontradas
            
        Exemplo:
            >>> def on_port(port):
            ...     print(f"Encontrado: {port.number}")
            >>> result = scanner.scan("10.0.0.1", "1-100", callback=on_port)
        """
        # Resolver host
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            raise ValueError(f"Não foi possível resolver '{host}': {e}")
        
        # Parsear portas
        port_list = self._parse_ports(ports)
        
        result = ScanResult(
            host=host,
            ip=ip,
            ports_scanned=len(port_list)
        )
        
        start_time = time.perf_counter()
        
        # Executar scan com threads
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._scan_port, ip, port): port
                for port in port_list
            }
            
            for future in as_completed(futures):
                port_result = future.result()
                
                if port_result.state == "open":
                    result.open_ports.append(port_result)
                    if callback:
                        callback(port_result)
                elif port_result.state == "closed":
                    result.closed_ports += 1
                else:
                    result.filtered_ports += 1
        
        # Ordenar portas abertas
        result.open_ports.sort(key=lambda p: p.number)
        
        result.scan_time_ms = (time.perf_counter() - start_time) * 1000
        
        return result
    
    def scan_single(self, host: str, port: int) -> PortResult:
        """
        Verifica uma única porta.
        
        Args:
            host: Host ou IP
            port: Número da porta
            
        Returns:
            PortResult com estado da porta
        """
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return PortResult(
                number=port,
                state="error",
                service=str(e)
            )
        
        return self._scan_port(ip, port)
    
    def _scan_port(self, ip: str, port: int) -> PortResult:
        """
        Verifica uma porta específica.
        
        Tenta conexão TCP e opcionalmente captura banner.
        """
        result = PortResult(
            number=port,
            state="closed",
            service=COMMON_PORTS.get(port, "")
        )
        
        try:
            start = time.perf_counter()
            
            # Criar socket e tentar conectar
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            connection = sock.connect_ex((ip, port))
            
            result.response_time_ms = (time.perf_counter() - start) * 1000
            
            if connection == 0:
                result.state = "open"
                
                # Tentar capturar banner
                if self.grab_banner:
                    result.banner = self._grab_banner(sock, port)
                    
                    # Detectar serviço pelo banner
                    if not result.service and result.banner:
                        result.service = self._detect_service(result.banner)
            
            sock.close()
            
        except socket.timeout:
            result.state = "filtered"
        except socket.error:
            result.state = "closed"
        except Exception:
            result.state = "error"
        
        return result
    
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Tenta capturar banner do serviço.
        
        Envia dados apropriados baseado na porta.
        """
        try:
            sock.settimeout(2)
            
            # Enviar request HTTP para portas web
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in [443, 8443]:
                return ""  # SSL requer handshake
            elif port == 21:
                pass  # FTP envia banner automaticamente
            elif port == 22:
                pass  # SSH envia banner automaticamente
            elif port == 25:
                pass  # SMTP envia banner automaticamente
            else:
                sock.send(b"\r\n")
            
            # Receber resposta
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Limitar tamanho
            if len(banner) > 200:
                banner = banner[:200] + "..."
            
            return banner
            
        except Exception:
            return ""
    
    def _detect_service(self, banner: str) -> str:
        """Detecta serviço baseado no banner."""
        banner_lower = banner.lower()
        
        if "ssh" in banner_lower:
            return "SSH"
        elif "http" in banner_lower or "html" in banner_lower:
            return "HTTP"
        elif "ftp" in banner_lower:
            return "FTP"
        elif "smtp" in banner_lower or "mail" in banner_lower:
            return "SMTP"
        elif "mysql" in banner_lower:
            return "MySQL"
        elif "postgresql" in banner_lower:
            return "PostgreSQL"
        elif "redis" in banner_lower:
            return "Redis"
        elif "mongodb" in banner_lower:
            return "MongoDB"
        
        return ""
    
    def _parse_ports(self, ports: Union[str, List[int]]) -> List[int]:
        """
        Converte especificação de portas para lista.
        
        Args:
            ports: Especificação de portas
            
        Returns:
            Lista de números de portas
        """
        if isinstance(ports, list):
            return ports
        
        ports = ports.lower().strip()
        
        if ports == "common":
            return TOP_PORTS
        
        if ports == "top100":
            return list(COMMON_PORTS.keys())
        
        if ports == "all":
            return list(range(1, 65536))
        
        # Range: "1-1024"
        if "-" in ports and "," not in ports:
            parts = ports.split("-")
            start = int(parts[0])
            end = int(parts[1])
            return list(range(start, end + 1))
        
        # Lista: "80,443,8080"
        if "," in ports:
            return [int(p.strip()) for p in ports.split(",")]
        
        # Porta única
        return [int(ports)]
    
    def quick_scan(self, host: str) -> ScanResult:
        """
        Scan rápido das portas mais comuns.
        
        Args:
            host: Host a scanear
            
        Returns:
            ScanResult
        """
        return self.scan(host, ports="common")
    
    def full_scan(self, host: str, callback=None) -> ScanResult:
        """
        Scan completo de todas as 65535 portas.
        
        ⚠ Pode demorar vários minutos!
        
        Args:
            host: Host a scanear
            callback: Função de callback
            
        Returns:
            ScanResult
        """
        return self.scan(host, ports="all", callback=callback)


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    print("=== Teste do módulo Port Scanner ===\n")
    
    scanner = PortScanner(timeout=1.0, threads=50)
    
    # Callback para mostrar portas em tempo real
    def on_port(port: PortResult):
        service = f" ({port.service})" if port.service else ""
        banner = f" - {port.banner[:50]}" if port.banner else ""
        print(f"  [ABERTA] Porta {port.number}{service}{banner}")
    
    # Scan localhost
    host = "127.0.0.1"
    print(f"Scanning {host}...")
    print("(Portas comuns)\n")
    
    result = scanner.scan(host, ports="common", callback=on_port)
    
    print(f"\n--- Resultado ---")
    print(f"Host: {result.host} ({result.ip})")
    print(f"Portas verificadas: {result.ports_scanned}")
    print(f"Portas abertas: {result.open_count}")
    print(f"Portas fechadas: {result.closed_ports}")
    print(f"Portas filtradas: {result.filtered_ports}")
    print(f"Tempo: {result.scan_time_ms:.0f}ms")
