"""
Módulo Connection Monitor - Network Analyzer Pro.

Este módulo fornece funcionalidades para monitorizar conexões de rede:
- Lista de conexões activas (TCP/UDP)
- Conexões por processo
- Portas em escuta
- Estatísticas de conexões
- Monitorização em tempo real

Exemplo de uso:
    from network_analyzer.modules.connection_monitor import ConnectionMonitor
    
    monitor = ConnectionMonitor()
    
    # Listar conexões
    connections = monitor.get_connections()
    for conn in connections:
        print(f"{conn.local_addr}:{conn.local_port} -> {conn.remote_addr}:{conn.remote_port}")
    
    # Portas em escuta
    listening = monitor.get_listening_ports()
"""

import socket
import subprocess
import platform
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from enum import Enum

# Tentar importar psutil
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# =============================================================================
# ENUMS E CONSTANTES
# =============================================================================

class ConnectionState(Enum):
    """Estados de conexão TCP."""
    LISTEN = "LISTEN"
    ESTABLISHED = "ESTABLISHED"
    TIME_WAIT = "TIME_WAIT"
    CLOSE_WAIT = "CLOSE_WAIT"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    FIN_WAIT1 = "FIN_WAIT1"
    FIN_WAIT2 = "FIN_WAIT2"
    LAST_ACK = "LAST_ACK"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    NONE = "NONE"


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class Connection:
    """
    Representa uma conexão de rede.
    
    Attributes:
        protocol: Protocolo (tcp, udp)
        local_addr: Endereço local
        local_port: Porta local
        remote_addr: Endereço remoto
        remote_port: Porta remota
        state: Estado da conexão
        pid: ID do processo
        process_name: Nome do processo
        family: Família de endereços (IPv4/IPv6)
    """
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: Optional[int] = None
    process_name: str = ""
    family: str = "IPv4"
    
    @property
    def local(self) -> str:
        """Endereço local formatado."""
        return f"{self.local_addr}:{self.local_port}"
    
    @property
    def remote(self) -> str:
        """Endereço remoto formatado."""
        if self.remote_addr and self.remote_port:
            return f"{self.remote_addr}:{self.remote_port}"
        return "-"
    
    @property
    def is_listening(self) -> bool:
        """Se está em modo escuta."""
        return self.state.upper() == "LISTEN"
    
    @property
    def is_established(self) -> bool:
        """Se está estabelecida."""
        return self.state.upper() == "ESTABLISHED"


@dataclass
class ConnectionStats:
    """
    Estatísticas de conexões.
    
    Attributes:
        total: Total de conexões
        tcp: Conexões TCP
        udp: Conexões UDP
        established: Conexões estabelecidas
        listening: Portas em escuta
        time_wait: Conexões em TIME_WAIT
        by_state: Contagem por estado
        by_process: Contagem por processo
    """
    total: int = 0
    tcp: int = 0
    udp: int = 0
    established: int = 0
    listening: int = 0
    time_wait: int = 0
    by_state: Dict[str, int] = field(default_factory=dict)
    by_process: Dict[str, int] = field(default_factory=dict)


# =============================================================================
# CLASSE PRINCIPAL
# =============================================================================

class ConnectionMonitor:
    """
    Monitor de conexões de rede.
    
    Fornece métodos para listar e analisar conexões de rede activas,
    portas em escuta e estatísticas.
    
    Exemplo:
        >>> monitor = ConnectionMonitor()
        >>> for conn in monitor.get_connections():
        ...     if conn.is_established:
        ...         print(f"{conn.process_name}: {conn.remote}")
    """
    
    def __init__(self):
        """Inicializa o monitor."""
        self._process_cache: Dict[int, str] = {}
    
    def get_connections(
        self,
        protocol: str = "all",
        state: Optional[str] = None,
        pid: Optional[int] = None
    ) -> List[Connection]:
        """
        Obtém lista de conexões de rede.
        
        Args:
            protocol: "tcp", "udp" ou "all"
            state: Filtrar por estado (ESTABLISHED, LISTEN, etc.)
            pid: Filtrar por ID de processo
            
        Returns:
            Lista de Connection
            
        Exemplo:
            >>> # Apenas conexões estabelecidas
            >>> established = monitor.get_connections(state="ESTABLISHED")
            >>> 
            >>> # Apenas TCP
            >>> tcp = monitor.get_connections(protocol="tcp")
        """
        if PSUTIL_AVAILABLE:
            connections = self._get_connections_psutil()
        else:
            connections = self._get_connections_fallback()
        
        # Aplicar filtros
        if protocol != "all":
            connections = [c for c in connections if c.protocol == protocol]
        
        if state:
            connections = [c for c in connections if c.state.upper() == state.upper()]
        
        if pid:
            connections = [c for c in connections if c.pid == pid]
        
        return connections
    
    def _get_connections_psutil(self) -> List[Connection]:
        """Obtém conexões usando psutil."""
        connections = []
        
        for conn in psutil.net_connections(kind='all'):
            try:
                # Endereços
                local_addr = conn.laddr.ip if conn.laddr else ""
                local_port = conn.laddr.port if conn.laddr else 0
                remote_addr = conn.raddr.ip if conn.raddr else ""
                remote_port = conn.raddr.port if conn.raddr else 0
                
                # Protocolo
                if conn.type == socket.SOCK_STREAM:
                    protocol = "tcp"
                elif conn.type == socket.SOCK_DGRAM:
                    protocol = "udp"
                else:
                    protocol = "other"
                
                # Família
                if conn.family == socket.AF_INET:
                    family = "IPv4"
                elif conn.family == socket.AF_INET6:
                    family = "IPv6"
                else:
                    family = "other"
                
                # Estado
                state = conn.status if hasattr(conn, 'status') else "NONE"
                
                # Processo
                pid = conn.pid
                process_name = ""
                if pid:
                    if pid in self._process_cache:
                        process_name = self._process_cache[pid]
                    else:
                        try:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                            self._process_cache[pid] = process_name
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            process_name = f"PID {pid}"
                
                connections.append(Connection(
                    protocol=protocol,
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr=remote_addr,
                    remote_port=remote_port,
                    state=state,
                    pid=pid,
                    process_name=process_name,
                    family=family
                ))
                
            except Exception:
                continue
        
        return connections
    
    def _get_connections_fallback(self) -> List[Connection]:
        """Fallback usando netstat."""
        connections = []
        system = platform.system().lower()
        
        try:
            if system == "windows":
                # netstat -ano mostra PID
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                for line in result.stdout.split("\n"):
                    match = re.match(
                        r"\s*(TCP|UDP)\s+"
                        r"(\d+\.\d+\.\d+\.\d+|\[::\]):(\d+)\s+"
                        r"(\d+\.\d+\.\d+\.\d+|\[::\]|0\.0\.0\.0|\*):(\d+|\*)\s+"
                        r"(\w+)?\s*"
                        r"(\d+)?",
                        line
                    )
                    
                    if match:
                        protocol = match.group(1).lower()
                        local_addr = match.group(2).strip("[]")
                        local_port = int(match.group(3))
                        remote_addr = match.group(4).strip("[]")
                        remote_port = int(match.group(5)) if match.group(5) != "*" else 0
                        state = match.group(6) or "NONE"
                        pid = int(match.group(7)) if match.group(7) else None
                        
                        connections.append(Connection(
                            protocol=protocol,
                            local_addr=local_addr,
                            local_port=local_port,
                            remote_addr=remote_addr if remote_addr not in ["0.0.0.0", "*"] else "",
                            remote_port=remote_port,
                            state=state,
                            pid=pid
                        ))
            else:
                # Linux: ss -tuanp
                result = subprocess.run(
                    ["ss", "-tuanp"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                for line in result.stdout.split("\n")[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 5:
                        protocol = parts[0].lower()
                        state = parts[1]
                        local = parts[4]
                        remote = parts[5] if len(parts) > 5 else ""
                        
                        # Parse local
                        if ":" in local:
                            local_addr, local_port = local.rsplit(":", 1)
                            local_port = int(local_port)
                        else:
                            continue
                        
                        # Parse remote
                        if ":" in remote:
                            remote_addr, remote_port = remote.rsplit(":", 1)
                            remote_port = int(remote_port) if remote_port != "*" else 0
                        else:
                            remote_addr = ""
                            remote_port = 0
                        
                        connections.append(Connection(
                            protocol=protocol,
                            local_addr=local_addr,
                            local_port=local_port,
                            remote_addr=remote_addr,
                            remote_port=remote_port,
                            state=state
                        ))
                        
        except Exception:
            pass
        
        return connections
    
    def get_listening_ports(self) -> List[Connection]:
        """
        Obtém lista de portas em modo escuta.
        
        Returns:
            Lista de Connection em estado LISTEN
        """
        return self.get_connections(state="LISTEN")
    
    def get_established(self) -> List[Connection]:
        """
        Obtém lista de conexões estabelecidas.
        
        Returns:
            Lista de Connection em estado ESTABLISHED
        """
        return self.get_connections(state="ESTABLISHED")
    
    def get_stats(self) -> ConnectionStats:
        """
        Calcula estatísticas de conexões.
        
        Returns:
            ConnectionStats com resumo
        """
        connections = self.get_connections()
        
        stats = ConnectionStats(total=len(connections))
        
        for conn in connections:
            # Por protocolo
            if conn.protocol == "tcp":
                stats.tcp += 1
            elif conn.protocol == "udp":
                stats.udp += 1
            
            # Por estado
            state = conn.state.upper()
            stats.by_state[state] = stats.by_state.get(state, 0) + 1
            
            if state == "ESTABLISHED":
                stats.established += 1
            elif state == "LISTEN":
                stats.listening += 1
            elif state == "TIME_WAIT":
                stats.time_wait += 1
            
            # Por processo
            if conn.process_name:
                stats.by_process[conn.process_name] = \
                    stats.by_process.get(conn.process_name, 0) + 1
        
        return stats
    
    def get_connections_by_process(self, process_name: str) -> List[Connection]:
        """
        Obtém conexões de um processo específico.
        
        Args:
            process_name: Nome do processo
            
        Returns:
            Lista de Connection do processo
        """
        return [
            c for c in self.get_connections()
            if process_name.lower() in c.process_name.lower()
        ]
    
    def is_port_in_use(self, port: int, protocol: str = "tcp") -> bool:
        """
        Verifica se uma porta está em uso.
        
        Args:
            port: Número da porta
            protocol: "tcp" ou "udp"
            
        Returns:
            True se a porta está em uso
        """
        for conn in self.get_connections(protocol=protocol):
            if conn.local_port == port:
                return True
        return False
    
    def get_remote_connections(self) -> List[Connection]:
        """
        Obtém conexões com hosts remotos (exclui localhost).
        
        Returns:
            Lista de Connection remotas
        """
        local_addrs = ["127.0.0.1", "::1", "0.0.0.0", "localhost"]
        
        return [
            c for c in self.get_connections(state="ESTABLISHED")
            if c.remote_addr and c.remote_addr not in local_addrs
        ]


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    print("=== Teste do módulo Connection Monitor ===\n")
    
    if not PSUTIL_AVAILABLE:
        print("⚠ psutil não instalado. Funcionalidades limitadas.")
        print("  Instale com: pip install psutil\n")
    
    monitor = ConnectionMonitor()
    
    # Estatísticas
    print("--- Estatísticas de Conexões ---")
    stats = monitor.get_stats()
    print(f"Total: {stats.total}")
    print(f"TCP: {stats.tcp}, UDP: {stats.udp}")
    print(f"Estabelecidas: {stats.established}")
    print(f"Em escuta: {stats.listening}")
    print(f"TIME_WAIT: {stats.time_wait}")
    
    # Top processos
    if stats.by_process:
        print("\n--- Top Processos (por conexões) ---")
        sorted_procs = sorted(
            stats.by_process.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        for proc, count in sorted_procs:
            print(f"  {proc}: {count}")
    
    # Portas em escuta
    print("\n--- Portas em Escuta ---")
    for conn in monitor.get_listening_ports()[:10]:
        proc = f" ({conn.process_name})" if conn.process_name else ""
        print(f"  {conn.protocol.upper()} {conn.local_addr}:{conn.local_port}{proc}")
    
    # Conexões remotas
    print("\n--- Conexões Remotas (top 5) ---")
    for conn in monitor.get_remote_connections()[:5]:
        proc = f" [{conn.process_name}]" if conn.process_name else ""
        print(f"  {conn.local} -> {conn.remote}{proc}")
