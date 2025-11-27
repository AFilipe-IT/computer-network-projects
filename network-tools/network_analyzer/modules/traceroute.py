"""
Módulo de Traceroute - Network Analyzer Pro.

Este módulo fornece funcionalidades de traceroute para mapear
a rota de pacotes até um destino, incluindo:
- Traceroute com detecção de hops
- Resolução DNS reversa
- Medição de latência por hop
- Suporte a Windows (tracert) e Linux/macOS (traceroute)

Exemplo de uso:
    from network_analyzer.modules.traceroute import traceroute
    
    result = traceroute("google.com", max_hops=20)
    for hop in result.hops:
        print(f"{hop.hop}: {hop.ip} - {hop.avg_ms}ms")
"""

import subprocess
import platform
import re
import statistics
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Callable


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class TracerouteHop:
    """
    Informação de um único hop no traceroute.
    
    Attributes:
        hop: Número do hop (1, 2, 3, ...)
        ip: Endereço IP do hop (None se timeout)
        hostname: Nome DNS do hop (None se não resolvido)
        times_ms: Lista de tempos de resposta
        avg_ms: Tempo médio de resposta
        success: Se o hop respondeu
    """
    hop: int
    ip: Optional[str]
    hostname: Optional[str]
    times_ms: List[float]
    avg_ms: float
    success: bool


@dataclass
class TracerouteResult:
    """
    Resultado completo de um traceroute.
    
    Attributes:
        target: Host de destino original
        target_ip: IP resolvido do destino
        hops: Lista de todos os hops
        reached: Se o destino foi alcançado
        total_hops: Número total de hops até o destino
    """
    target: str
    target_ip: str
    hops: List[TracerouteHop] = field(default_factory=list)
    reached: bool = False
    
    @property
    def total_hops(self) -> int:
        """Retorna o número total de hops."""
        return len(self.hops)


# =============================================================================
# FUNÇÕES AUXILIARES
# =============================================================================

def resolve_host(host: str) -> str:
    """
    Resolve um hostname para endereço IP.
    
    Args:
        host: Nome do host a resolver
        
    Returns:
        Endereço IP resolvido
        
    Raises:
        ValueError: Se não conseguir resolver
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{host}': {e}")


def reverse_dns(ip: str) -> Optional[str]:
    """
    Resolve um IP para hostname (DNS reverso).
    
    Args:
        ip: Endereço IP a resolver
        
    Returns:
        Nome do host ou None se não encontrado
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


# =============================================================================
# FUNÇÃO PRINCIPAL
# =============================================================================

def traceroute(
    host: str,
    max_hops: int = 30,
    timeout: float = 2.0,
    queries: int = 3,
    callback: Optional[Callable[[TracerouteHop], None]] = None
) -> TracerouteResult:
    """
    Executa um traceroute completo para o host especificado.
    
    Utiliza o comando tracert (Windows) ou traceroute (Linux/macOS)
    do sistema operativo. Força IPv4 para consistência.
    
    Args:
        host: Nome do host ou IP de destino
        max_hops: Número máximo de hops a tentar
        timeout: Tempo limite por hop em segundos
        queries: Número de queries por hop (Linux apenas)
        callback: Função chamada após cada hop descoberto
        
    Returns:
        TracerouteResult com todos os hops e estatísticas
        
    Raises:
        ValueError: Se o host não puder ser resolvido
        RuntimeError: Se ocorrer erro ao executar traceroute
        
    Exemplo:
        >>> def on_hop(hop):
        ...     print(f"Hop {hop.hop}: {hop.ip or '*'}")
        >>> 
        >>> result = traceroute("google.com", callback=on_hop)
        >>> print(f"Destino alcançado: {result.reached}")
    """
    # Resolver host primeiro
    try:
        target_ip = resolve_host(host)
    except ValueError as e:
        raise ValueError(str(e))
    
    # Construir comando baseado no sistema operativo
    system = platform.system().lower()
    
    if system == "windows":
        # tracert: -4 força IPv4, -h max hops, -w timeout em ms
        cmd = [
            "tracert", 
            "-4",  # Forçar IPv4
            "-h", str(max_hops), 
            "-w", str(int(timeout * 1000)), 
            host
        ]
    else:
        # traceroute: -4 força IPv4, -m max hops, -w timeout, -q queries
        cmd = [
            "traceroute",
            "-4",  # Forçar IPv4
            "-m", str(max_hops),
            "-w", str(timeout),
            "-q", str(queries),
            host
        ]
    
    result = TracerouteResult(target=host, target_ip=target_ip)
    
    try:
        # Executar comando e processar output em tempo real
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            
            # Extrair número do hop
            hop_match = re.match(r"^\s*(\d+)", line)
            if not hop_match:
                continue
            
            hop_num = int(hop_match.group(1))
            
            # Extrair IP (IPv4 ou IPv6)
            ip_match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)|([0-9a-fA-F:]+:[0-9a-fA-F:]+)", 
                line
            )
            hop_ip = None
            if ip_match:
                hop_ip = ip_match.group(1) or ip_match.group(2)
            
            # Extrair tempos de resposta
            times = []
            time_matches = re.findall(
                r"(\d+)\s*ms|<\s*(\d+)\s*ms", 
                line, 
                re.IGNORECASE
            )
            for match in time_matches:
                try:
                    val = match[0] or match[1]
                    if val:
                        times.append(float(val))
                except ValueError:
                    pass
            
            # Determinar sucesso
            success = hop_ip is not None and len(times) > 0
            
            # Resolver DNS reverso
            hostname = None
            if hop_ip:
                hostname = reverse_dns(hop_ip)
            
            # Calcular média
            avg_time = statistics.mean(times) if times else 0.0
            
            # Criar objecto hop
            hop = TracerouteHop(
                hop=hop_num,
                ip=hop_ip,
                hostname=hostname,
                times_ms=times,
                avg_ms=avg_time,
                success=success
            )
            result.hops.append(hop)
            
            # Chamar callback se fornecido
            if callback:
                callback(hop)
            
            # Verificar se chegou ao destino
            if hop_ip == target_ip:
                result.reached = True
                break
        
        process.wait()
        
    except Exception as e:
        raise RuntimeError(f"Erro ao executar traceroute: {e}")
    
    return result


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    print("=== Teste do módulo Traceroute ===\n")
    
    def callback(hop: TracerouteHop):
        if hop.success:
            hostname = f" ({hop.hostname})" if hop.hostname else ""
            times = "  ".join(f"{t:.0f}ms" for t in hop.times_ms)
            print(f"{hop.hop:2d}  {hop.ip}{hostname}  {times}")
        else:
            print(f"{hop.hop:2d}  * * * Request timed out")
    
    try:
        result = traceroute("google.com", max_hops=15, callback=callback)
        
        print(f"\n--- Resultado ---")
        print(f"Destino: {result.target} ({result.target_ip})")
        print(f"Hops: {result.total_hops}")
        print(f"Alcançado: {'Sim' if result.reached else 'Não'}")
    except Exception as e:
        print(f"Erro: {e}")
