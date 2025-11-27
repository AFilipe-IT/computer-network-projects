"""
Módulo de Ping - Network Analyzer Pro.

Este módulo fornece funcionalidades avançadas de ping incluindo:
- Ping único com estatísticas detalhadas
- Ping contínuo com cálculo de métricas
- Suporte a IPv4 (com fallback para IPv6)
- Extracção de TTL e tempos de resposta

Exemplo de uso:
    from network_analyzer.modules.ping import ping, ping_once
    
    # Ping único
    result = ping_once("google.com", seq=1)
    print(f"Tempo: {result.time_ms}ms, TTL: {result.ttl}")
    
    # Ping múltiplo com estatísticas
    stats = ping("google.com", count=10)
    print(f"Média: {stats.avg_ms}ms, Perda: {stats.packet_loss_pct}%")
"""

import subprocess
import platform
import time
import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Callable
import socket


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class PingResult:
    """
    Resultado de um único ping.
    
    Attributes:
        seq: Número de sequência do ping
        host: Nome do host de destino
        ip: Endereço IP resolvido
        ttl: Time To Live da resposta
        time_ms: Tempo de resposta em milissegundos
        timestamp: Momento em que o ping foi executado
        success: Se o ping foi bem-sucedido
        error: Mensagem de erro se falhou
    """
    seq: int
    host: str
    ip: str
    ttl: int
    time_ms: float
    timestamp: datetime
    success: bool
    error: Optional[str] = None


@dataclass
class PingStats:
    """
    Estatísticas agregadas de múltiplos pings.
    
    Attributes:
        host: Nome do host de destino
        ip: Endereço IP resolvido
        packets_sent: Total de pacotes enviados
        packets_received: Total de pacotes recebidos
        packet_loss_pct: Percentagem de perda de pacotes
        min_ms: Tempo mínimo de resposta
        max_ms: Tempo máximo de resposta
        avg_ms: Tempo médio de resposta
        jitter_ms: Desvio padrão (jitter)
        results: Lista de todos os resultados individuais
    """
    host: str
    ip: str
    packets_sent: int
    packets_received: int
    packet_loss_pct: float
    min_ms: float
    max_ms: float
    avg_ms: float
    jitter_ms: float
    results: List[PingResult] = field(default_factory=list)


# =============================================================================
# FUNÇÕES AUXILIARES
# =============================================================================

def resolve_host(host: str) -> str:
    """
    Resolve um hostname para endereço IP.
    
    Args:
        host: Nome do host ou IP a resolver
        
    Returns:
        Endereço IP resolvido
        
    Raises:
        ValueError: Se não conseguir resolver o host
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{host}': {e}")


# =============================================================================
# FUNÇÕES PRINCIPAIS
# =============================================================================

def ping_once(host: str, seq: int = 1, timeout: float = 2.0) -> PingResult:
    """
    Executa um único ping para o host especificado.
    
    Utiliza o comando ping do sistema operativo para máxima compatibilidade.
    Força IPv4 para garantir a obtenção do TTL.
    
    Args:
        host: Nome do host ou IP de destino
        seq: Número de sequência do ping
        timeout: Tempo limite em segundos
        
    Returns:
        PingResult com os detalhes da resposta
        
    Exemplo:
        >>> result = ping_once("8.8.8.8", seq=1)
        >>> if result.success:
        ...     print(f"Resposta em {result.time_ms}ms")
    """
    timestamp = datetime.now()
    
    # Tentar resolver o host primeiro
    try:
        ip = resolve_host(host)
    except ValueError as e:
        return PingResult(
            seq=seq, host=host, ip="N/A", ttl=0, time_ms=0,
            timestamp=timestamp, success=False, error=str(e)
        )
    
    # Construir comando baseado no sistema operativo
    system = platform.system().lower()
    if system == "windows":
        # -4: forçar IPv4, -n 1: um ping, -w: timeout em ms
        cmd = ["ping", "-4", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        # Linux/macOS: -4: forçar IPv4, -c 1: um ping, -W: timeout em segundos
        cmd = ["ping", "-4", "-c", "1", "-W", str(int(timeout)), host]
    
    try:
        # Executar o comando e medir tempo
        start = time.perf_counter()
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout + 1
        )
        elapsed = (time.perf_counter() - start) * 1000
        
        output = result.stdout
        
        # Analisar resposta bem-sucedida
        if result.returncode == 0:
            # Extrair TTL da resposta
            ttl_match = re.search(r"TTL[=:](\d+)", output, re.IGNORECASE)
            ttl = int(ttl_match.group(1)) if ttl_match else 0
            
            # Extrair tempo de resposta
            time_match = re.search(r"time[=<](\d+\.?\d*)\s*ms", output, re.IGNORECASE)
            ping_time = float(time_match.group(1)) if time_match else elapsed
            
            return PingResult(
                seq=seq, host=host, ip=ip, ttl=ttl, time_ms=ping_time,
                timestamp=timestamp, success=True
            )
        else:
            return PingResult(
                seq=seq, host=host, ip=ip, ttl=0, time_ms=0,
                timestamp=timestamp, success=False, error="Request timed out"
            )
            
    except subprocess.TimeoutExpired:
        return PingResult(
            seq=seq, host=host, ip=ip, ttl=0, time_ms=0,
            timestamp=timestamp, success=False, error="Timeout"
        )
    except Exception as e:
        return PingResult(
            seq=seq, host=host, ip=ip, ttl=0, time_ms=0,
            timestamp=timestamp, success=False, error=str(e)
        )


def ping(
    host: str,
    count: int = 10,
    interval: float = 1.0,
    timeout: float = 2.0,
    callback: Optional[Callable[[PingResult], None]] = None
) -> PingStats:
    """
    Executa múltiplos pings e calcula estatísticas agregadas.
    
    Args:
        host: Nome do host ou IP de destino
        count: Número de pings a executar (0 = infinito)
        interval: Intervalo entre pings em segundos
        timeout: Tempo limite por ping em segundos
        callback: Função opcional chamada após cada ping
        
    Returns:
        PingStats com estatísticas completas
        
    Exemplo:
        >>> def on_ping(result):
        ...     print(f"[{result.seq}] {result.time_ms}ms")
        >>> 
        >>> stats = ping("google.com", count=5, callback=on_ping)
        >>> print(f"Média: {stats.avg_ms}ms")
        
    Raises:
        ValueError: Se o host não puder ser resolvido
    """
    # Resolver host uma vez no início
    try:
        ip = resolve_host(host)
    except ValueError as e:
        raise ValueError(str(e))
    
    results: List[PingResult] = []
    seq = 0
    
    try:
        while count == 0 or seq < count:
            seq += 1
            result = ping_once(host, seq, timeout)
            results.append(result)
            
            # Chamar callback se fornecido
            if callback:
                callback(result)
            
            # Aguardar intervalo (excepto no último)
            if count == 0 or seq < count:
                time.sleep(interval)
                
    except KeyboardInterrupt:
        # Permitir interrupção com Ctrl+C
        pass
    
    # Calcular estatísticas
    success_times = [r.time_ms for r in results if r.success]
    packets_sent = len(results)
    packets_received = len(success_times)
    
    # Calcular percentagem de perda
    if packets_sent > 0:
        packet_loss = (packets_sent - packets_received) / packets_sent * 100
    else:
        packet_loss = 100.0
    
    # Calcular estatísticas de tempo
    if success_times:
        min_ms = min(success_times)
        max_ms = max(success_times)
        avg_ms = statistics.mean(success_times)
        jitter_ms = statistics.stdev(success_times) if len(success_times) > 1 else 0.0
    else:
        min_ms = max_ms = avg_ms = jitter_ms = 0.0
    
    return PingStats(
        host=host,
        ip=ip,
        packets_sent=packets_sent,
        packets_received=packets_received,
        packet_loss_pct=packet_loss,
        min_ms=min_ms,
        max_ms=max_ms,
        avg_ms=avg_ms,
        jitter_ms=jitter_ms,
        results=results
    )


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    # Teste rápido do módulo
    print("=== Teste do módulo Ping ===\n")
    
    def callback(result: PingResult):
        if result.success:
            print(f"[{result.seq:03d}] {result.ip}: {result.time_ms:.1f}ms TTL={result.ttl}")
        else:
            print(f"[{result.seq:03d}] Falha: {result.error}")
    
    stats = ping("google.com", count=5, callback=callback)
    
    print(f"\n--- Estatísticas ---")
    print(f"Enviados: {stats.packets_sent}")
    print(f"Recebidos: {stats.packets_received}")
    print(f"Perda: {stats.packet_loss_pct:.1f}%")
    print(f"Mín/Média/Máx: {stats.min_ms:.1f}/{stats.avg_ms:.1f}/{stats.max_ms:.1f} ms")
    print(f"Jitter: {stats.jitter_ms:.1f} ms")
