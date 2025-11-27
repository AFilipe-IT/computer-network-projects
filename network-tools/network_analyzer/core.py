"""Módulo core do network_analyzer.

Contém lógica de ping, traceroute e geração de gráficos.
"""

import os
import socket
import struct
import time
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple
import subprocess
import platform
import re

# Tentar importar matplotlib para gráficos
try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


@dataclass
class PingResult:
    """Resultado de um ping individual."""
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
    """Estatísticas agregadas de ping."""
    host: str
    ip: str
    packets_sent: int
    packets_received: int
    packet_loss_pct: float
    min_ms: float
    max_ms: float
    avg_ms: float
    jitter_ms: float  # desvio padrão
    results: List[PingResult] = field(default_factory=list)


@dataclass
class TracerouteHop:
    """Resultado de um hop no traceroute."""
    hop: int
    ip: Optional[str]
    hostname: Optional[str]
    times_ms: List[float]
    avg_ms: float
    success: bool


@dataclass
class TracerouteResult:
    """Resultado completo do traceroute."""
    target: str
    target_ip: str
    hops: List[TracerouteHop] = field(default_factory=list)
    reached: bool = False


def resolve_host(host: str) -> str:
    """Resolve hostname para IP."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{host}': {e}")


def reverse_dns(ip: str) -> Optional[str]:
    """Resolve IP para hostname (reverse DNS)."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def ping_once(host: str, seq: int, timeout: float = 2.0) -> PingResult:
    """Executa um ping usando o comando do sistema.
    
    Usa subprocess para compatibilidade cross-platform.
    """
    timestamp = datetime.now()
    
    try:
        ip = resolve_host(host)
    except ValueError as e:
        return PingResult(
            seq=seq, host=host, ip="N/A", ttl=0, time_ms=0,
            timestamp=timestamp, success=False, error=str(e)
        )
    
    # Comando ping por plataforma
    system = platform.system().lower()
    if system == "windows":
        # -4 força IPv4 para obter TTL
        cmd = ["ping", "-4", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:  # Linux/macOS
        cmd = ["ping", "-4", "-c", "1", "-W", str(int(timeout)), host]
    
    try:
        start = time.perf_counter()
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 1
        )
        elapsed = (time.perf_counter() - start) * 1000
        
        output = result.stdout
        
        # Parsear resposta
        if result.returncode == 0:
            # Extrair TTL
            ttl_match = re.search(r"TTL[=:](\d+)", output, re.IGNORECASE)
            ttl = int(ttl_match.group(1)) if ttl_match else 0
            
            # Extrair tempo (tentar múltiplos padrões)
            time_match = re.search(r"time[=<](\d+\.?\d*)\s*ms", output, re.IGNORECASE)
            if time_match:
                ping_time = float(time_match.group(1))
            else:
                ping_time = elapsed
            
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
    callback=None
) -> PingStats:
    """Executa múltiplos pings e calcula estatísticas.
    
    Args:
        host: Host/IP destino
        count: Número de pings (0 = infinito)
        interval: Intervalo entre pings em segundos
        timeout: Timeout por ping em segundos
        callback: Função chamada após cada ping (para output em tempo real)
    
    Returns:
        PingStats com estatísticas agregadas
    """
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
            
            if callback:
                callback(result)
            
            # Intervalo entre pings (exceto no último)
            if count == 0 or seq < count:
                time.sleep(interval)
    except KeyboardInterrupt:
        pass  # Permite interromper com Ctrl+C
    
    # Calcular estatísticas
    success_times = [r.time_ms for r in results if r.success]
    packets_sent = len(results)
    packets_received = len(success_times)
    packet_loss = ((packets_sent - packets_received) / packets_sent * 100) if packets_sent > 0 else 100
    
    if success_times:
        min_ms = min(success_times)
        max_ms = max(success_times)
        avg_ms = statistics.mean(success_times)
        jitter_ms = statistics.stdev(success_times) if len(success_times) > 1 else 0
    else:
        min_ms = max_ms = avg_ms = jitter_ms = 0
    
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


def traceroute(
    host: str,
    max_hops: int = 30,
    timeout: float = 2.0,
    queries: int = 3,
    callback=None
) -> TracerouteResult:
    """Executa traceroute usando comando do sistema.
    
    Args:
        host: Host/IP destino
        max_hops: Número máximo de hops
        timeout: Timeout por hop
        queries: Número de queries por hop
        callback: Função chamada após cada hop
    
    Returns:
        TracerouteResult com todos os hops
    """
    try:
        target_ip = resolve_host(host)
    except ValueError as e:
        raise ValueError(str(e))
    
    system = platform.system().lower()
    
    if system == "windows":
        # -4 força IPv4, -d desliga resolução DNS (mais rápido)
        cmd = ["tracert", "-4", "-h", str(max_hops), "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["traceroute", "-4", "-m", str(max_hops), "-w", str(timeout), "-q", str(queries), host]
    
    result = TracerouteResult(target=host, target_ip=target_ip)
    
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        
        hop_num = 0
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            
            # Parsear linha do traceroute
            # Windows: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
            # Linux: " 1  router (192.168.1.1)  0.5 ms  0.4 ms  0.3 ms"
            
            # Tentar extrair número do hop
            hop_match = re.match(r"^\s*(\d+)", line)
            if not hop_match:
                continue
            
            hop_num = int(hop_match.group(1))
            
            # Extrair IP (IPv4 ou IPv6)
            # IPv4: 192.168.1.1
            # IPv6: 2001:8a0:e8db:8800::1 ou com colchetes [::1]
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)|([0-9a-fA-F:]+:[0-9a-fA-F:]+)", line)
            hop_ip = None
            if ip_match:
                hop_ip = ip_match.group(1) or ip_match.group(2)
            
            # Extrair tempos (vários formatos: "12 ms", "12ms", "<1 ms", "* ")
            times = []
            # Windows: "  1     2 ms     1 ms     1 ms  192.168.1.1"
            time_matches = re.findall(r"(\d+)\s*ms|<\s*(\d+)\s*ms", line, re.IGNORECASE)
            for match in time_matches:
                try:
                    # match é tupla (normal, <1ms)
                    val = match[0] or match[1]
                    if val:
                        times.append(float(val))
                except ValueError:
                    pass
            
            # Verificar timeout (* ou Request timed out)
            success = hop_ip is not None and len(times) > 0
            
            # Reverse DNS
            hostname = None
            if hop_ip:
                hostname = reverse_dns(hop_ip)
            
            avg_time = statistics.mean(times) if times else 0
            
            hop = TracerouteHop(
                hop=hop_num,
                ip=hop_ip,
                hostname=hostname,
                times_ms=times,
                avg_ms=avg_time,
                success=success
            )
            result.hops.append(hop)
            
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


def generate_ping_graph(
    stats: PingStats,
    output_file: Optional[str] = None,
    show: bool = False
) -> Optional[str]:
    """Gera gráfico de latência do ping ao longo do tempo.
    
    Args:
        stats: Estatísticas de ping
        output_file: Caminho para salvar o gráfico (PNG)
        show: Se True, exibe o gráfico interactivamente
    
    Returns:
        Caminho do ficheiro gerado ou None
    """
    if not MATPLOTLIB_AVAILABLE:
        raise ImportError(
            "Matplotlib não está instalado. Instale com: pip install matplotlib"
        )
    
    # Preparar dados
    successful = [(r.timestamp, r.time_ms) for r in stats.results if r.success]
    if not successful:
        raise ValueError("Sem dados de ping bem-sucedidos para gerar gráfico")
    
    timestamps, times = zip(*successful)
    
    # Criar figura
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Plotar latência
    ax.plot(timestamps, times, 'b-', linewidth=1, marker='o', markersize=4, label='Latência')
    
    # Linha média
    ax.axhline(y=stats.avg_ms, color='g', linestyle='--', linewidth=1, label=f'Média: {stats.avg_ms:.2f}ms')
    
    # Área de jitter
    if stats.jitter_ms > 0:
        ax.fill_between(
            timestamps,
            [stats.avg_ms - stats.jitter_ms] * len(timestamps),
            [stats.avg_ms + stats.jitter_ms] * len(timestamps),
            alpha=0.2, color='green', label=f'Jitter: ±{stats.jitter_ms:.2f}ms'
        )
    
    # Formatação
    ax.set_xlabel('Tempo')
    ax.set_ylabel('Latência (ms)')
    ax.set_title(f'Ping para {stats.host} ({stats.ip})\n'
                 f'Enviados: {stats.packets_sent} | Recebidos: {stats.packets_received} | '
                 f'Perda: {stats.packet_loss_pct:.1f}%')
    ax.legend(loc='upper right')
    ax.grid(True, alpha=0.3)
    
    # Formatar eixo X como tempo
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    fig.autofmt_xdate()
    
    # Limites Y
    if times:
        ax.set_ylim(0, max(times) * 1.2)
    
    plt.tight_layout()
    
    # Salvar/exibir
    if output_file:
        # Criar diretório graphs/ se não existir
        if not os.path.isabs(output_file):
            graphs_dir = os.path.join(os.path.dirname(__file__), 'graphs')
            os.makedirs(graphs_dir, exist_ok=True)
            output_file = os.path.join(graphs_dir, output_file)
        
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        print(f"\nGráfico salvo em: {output_file}")
    
    if show:
        plt.show()
    
    plt.close()
    
    return output_file if output_file else None


def generate_traceroute_graph(
    result: TracerouteResult,
    output_file: Optional[str] = None,
    show: bool = False
) -> Optional[str]:
    """Gera gráfico de latência por hop do traceroute.
    
    Args:
        result: Resultado do traceroute
        output_file: Caminho para salvar o gráfico
        show: Se True, exibe interactivamente
    
    Returns:
        Caminho do ficheiro ou None
    """
    if not MATPLOTLIB_AVAILABLE:
        raise ImportError(
            "Matplotlib não está instalado. Instale com: pip install matplotlib"
        )
    
    if not result.hops:
        raise ValueError("Sem hops para gerar gráfico")
    
    # Preparar dados
    hops = []
    latencies = []
    labels = []
    
    for hop in result.hops:
        if hop.success:
            hops.append(hop.hop)
            latencies.append(hop.avg_ms)
            label = hop.hostname if hop.hostname else hop.ip
            if len(label) > 20:
                label = label[:17] + "..."
            labels.append(f"{hop.hop}: {label}")
    
    if not hops:
        raise ValueError("Sem hops bem-sucedidos para gerar gráfico")
    
    # Criar figura
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Gráfico de barras
    bars = ax.bar(range(len(hops)), latencies, color='steelblue', edgecolor='navy')
    
    # Valores nas barras
    for bar, lat in zip(bars, latencies):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f'{lat:.1f}ms', ha='center', va='bottom', fontsize=8)
    
    # Formatação
    ax.set_xlabel('Hop')
    ax.set_ylabel('Latência média (ms)')
    ax.set_title(f'Traceroute para {result.target} ({result.target_ip})\n'
                 f'Total de hops: {len(result.hops)} | '
                 f'Destino alcançado: {"Sim" if result.reached else "Não"}')
    ax.set_xticks(range(len(hops)))
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    ax.grid(True, axis='y', alpha=0.3)
    
    plt.tight_layout()
    
    # Salvar/exibir
    if output_file:
        if not os.path.isabs(output_file):
            graphs_dir = os.path.join(os.path.dirname(__file__), 'graphs')
            os.makedirs(graphs_dir, exist_ok=True)
            output_file = os.path.join(graphs_dir, output_file)
        
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        print(f"\nGráfico salvo em: {output_file}")
    
    if show:
        plt.show()
    
    plt.close()
    
    return output_file if output_file else None


def check_matplotlib() -> None:
    """Verifica se matplotlib está disponível."""
    if not MATPLOTLIB_AVAILABLE:
        raise ImportError(
            "Matplotlib não está instalado. Instale com: pip install matplotlib"
        )
