"""
Módulo Bandwidth Test - Network Analyzer Pro.

Este módulo fornece funcionalidades para testar largura de banda:
- Teste de velocidade de download
- Teste de velocidade de upload
- Latência e jitter
- Servidores de teste customizáveis

Nota: Para testes precisos, recomenda-se usar servidores speedtest
ou o módulo speedtest-cli se disponível.

Exemplo de uso:
    from network_analyzer.modules.bandwidth import BandwidthTest
    
    bw = BandwidthTest()
    
    # Teste simples de download
    result = bw.test_download()
    print(f"Download: {result.speed_mbps} Mbps")
"""

import socket
import time
import urllib.request
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict
from datetime import datetime
import statistics


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class SpeedResult:
    """
    Resultado de um teste de velocidade.
    
    Attributes:
        speed_bps: Velocidade em bits por segundo
        speed_mbps: Velocidade em Megabits por segundo
        bytes_transferred: Total de bytes transferidos
        duration_seconds: Duração do teste
        server: Servidor usado
        timestamp: Momento do teste
        success: Se foi bem-sucedido
        error: Mensagem de erro
    """
    speed_bps: float = 0.0
    bytes_transferred: int = 0
    duration_seconds: float = 0.0
    server: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = True
    error: Optional[str] = None
    
    @property
    def speed_mbps(self) -> float:
        """Velocidade em Mbps."""
        return self.speed_bps / 1_000_000
    
    @property
    def speed_kbps(self) -> float:
        """Velocidade em Kbps."""
        return self.speed_bps / 1_000
    
    @property
    def speed_human(self) -> str:
        """Velocidade em formato legível."""
        if self.speed_mbps >= 1:
            return f"{self.speed_mbps:.2f} Mbps"
        else:
            return f"{self.speed_kbps:.2f} Kbps"


@dataclass
class BandwidthTestResult:
    """
    Resultado completo de teste de largura de banda.
    
    Attributes:
        download: Resultado do teste de download
        upload: Resultado do teste de upload
        ping_ms: Latência em ms
        jitter_ms: Jitter em ms
        server: Servidor usado
        client_ip: IP do cliente
    """
    download: Optional[SpeedResult] = None
    upload: Optional[SpeedResult] = None
    ping_ms: float = 0.0
    jitter_ms: float = 0.0
    server: str = ""
    client_ip: str = ""


# =============================================================================
# SERVIDORES DE TESTE
# =============================================================================

# URLs para teste de download (ficheiros grandes públicos)
DOWNLOAD_TEST_URLS = [
    # Cloudflare - vários tamanhos
    ("https://speed.cloudflare.com/__down?bytes=10000000", "Cloudflare 10MB"),
    ("https://speed.cloudflare.com/__down?bytes=25000000", "Cloudflare 25MB"),
    # Outros
    ("http://speedtest.tele2.net/10MB.zip", "Tele2 10MB"),
    ("http://ipv4.download.thinkbroadband.com/10MB.zip", "ThinkBroadband 10MB"),
]


# =============================================================================
# CLASSE PRINCIPAL
# =============================================================================

class BandwidthTest:
    """
    Teste de largura de banda de rede.
    
    Fornece métodos para testar velocidade de download e upload,
    bem como latência da conexão.
    
    Attributes:
        timeout: Tempo limite para testes
        chunk_size: Tamanho de bloco para leitura
        
    Exemplo:
        >>> bw = BandwidthTest()
        >>> result = bw.run_full_test()
        >>> print(f"Download: {result.download.speed_human}")
        >>> print(f"Ping: {result.ping_ms}ms")
    """
    
    def __init__(
        self,
        timeout: float = 30.0,
        chunk_size: int = 8192
    ):
        """
        Inicializa o teste.
        
        Args:
            timeout: Tempo limite em segundos
            chunk_size: Tamanho de bloco de leitura
        """
        self.timeout = timeout
        self.chunk_size = chunk_size
    
    def test_download(
        self,
        url: Optional[str] = None,
        callback: Optional[Callable[[int, float], None]] = None
    ) -> SpeedResult:
        """
        Testa velocidade de download.
        
        Args:
            url: URL do ficheiro para download (usa default se None)
            callback: Função chamada com (bytes, velocidade) durante download
            
        Returns:
            SpeedResult com a velocidade medida
            
        Exemplo:
            >>> def progress(bytes_dl, speed):
            ...     print(f"Downloaded {bytes_dl/1e6:.1f}MB at {speed:.1f} Mbps")
            >>> result = bw.test_download(callback=progress)
        """
        result = SpeedResult()
        
        # Seleccionar URL
        if url is None:
            url, server = DOWNLOAD_TEST_URLS[0]
            result.server = server
        else:
            result.server = url
        
        try:
            # Criar request
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "NetworkAnalyzer/2.0"}
            )
            
            # Iniciar download
            start_time = time.perf_counter()
            total_bytes = 0
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                while True:
                    chunk = response.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    total_bytes += len(chunk)
                    elapsed = time.perf_counter() - start_time
                    
                    # Callback com progresso
                    if callback and elapsed > 0:
                        current_speed = (total_bytes * 8) / elapsed
                        callback(total_bytes, current_speed / 1_000_000)
                    
                    # Limite de tempo
                    if elapsed > self.timeout:
                        break
            
            # Calcular resultado
            result.duration_seconds = time.perf_counter() - start_time
            result.bytes_transferred = total_bytes
            
            if result.duration_seconds > 0:
                result.speed_bps = (total_bytes * 8) / result.duration_seconds
            
        except Exception as e:
            result.success = False
            result.error = str(e)
        
        return result
    
    def test_upload(
        self,
        size_bytes: int = 5_000_000,
        callback: Optional[Callable[[int, float], None]] = None
    ) -> SpeedResult:
        """
        Testa velocidade de upload.
        
        Nota: Este teste usa um servidor local ou echo service.
        Para testes precisos, use speedtest-cli.
        
        Args:
            size_bytes: Tamanho de dados a enviar
            callback: Função de progresso
            
        Returns:
            SpeedResult com a velocidade estimada
        """
        result = SpeedResult()
        result.server = "Local estimate"
        
        try:
            # Gerar dados aleatórios
            data = b'0' * size_bytes
            
            # Tentar upload para servidor de teste
            # Nota: Muitos servidores não aceitam uploads grandes
            # Este é um teste simplificado
            
            url = "https://httpbin.org/post"
            
            start_time = time.perf_counter()
            
            request = urllib.request.Request(
                url,
                data=data[:min(size_bytes, 100_000)],  # Limitar para httpbin
                headers={
                    "User-Agent": "NetworkAnalyzer/2.0",
                    "Content-Type": "application/octet-stream"
                }
            )
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read()
            
            result.duration_seconds = time.perf_counter() - start_time
            result.bytes_transferred = min(size_bytes, 100_000)
            
            if result.duration_seconds > 0:
                result.speed_bps = (result.bytes_transferred * 8) / result.duration_seconds
            
        except Exception as e:
            result.success = False
            result.error = str(e)
        
        return result
    
    def test_latency(
        self,
        host: str = "8.8.8.8",
        port: int = 53,
        samples: int = 5
    ) -> Dict[str, float]:
        """
        Testa latência da conexão.
        
        Args:
            host: Host para testar
            port: Porta para conectar
            samples: Número de amostras
            
        Returns:
            Dicionário com min, max, avg, jitter
            
        Exemplo:
            >>> latency = bw.test_latency()
            >>> print(f"Ping: {latency['avg']:.1f}ms")
        """
        times = []
        
        for _ in range(samples):
            try:
                start = time.perf_counter()
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                sock.close()
                
                elapsed = (time.perf_counter() - start) * 1000
                times.append(elapsed)
                
            except Exception:
                continue
            
            time.sleep(0.1)
        
        if not times:
            return {"error": "Todas as conexões falharam"}
        
        return {
            "min": min(times),
            "max": max(times),
            "avg": statistics.mean(times),
            "jitter": statistics.stdev(times) if len(times) > 1 else 0,
            "samples": len(times)
        }
    
    def run_full_test(
        self,
        download: bool = True,
        upload: bool = True,
        latency: bool = True,
        callback: Optional[Callable[[str, float], None]] = None
    ) -> BandwidthTestResult:
        """
        Executa teste completo de largura de banda.
        
        Args:
            download: Se deve testar download
            upload: Se deve testar upload
            latency: Se deve testar latência
            callback: Função chamada com (fase, progresso 0-1)
            
        Returns:
            BandwidthTestResult com todos os resultados
            
        Exemplo:
            >>> def on_progress(phase, progress):
            ...     print(f"{phase}: {progress*100:.0f}%")
            >>> result = bw.run_full_test(callback=on_progress)
        """
        result = BandwidthTestResult()
        
        # Obter IP do cliente
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
                result.client_ip = r.read().decode().strip()
        except Exception:
            result.client_ip = "Unknown"
        
        # Teste de latência
        if latency:
            if callback:
                callback("latency", 0)
            
            lat_result = self.test_latency()
            if "error" not in lat_result:
                result.ping_ms = lat_result["avg"]
                result.jitter_ms = lat_result["jitter"]
            
            if callback:
                callback("latency", 1.0)
        
        # Teste de download
        if download:
            if callback:
                callback("download", 0)
            
            def dl_callback(bytes_dl, speed):
                if callback:
                    # Estimar progresso (assumindo ~10MB de download)
                    progress = min(bytes_dl / 10_000_000, 1.0)
                    callback("download", progress)
            
            result.download = self.test_download(callback=dl_callback)
            
            if callback:
                callback("download", 1.0)
        
        # Teste de upload
        if upload:
            if callback:
                callback("upload", 0)
            
            result.upload = self.test_upload()
            
            if callback:
                callback("upload", 1.0)
        
        return result
    
    def quick_test(self) -> Dict[str, str]:
        """
        Teste rápido de velocidade.
        
        Returns:
            Dicionário com resultados formatados
        """
        result = self.run_full_test(upload=False)
        
        return {
            "download": result.download.speed_human if result.download else "N/A",
            "ping": f"{result.ping_ms:.1f} ms" if result.ping_ms else "N/A",
            "jitter": f"{result.jitter_ms:.1f} ms" if result.jitter_ms else "N/A",
            "client_ip": result.client_ip
        }


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    print("=== Teste do módulo Bandwidth Test ===\n")
    
    bw = BandwidthTest(timeout=15)
    
    # Teste de latência
    print("--- Teste de Latência ---")
    latency = bw.test_latency()
    if "error" not in latency:
        print(f"Ping: {latency['avg']:.1f} ms")
        print(f"Jitter: {latency['jitter']:.1f} ms")
        print(f"Min/Max: {latency['min']:.1f}/{latency['max']:.1f} ms")
    else:
        print(f"Erro: {latency['error']}")
    
    # Teste de download
    print("\n--- Teste de Download ---")
    print("A testar...")
    
    def progress(bytes_dl, speed):
        mb = bytes_dl / 1_000_000
        print(f"\r  {mb:.1f} MB - {speed:.1f} Mbps", end="", flush=True)
    
    dl_result = bw.test_download(callback=progress)
    print()
    
    if dl_result.success:
        print(f"Velocidade: {dl_result.speed_human}")
        print(f"Transferido: {dl_result.bytes_transferred/1e6:.1f} MB")
        print(f"Duração: {dl_result.duration_seconds:.1f} s")
    else:
        print(f"Erro: {dl_result.error}")
    
    # Resumo rápido
    print("\n--- Resumo Rápido ---")
    quick = bw.quick_test()
    for key, value in quick.items():
        print(f"{key}: {value}")
