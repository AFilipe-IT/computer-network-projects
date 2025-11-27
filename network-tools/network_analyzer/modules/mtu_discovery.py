"""
Módulo MTU Discovery - Network Analyzer Pro.

Este módulo fornece funcionalidades para descoberta de Path MTU:
- Descoberta do MTU máximo até um destino
- Teste de fragmentação
- Análise de caminho com diferentes tamanhos

O Path MTU Discovery (PMTUD) é usado para encontrar o maior
tamanho de pacote que pode ser transmitido sem fragmentação.

Exemplo de uso:
    from network_analyzer.modules.mtu_discovery import MTUDiscovery
    
    mtu = MTUDiscovery()
    result = mtu.discover("google.com")
    print(f"Path MTU: {result.mtu} bytes")
"""

import subprocess
import platform
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from datetime import datetime


# =============================================================================
# CONSTANTES
# =============================================================================

# Valores MTU comuns
MTU_VALUES = {
    1500: "Ethernet padrão",
    1492: "PPPoE",
    1480: "PPPoE com DSL",
    1400: "VPN/Túnel",
    1380: "IPsec",
    576: "Mínimo IPv4",
    1280: "Mínimo IPv6",
    9000: "Jumbo Frame",
    4352: "FDDI",
    1476: "PPTP",
    1472: "Ethernet com ICMP overhead",
    1464: "PPPoE com ICMP overhead",
}


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class MTUTestResult:
    """
    Resultado de um teste MTU individual.
    
    Attributes:
        size: Tamanho do pacote testado
        success: Se passou sem fragmentação
        response_time: Tempo de resposta
        ttl: TTL da resposta
    """
    size: int
    success: bool
    response_time: float = 0.0
    ttl: int = 0
    error: str = ""


@dataclass
class MTUDiscoveryResult:
    """
    Resultado da descoberta de Path MTU.
    
    Attributes:
        host: Host destino
        mtu: MTU descoberto
        icmp_payload: Tamanho do payload ICMP
        tests: Lista de testes realizados
        discovery_time: Tempo total de descoberta
    """
    host: str
    mtu: int = 0
    icmp_payload: int = 0
    tests: List[MTUTestResult] = field(default_factory=list)
    discovery_time: float = 0.0
    success: bool = True
    error: Optional[str] = None
    
    @property
    def mtu_description(self) -> str:
        """Descrição do MTU encontrado."""
        if self.mtu in MTU_VALUES:
            return MTU_VALUES[self.mtu]
        
        # Tentar encontrar próximo
        for mtu_val, desc in sorted(MTU_VALUES.items(), reverse=True):
            if self.mtu >= mtu_val:
                return f"~{desc}"
        
        return "Desconhecido"


# =============================================================================
# CLASSE PRINCIPAL
# =============================================================================

class MTUDiscovery:
    """
    Descoberta de Path MTU.
    
    Usa pacotes ICMP com flag Don't Fragment (DF) para
    descobrir o maior MTU possível até um destino.
    
    Attributes:
        timeout: Tempo limite para ping
        min_mtu: MTU mínimo a testar
        max_mtu: MTU máximo a testar
        
    Exemplo:
        >>> mtu = MTUDiscovery()
        >>> result = mtu.discover("8.8.8.8")
        >>> print(f"MTU: {result.mtu} ({result.mtu_description})")
    """
    
    def __init__(
        self,
        timeout: float = 2.0,
        min_mtu: int = 68,
        max_mtu: int = 1500
    ):
        """
        Inicializa o descobridor MTU.
        
        Args:
            timeout: Tempo limite para ping
            min_mtu: MTU mínimo (default 68 - mínimo IP)
            max_mtu: MTU máximo (default 1500 - Ethernet)
        """
        self.timeout = timeout
        self.min_mtu = min_mtu
        self.max_mtu = max_mtu
        self._is_windows = platform.system().lower() == "windows"
    
    def _calculate_icmp_payload(self, mtu: int) -> int:
        """
        Calcula o payload ICMP para um dado MTU.
        
        MTU = IP Header (20) + ICMP Header (8) + Payload
        Payload = MTU - 28
        
        Args:
            mtu: Tamanho MTU desejado
            
        Returns:
            Tamanho do payload ICMP
        """
        return mtu - 28  # IP header (20) + ICMP header (8)
    
    def _test_size(self, host: str, size: int) -> MTUTestResult:
        """
        Testa um tamanho específico de pacote.
        
        Args:
            host: Host destino
            size: Tamanho do payload ICMP
            
        Returns:
            MTUTestResult
        """
        result = MTUTestResult(size=size + 28, success=False)
        
        try:
            if self._is_windows:
                # Windows: -f = don't fragment, -l = payload size
                cmd = [
                    "ping", "-4", "-n", "1",
                    "-f", "-l", str(size),
                    "-w", str(int(self.timeout * 1000)),
                    host
                ]
            else:
                # Linux/Mac: -M do = don't fragment, -s = payload size
                cmd = [
                    "ping", "-4", "-c", "1",
                    "-M", "do", "-s", str(size),
                    "-W", str(int(self.timeout)),
                    host
                ]
            
            start = time.perf_counter()
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 1
            )
            elapsed = (time.perf_counter() - start) * 1000
            
            # Verificar sucesso
            output = proc.stdout + proc.stderr
            
            # Fragmentação necessária
            if self._is_windows:
                if "fragmented" in output.lower() or "fragment" in output.lower():
                    result.error = "Fragmentação necessária"
                    return result
            else:
                if "frag needed" in output.lower() or "message too long" in output.lower():
                    result.error = "Fragmentação necessária"
                    return result
            
            # Timeout ou host inalcançável
            if proc.returncode != 0:
                if "unreachable" in output.lower():
                    result.error = "Host inalcançável"
                else:
                    result.error = "Timeout"
                return result
            
            # Sucesso
            result.success = True
            result.response_time = elapsed
            
            # Extrair TTL
            ttl_match = re.search(r"TTL[=:]?\s*(\d+)", output, re.IGNORECASE)
            if ttl_match:
                result.ttl = int(ttl_match.group(1))
            
        except subprocess.TimeoutExpired:
            result.error = "Timeout"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def discover(
        self,
        host: str,
        callback: Optional[callable] = None
    ) -> MTUDiscoveryResult:
        """
        Descobre o Path MTU para um host.
        
        Usa busca binária para encontrar eficientemente
        o maior MTU que passa sem fragmentação.
        
        Args:
            host: Host destino
            callback: Função chamada com (mtu_teste, sucesso, progresso)
            
        Returns:
            MTUDiscoveryResult
            
        Exemplo:
            >>> def on_test(mtu, ok, progress):
            ...     status = "✓" if ok else "✗"
            ...     print(f"{mtu}: {status}")
            >>> result = mtu.discover("8.8.8.8", callback=on_test)
        """
        result = MTUDiscoveryResult(host=host)
        start_time = time.perf_counter()
        
        # Primeiro, verificar se o host responde
        initial_test = self._test_size(host, 64)
        if not initial_test.success:
            result.success = False
            result.error = f"Host não responde: {initial_test.error}"
            result.discovery_time = time.perf_counter() - start_time
            return result
        
        # Busca binária para encontrar o MTU
        low = self._calculate_icmp_payload(self.min_mtu)
        high = self._calculate_icmp_payload(self.max_mtu)
        best_mtu = self.min_mtu
        
        iteration = 0
        max_iterations = 20  # Segurança
        
        while low <= high and iteration < max_iterations:
            iteration += 1
            mid = (low + high) // 2
            
            test_result = self._test_size(host, mid)
            result.tests.append(test_result)
            
            if callback:
                progress = iteration / max_iterations
                callback(mid + 28, test_result.success, progress)
            
            if test_result.success:
                best_mtu = mid + 28  # Converter payload para MTU
                low = mid + 1
            else:
                high = mid - 1
        
        result.mtu = best_mtu
        result.icmp_payload = best_mtu - 28
        result.discovery_time = time.perf_counter() - start_time
        
        return result
    
    def test_common_mtus(
        self,
        host: str,
        mtus: Optional[List[int]] = None
    ) -> Dict[int, bool]:
        """
        Testa valores MTU comuns.
        
        Args:
            host: Host destino
            mtus: Lista de MTUs a testar (usa comuns se None)
            
        Returns:
            Dicionário {MTU: sucesso}
        """
        if mtus is None:
            mtus = [576, 1280, 1400, 1472, 1480, 1492, 1500]
        
        results = {}
        for mtu in sorted(mtus, reverse=True):
            payload = self._calculate_icmp_payload(mtu)
            if payload > 0:
                test = self._test_size(host, payload)
                results[mtu] = test.success
        
        return results
    
    def get_interface_mtu(self) -> Dict[str, int]:
        """
        Obtém MTU das interfaces locais.
        
        Returns:
            Dicionário {interface: MTU}
        """
        mtus = {}
        
        try:
            if self._is_windows:
                result = subprocess.run(
                    ["netsh", "interface", "ipv4", "show", "interfaces"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Parsear output do netsh
                for line in result.stdout.split('\n'):
                    # Formato: Idx  Met  MTU   State  Name
                    parts = line.split()
                    if len(parts) >= 5 and parts[2].isdigit():
                        mtu = int(parts[2])
                        name = ' '.join(parts[4:])
                        mtus[name] = mtu
            else:
                result = subprocess.run(
                    ["ip", "link", "show"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Parsear output do ip link
                current_iface = ""
                for line in result.stdout.split('\n'):
                    if ':' in line and '<' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            current_iface = parts[1].strip()
                    
                    mtu_match = re.search(r'mtu\s+(\d+)', line)
                    if mtu_match and current_iface:
                        mtus[current_iface] = int(mtu_match.group(1))
                        current_iface = ""
                        
        except Exception:
            pass
        
        return mtus


def discover_mtu(host: str, timeout: float = 2.0) -> int:
    """
    Função conveniente para descobrir MTU.
    
    Args:
        host: Host destino
        timeout: Tempo limite
        
    Returns:
        MTU descoberto ou 0 em erro
    """
    discovery = MTUDiscovery(timeout=timeout)
    result = discovery.discover(host)
    return result.mtu if result.success else 0


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    print("=== Teste do módulo MTU Discovery ===\n")
    
    mtu = MTUDiscovery(timeout=2)
    
    # MTU das interfaces locais
    print("--- MTU das Interfaces Locais ---")
    interfaces = mtu.get_interface_mtu()
    for iface, mtu_val in interfaces.items():
        desc = MTU_VALUES.get(mtu_val, "")
        print(f"  {iface}: {mtu_val} bytes {desc}")
    
    # Teste de MTUs comuns
    host = "8.8.8.8"
    print(f"\n--- Teste de MTUs comuns para {host} ---")
    common_results = mtu.test_common_mtus(host)
    
    for mtu_val, success in common_results.items():
        status = "✓" if success else "✗"
        desc = MTU_VALUES.get(mtu_val, "")
        print(f"  {mtu_val}: {status} {desc}")
    
    # Descoberta de Path MTU
    print(f"\n--- Descoberta de Path MTU para {host} ---")
    print("A descobrir...")
    
    def progress(test_mtu, ok, pct):
        status = "OK" if ok else "FAIL"
        print(f"  MTU {test_mtu}: {status}")
    
    result = mtu.discover(host, callback=progress)
    
    if result.success:
        print(f"\nPath MTU: {result.mtu} bytes")
        print(f"Descrição: {result.mtu_description}")
        print(f"ICMP Payload máximo: {result.icmp_payload} bytes")
        print(f"Testes realizados: {len(result.tests)}")
        print(f"Tempo: {result.discovery_time:.2f}s")
    else:
        print(f"Erro: {result.error}")
