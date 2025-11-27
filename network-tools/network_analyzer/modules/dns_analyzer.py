"""
Módulo DNS Analyzer - Network Analyzer Pro.

Este módulo fornece funcionalidades completas de análise DNS incluindo:
- Lookup de diversos tipos de registos (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR)
- DNS reverso (IP para hostname)
- Medição de tempo de resolução
- Verificação de múltiplos servidores DNS
- Detecção de propagação DNS

O módulo usa a biblioteca dnspython se disponível, com fallback para
funções nativas do socket para operações básicas.

Exemplo de uso:
    from network_analyzer.modules.dns_analyzer import DNSAnalyzer
    
    dns = DNSAnalyzer()
    
    # Lookup simples
    result = dns.lookup("google.com", "A")
    print(result.records)
    
    # Todos os registos
    all_records = dns.lookup_all("google.com")
    for record_type, data in all_records.items():
        print(f"{record_type}: {data}")
"""

import socket
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime

# Tentar importar dnspython para funcionalidades avançadas
try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class DNSRecord:
    """
    Representa um registo DNS.
    
    Attributes:
        record_type: Tipo do registo (A, AAAA, MX, etc.)
        value: Valor do registo
        ttl: Time To Live em segundos
        priority: Prioridade (para MX)
    """
    record_type: str
    value: str
    ttl: int = 0
    priority: Optional[int] = None


@dataclass
class DNSResult:
    """
    Resultado de uma consulta DNS.
    
    Attributes:
        query: Domínio consultado
        record_type: Tipo de registo solicitado
        records: Lista de registos encontrados
        server: Servidor DNS usado
        response_time_ms: Tempo de resposta em ms
        success: Se a consulta foi bem-sucedida
        error: Mensagem de erro se falhou
        timestamp: Momento da consulta
    """
    query: str
    record_type: str
    records: List[DNSRecord] = field(default_factory=list)
    server: str = "default"
    response_time_ms: float = 0.0
    success: bool = True
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def values(self) -> List[str]:
        """Retorna apenas os valores dos registos."""
        return [r.value for r in self.records]


# =============================================================================
# SERVIDORES DNS PÚBLICOS
# =============================================================================

PUBLIC_DNS_SERVERS = {
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220"],
    "Quad9": ["9.9.9.9", "149.112.112.112"],
    "AdGuard": ["94.140.14.14", "94.140.15.15"],
}


# =============================================================================
# CLASSE PRINCIPAL
# =============================================================================

class DNSAnalyzer:
    """
    Analisador DNS completo.
    
    Fornece métodos para consultar diferentes tipos de registos DNS,
    medir tempos de resposta e comparar resultados entre servidores.
    
    Attributes:
        timeout: Tempo limite para consultas em segundos
        
    Exemplo:
        >>> dns = DNSAnalyzer(timeout=5.0)
        >>> result = dns.lookup("example.com", "A")
        >>> print(result.records)
    """
    
    # Tipos de registos suportados
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]
    
    def __init__(self, timeout: float = 5.0):
        """
        Inicializa o analisador DNS.
        
        Args:
            timeout: Tempo limite para consultas em segundos
        """
        self.timeout = timeout
        self._resolver = None
        
        # Configurar resolver se dnspython disponível
        if DNSPYTHON_AVAILABLE:
            self._resolver = dns.resolver.Resolver()
            self._resolver.timeout = timeout
            self._resolver.lifetime = timeout
    
    def lookup(
        self, 
        domain: str, 
        record_type: str = "A",
        server: Optional[str] = None
    ) -> DNSResult:
        """
        Consulta um registo DNS específico.
        
        Args:
            domain: Nome do domínio a consultar
            record_type: Tipo de registo (A, AAAA, MX, NS, TXT, CNAME, SOA)
            server: Servidor DNS a usar (None = default do sistema)
            
        Returns:
            DNSResult com os registos encontrados
            
        Exemplo:
            >>> result = dns.lookup("google.com", "MX")
            >>> for record in result.records:
            ...     print(f"MX: {record.value} (prioridade: {record.priority})")
        """
        record_type = record_type.upper()
        
        if record_type not in self.RECORD_TYPES:
            return DNSResult(
                query=domain,
                record_type=record_type,
                success=False,
                error=f"Tipo de registo inválido: {record_type}"
            )
        
        # Usar dnspython se disponível
        if DNSPYTHON_AVAILABLE:
            return self._lookup_dnspython(domain, record_type, server)
        else:
            return self._lookup_socket(domain, record_type)
    
    def _lookup_dnspython(
        self, 
        domain: str, 
        record_type: str,
        server: Optional[str] = None
    ) -> DNSResult:
        """Consulta DNS usando dnspython."""
        result = DNSResult(
            query=domain,
            record_type=record_type,
            server=server or "default"
        )
        
        # Configurar servidor se especificado
        if server:
            self._resolver.nameservers = [server]
        
        try:
            start = time.perf_counter()
            answers = self._resolver.resolve(domain, record_type)
            result.response_time_ms = (time.perf_counter() - start) * 1000
            
            for rdata in answers:
                record = DNSRecord(
                    record_type=record_type,
                    value=str(rdata),
                    ttl=answers.ttl
                )
                
                # Extrair prioridade para MX
                if record_type == "MX":
                    record.priority = rdata.preference
                    record.value = str(rdata.exchange)
                
                result.records.append(record)
                
        except dns.resolver.NXDOMAIN:
            result.success = False
            result.error = "Domínio não existe (NXDOMAIN)"
        except dns.resolver.NoAnswer:
            result.success = False
            result.error = f"Sem registos {record_type} para este domínio"
        except dns.resolver.Timeout:
            result.success = False
            result.error = "Timeout na consulta DNS"
        except dns.exception.DNSException as e:
            result.success = False
            result.error = str(e)
        except Exception as e:
            result.success = False
            result.error = str(e)
        
        return result
    
    def _lookup_socket(self, domain: str, record_type: str) -> DNSResult:
        """Consulta DNS usando socket (fallback básico)."""
        result = DNSResult(
            query=domain,
            record_type=record_type,
            server="system"
        )
        
        try:
            start = time.perf_counter()
            
            if record_type == "A":
                # Obter IPv4
                ip = socket.gethostbyname(domain)
                result.records.append(DNSRecord(
                    record_type="A",
                    value=ip
                ))
                
            elif record_type == "AAAA":
                # Obter IPv6
                infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
                for info in infos:
                    ip = info[4][0]
                    if ip not in [r.value for r in result.records]:
                        result.records.append(DNSRecord(
                            record_type="AAAA",
                            value=ip
                        ))
                        
            else:
                result.success = False
                result.error = f"dnspython necessário para registos {record_type}"
                return result
            
            result.response_time_ms = (time.perf_counter() - start) * 1000
            
        except socket.gaierror as e:
            result.success = False
            result.error = str(e)
        except Exception as e:
            result.success = False
            result.error = str(e)
        
        return result
    
    def lookup_all(self, domain: str) -> Dict[str, DNSResult]:
        """
        Consulta todos os tipos de registos DNS para um domínio.
        
        Args:
            domain: Nome do domínio a consultar
            
        Returns:
            Dicionário com tipo de registo -> DNSResult
            
        Exemplo:
            >>> all_records = dns.lookup_all("google.com")
            >>> for rtype, result in all_records.items():
            ...     if result.success:
            ...         print(f"{rtype}: {result.values}")
        """
        results = {}
        for record_type in self.RECORD_TYPES:
            if record_type != "PTR":  # PTR requer IP, não domínio
                results[record_type] = self.lookup(domain, record_type)
        return results
    
    def reverse_lookup(self, ip: str) -> DNSResult:
        """
        Resolve um IP para hostname (DNS reverso / PTR).
        
        Args:
            ip: Endereço IP a resolver
            
        Returns:
            DNSResult com o hostname
            
        Exemplo:
            >>> result = dns.reverse_lookup("8.8.8.8")
            >>> print(result.values)  # ['dns.google']
        """
        result = DNSResult(
            query=ip,
            record_type="PTR"
        )
        
        try:
            start = time.perf_counter()
            hostname, _, _ = socket.gethostbyaddr(ip)
            result.response_time_ms = (time.perf_counter() - start) * 1000
            
            result.records.append(DNSRecord(
                record_type="PTR",
                value=hostname
            ))
            
        except socket.herror as e:
            result.success = False
            result.error = f"Sem registo PTR: {e}"
        except Exception as e:
            result.success = False
            result.error = str(e)
        
        return result
    
    def compare_servers(
        self, 
        domain: str, 
        record_type: str = "A"
    ) -> Dict[str, DNSResult]:
        """
        Compara resultados entre diferentes servidores DNS públicos.
        
        Útil para verificar propagação DNS ou diferenças entre resolvers.
        
        Args:
            domain: Nome do domínio a consultar
            record_type: Tipo de registo a consultar
            
        Returns:
            Dicionário com nome do servidor -> DNSResult
            
        Exemplo:
            >>> results = dns.compare_servers("example.com", "A")
            >>> for server, result in results.items():
            ...     print(f"{server}: {result.response_time_ms:.1f}ms")
        """
        if not DNSPYTHON_AVAILABLE:
            return {"error": DNSResult(
                query=domain,
                record_type=record_type,
                success=False,
                error="dnspython necessário para esta funcionalidade"
            )}
        
        results = {}
        
        for name, servers in PUBLIC_DNS_SERVERS.items():
            result = self.lookup(domain, record_type, server=servers[0])
            result.server = f"{name} ({servers[0]})"
            results[name] = result
        
        return results
    
    def measure_resolution_time(
        self, 
        domain: str, 
        iterations: int = 5
    ) -> Dict[str, float]:
        """
        Mede o tempo de resolução DNS (múltiplas iterações).
        
        Args:
            domain: Nome do domínio a consultar
            iterations: Número de iterações
            
        Returns:
            Dicionário com estatísticas de tempo
            
        Exemplo:
            >>> stats = dns.measure_resolution_time("google.com", 10)
            >>> print(f"Média: {stats['avg_ms']:.2f}ms")
        """
        times = []
        
        for _ in range(iterations):
            result = self.lookup(domain, "A")
            if result.success:
                times.append(result.response_time_ms)
        
        if not times:
            return {"error": "Todas as consultas falharam"}
        
        import statistics
        return {
            "min_ms": min(times),
            "max_ms": max(times),
            "avg_ms": statistics.mean(times),
            "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
            "samples": len(times)
        }


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    print("=== Teste do módulo DNS Analyzer ===\n")
    
    if not DNSPYTHON_AVAILABLE:
        print("⚠ dnspython não instalado. Funcionalidades limitadas.")
        print("  Instale com: pip install dnspython\n")
    
    dns = DNSAnalyzer()
    domain = "google.com"
    
    # Teste básico
    print(f"--- Lookup A para {domain} ---")
    result = dns.lookup(domain, "A")
    if result.success:
        print(f"IPs: {result.values}")
        print(f"Tempo: {result.response_time_ms:.2f}ms")
    else:
        print(f"Erro: {result.error}")
    
    # DNS reverso
    print(f"\n--- DNS Reverso para 8.8.8.8 ---")
    result = dns.reverse_lookup("8.8.8.8")
    if result.success:
        print(f"Hostname: {result.values}")
    else:
        print(f"Erro: {result.error}")
    
    # Todos os registos
    if DNSPYTHON_AVAILABLE:
        print(f"\n--- Todos os registos para {domain} ---")
        all_records = dns.lookup_all(domain)
        for rtype, res in all_records.items():
            if res.success and res.records:
                print(f"{rtype}: {res.values[:3]}...")  # Mostrar só 3
