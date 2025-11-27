"""
Módulo HTTP Analyzer - Network Analyzer Pro.

Este módulo fornece funcionalidades completas de análise HTTP/HTTPS incluindo:
- Verificação de headers HTTP
- Teste de tempo de resposta
- Verificação de certificados SSL/TLS
- Seguimento de redirects
- Análise de segurança de headers

Exemplo de uso:
    from network_analyzer.modules.http_analyzer import HTTPAnalyzer
    
    http = HTTPAnalyzer()
    
    # Analisar URL
    result = http.analyze("https://google.com")
    print(f"Status: {result.status_code}")
    print(f"Tempo: {result.response_time_ms}ms")
    
    # Verificar SSL
    ssl_info = http.check_ssl("google.com")
    print(f"Válido até: {ssl_info.valid_until}")
"""

import socket
import ssl
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class HTTPHeader:
    """
    Representa um header HTTP.
    
    Attributes:
        name: Nome do header
        value: Valor do header
        is_security: Se é um header de segurança
    """
    name: str
    value: str
    is_security: bool = False


@dataclass
class SSLInfo:
    """
    Informação sobre certificado SSL/TLS.
    
    Attributes:
        valid: Se o certificado é válido
        issuer: Entidade emissora
        subject: Sujeito do certificado
        valid_from: Data de início de validade
        valid_until: Data de expiração
        days_remaining: Dias até expiração
        protocol: Protocolo TLS usado
        cipher: Cifra usada
        error: Mensagem de erro se inválido
    """
    valid: bool = True
    issuer: str = ""
    subject: str = ""
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    days_remaining: int = 0
    protocol: str = ""
    cipher: str = ""
    error: Optional[str] = None


@dataclass
class RedirectInfo:
    """
    Informação sobre um redirect.
    
    Attributes:
        url: URL do redirect
        status_code: Código HTTP do redirect
    """
    url: str
    status_code: int


@dataclass
class HTTPResult:
    """
    Resultado completo de uma análise HTTP.
    
    Attributes:
        url: URL analisada
        final_url: URL final após redirects
        status_code: Código de status HTTP
        status_text: Texto do status
        headers: Lista de headers
        response_time_ms: Tempo de resposta em ms
        content_length: Tamanho do conteúdo
        content_type: Tipo de conteúdo
        server: Servidor web
        redirects: Lista de redirects seguidos
        ssl_info: Informação SSL (se HTTPS)
        security_score: Pontuação de segurança (0-100)
        success: Se a requisição foi bem-sucedida
        error: Mensagem de erro se falhou
        timestamp: Momento da análise
    """
    url: str
    final_url: str = ""
    status_code: int = 0
    status_text: str = ""
    headers: List[HTTPHeader] = field(default_factory=list)
    response_time_ms: float = 0.0
    content_length: int = 0
    content_type: str = ""
    server: str = ""
    redirects: List[RedirectInfo] = field(default_factory=list)
    ssl_info: Optional[SSLInfo] = None
    security_score: int = 0
    success: bool = True
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def headers_dict(self) -> Dict[str, str]:
        """Retorna headers como dicionário."""
        return {h.name: h.value for h in self.headers}


# =============================================================================
# HEADERS DE SEGURANÇA
# =============================================================================

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS - Força HTTPS",
    "Content-Security-Policy": "CSP - Previne XSS",
    "X-Content-Type-Options": "Previne MIME sniffing",
    "X-Frame-Options": "Previne clickjacking",
    "X-XSS-Protection": "Filtro XSS do browser",
    "Referrer-Policy": "Controla informação do Referer",
    "Permissions-Policy": "Controla APIs do browser",
    "Cross-Origin-Opener-Policy": "Isolamento de origem",
    "Cross-Origin-Embedder-Policy": "Embeddings de origem cruzada",
    "Cross-Origin-Resource-Policy": "Recursos de origem cruzada",
}


# =============================================================================
# CLASSE PRINCIPAL
# =============================================================================

class HTTPAnalyzer:
    """
    Analisador HTTP/HTTPS completo.
    
    Fornece métodos para analisar URLs, verificar certificados SSL,
    seguir redirects e avaliar segurança de headers.
    
    Attributes:
        timeout: Tempo limite para conexões
        user_agent: User-Agent a usar nas requisições
        follow_redirects: Se deve seguir redirects
        max_redirects: Número máximo de redirects a seguir
    """
    
    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "NetworkAnalyzer/2.0",
        follow_redirects: bool = True,
        max_redirects: int = 10
    ):
        """
        Inicializa o analisador HTTP.
        
        Args:
            timeout: Tempo limite para conexões em segundos
            user_agent: User-Agent a usar
            follow_redirects: Se deve seguir redirects
            max_redirects: Número máximo de redirects
        """
        self.timeout = timeout
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
    
    def analyze(self, url: str) -> HTTPResult:
        """
        Analisa uma URL completa (HTTP ou HTTPS).
        
        Obtém headers, mede tempo de resposta, segue redirects
        e verifica SSL se aplicável.
        
        Args:
            url: URL a analisar
            
        Returns:
            HTTPResult com análise completa
            
        Exemplo:
            >>> result = http.analyze("https://example.com")
            >>> print(f"Status: {result.status_code}")
            >>> print(f"Headers: {len(result.headers)}")
        """
        # Normalizar URL
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        result = HTTPResult(url=url)
        
        try:
            # Criar request
            request = urllib.request.Request(
                url,
                headers={"User-Agent": self.user_agent}
            )
            
            # Configurar handler de redirects
            if self.follow_redirects:
                opener = urllib.request.build_opener(
                    RedirectHandler(result, self.max_redirects)
                )
            else:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPRedirectHandler()
                )
            
            # Fazer requisição
            start = time.perf_counter()
            response = opener.open(request, timeout=self.timeout)
            result.response_time_ms = (time.perf_counter() - start) * 1000
            
            # Processar resposta
            result.final_url = response.geturl()
            result.status_code = response.getcode()
            result.status_text = self._get_status_text(response.getcode())
            
            # Processar headers
            for name, value in response.headers.items():
                is_security = name in SECURITY_HEADERS
                result.headers.append(HTTPHeader(
                    name=name,
                    value=value,
                    is_security=is_security
                ))
            
            # Extrair informações comuns
            result.content_type = response.headers.get("Content-Type", "")
            result.server = response.headers.get("Server", "")
            
            content_length = response.headers.get("Content-Length")
            if content_length:
                result.content_length = int(content_length)
            
            response.close()
            
            # Verificar SSL se HTTPS
            if url.startswith("https://"):
                parsed = urlparse(url)
                result.ssl_info = self.check_ssl(parsed.netloc)
            
            # Calcular pontuação de segurança
            result.security_score = self._calculate_security_score(result)
            
        except urllib.error.HTTPError as e:
            result.status_code = e.code
            result.status_text = self._get_status_text(e.code)
            result.success = e.code < 400
            if e.code >= 400:
                result.error = f"HTTP {e.code}: {e.reason}"
                
        except urllib.error.URLError as e:
            result.success = False
            result.error = str(e.reason)
            
        except Exception as e:
            result.success = False
            result.error = str(e)
        
        return result
    
    def check_ssl(self, hostname: str, port: int = 443) -> SSLInfo:
        """
        Verifica certificado SSL/TLS de um host.
        
        Args:
            hostname: Nome do host a verificar
            port: Porta HTTPS (default: 443)
            
        Returns:
            SSLInfo com detalhes do certificado
            
        Exemplo:
            >>> ssl_info = http.check_ssl("google.com")
            >>> print(f"Válido: {ssl_info.valid}")
            >>> print(f"Expira em: {ssl_info.days_remaining} dias")
        """
        info = SSLInfo()
        
        try:
            # Criar contexto SSL
            context = ssl.create_default_context()
            
            # Conectar
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Obter certificado
                    cert = ssock.getpeercert()
                    
                    # Protocolo e cifra
                    info.protocol = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        info.cipher = f"{cipher[0]} ({cipher[2]} bits)"
                    
                    # Issuer
                    issuer = cert.get("issuer", ())
                    for item in issuer:
                        for key, value in item:
                            if key == "organizationName":
                                info.issuer = value
                                break
                    
                    # Subject
                    subject = cert.get("subject", ())
                    for item in subject:
                        for key, value in item:
                            if key == "commonName":
                                info.subject = value
                                break
                    
                    # Datas
                    not_before = cert.get("notBefore")
                    not_after = cert.get("notAfter")
                    
                    if not_before:
                        info.valid_from = datetime.strptime(
                            not_before, "%b %d %H:%M:%S %Y %Z"
                        )
                    
                    if not_after:
                        info.valid_until = datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        )
                        info.days_remaining = (info.valid_until - datetime.now()).days
                    
                    info.valid = True
                    
        except ssl.SSLCertVerificationError as e:
            info.valid = False
            info.error = f"Certificado inválido: {e.verify_message}"
        except ssl.SSLError as e:
            info.valid = False
            info.error = f"Erro SSL: {e}"
        except socket.timeout:
            info.valid = False
            info.error = "Timeout ao conectar"
        except Exception as e:
            info.valid = False
            info.error = str(e)
        
        return info
    
    def check_headers(self, url: str) -> Dict[str, Tuple[bool, str]]:
        """
        Verifica headers de segurança de uma URL.
        
        Args:
            url: URL a verificar
            
        Returns:
            Dicionário com header -> (presente, descrição)
            
        Exemplo:
            >>> headers = http.check_headers("https://example.com")
            >>> for header, (present, desc) in headers.items():
            ...     status = "✓" if present else "✗"
            ...     print(f"{status} {header}: {desc}")
        """
        result = self.analyze(url)
        headers_dict = result.headers_dict
        
        checks = {}
        for header, description in SECURITY_HEADERS.items():
            present = header in headers_dict
            checks[header] = (present, description)
        
        return checks
    
    def measure_response_time(
        self, 
        url: str, 
        iterations: int = 5
    ) -> Dict[str, float]:
        """
        Mede tempo de resposta HTTP (múltiplas iterações).
        
        Args:
            url: URL a testar
            iterations: Número de iterações
            
        Returns:
            Estatísticas de tempo de resposta
        """
        times = []
        
        for _ in range(iterations):
            result = self.analyze(url)
            if result.success:
                times.append(result.response_time_ms)
        
        if not times:
            return {"error": "Todas as requisições falharam"}
        
        import statistics
        return {
            "min_ms": min(times),
            "max_ms": max(times),
            "avg_ms": statistics.mean(times),
            "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
            "samples": len(times)
        }
    
    def _get_status_text(self, code: int) -> str:
        """Retorna texto descritivo para código HTTP."""
        status_texts = {
            200: "OK",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }
        return status_texts.get(code, "Unknown")
    
    def _calculate_security_score(self, result: HTTPResult) -> int:
        """
        Calcula pontuação de segurança (0-100).
        
        Baseado em headers de segurança presentes, HTTPS e SSL.
        """
        score = 0
        max_score = 100
        
        # HTTPS (+30 pontos)
        if result.url.startswith("https://"):
            score += 30
        
        # SSL válido (+20 pontos)
        if result.ssl_info and result.ssl_info.valid:
            score += 20
        
        # Headers de segurança (50 pontos divididos)
        headers_dict = result.headers_dict
        points_per_header = 50 / len(SECURITY_HEADERS)
        
        for header in SECURITY_HEADERS:
            if header in headers_dict:
                score += points_per_header
        
        return min(int(score), max_score)


class RedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler customizado para rastrear redirects."""
    
    def __init__(self, result: HTTPResult, max_redirects: int):
        super().__init__()
        self.result = result
        self.max_redirects = max_redirects
        self.redirect_count = 0
    
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        
        if self.redirect_count > self.max_redirects:
            raise urllib.error.HTTPError(
                newurl, code, "Too many redirects", headers, fp
            )
        
        self.result.redirects.append(RedirectInfo(
            url=newurl,
            status_code=code
        ))
        
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    print("=== Teste do módulo HTTP Analyzer ===\n")
    
    http = HTTPAnalyzer()
    
    # Teste básico
    url = "https://google.com"
    print(f"--- Análise de {url} ---")
    result = http.analyze(url)
    
    if result.success:
        print(f"Status: {result.status_code} {result.status_text}")
        print(f"URL Final: {result.final_url}")
        print(f"Tempo: {result.response_time_ms:.1f}ms")
        print(f"Servidor: {result.server}")
        print(f"Redirects: {len(result.redirects)}")
        print(f"Pontuação Segurança: {result.security_score}/100")
        
        if result.ssl_info:
            print(f"\n--- SSL/TLS ---")
            print(f"Válido: {result.ssl_info.valid}")
            print(f"Protocolo: {result.ssl_info.protocol}")
            print(f"Expira em: {result.ssl_info.days_remaining} dias")
    else:
        print(f"Erro: {result.error}")
    
    # Headers de segurança
    print(f"\n--- Headers de Segurança ---")
    checks = http.check_headers(url)
    for header, (present, desc) in checks.items():
        status = "✓" if present else "✗"
        print(f"{status} {header}")
