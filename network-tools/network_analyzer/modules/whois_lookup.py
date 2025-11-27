"""
Módulo Whois Lookup - Network Analyzer Pro.

Este módulo fornece funcionalidades de pesquisa Whois e geolocalização:
- Whois lookup para domínios
- Whois lookup para IPs
- Geolocalização de IPs
- Informações de ASN (Autonomous System Number)
- Detecção de ISP

Exemplo de uso:
    from network_analyzer.modules.whois_lookup import WhoisLookup
    
    whois = WhoisLookup()
    
    # Whois de domínio
    result = whois.lookup_domain("google.com")
    print(f"Registrar: {result.registrar}")
    
    # Geolocalização
    geo = whois.geolocate("8.8.8.8")
    print(f"País: {geo.country}, Cidade: {geo.city}")
"""

import socket
import re
import urllib.request
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


# =============================================================================
# CLASSES DE DADOS
# =============================================================================

@dataclass
class WhoisDomainResult:
    """
    Resultado de Whois para domínio.
    
    Attributes:
        domain: Nome do domínio
        registrar: Empresa registadora
        creation_date: Data de criação
        expiration_date: Data de expiração
        updated_date: Última actualização
        name_servers: Lista de servidores DNS
        status: Estado do domínio
        registrant: Informação do registante
        raw_data: Dados brutos do Whois
        success: Se a consulta foi bem-sucedida
        error: Mensagem de erro
    """
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    registrant: str = ""
    raw_data: str = ""
    success: bool = True
    error: Optional[str] = None


@dataclass
class WhoisIPResult:
    """
    Resultado de Whois para IP.
    
    Attributes:
        ip: Endereço IP
        network: Range de rede
        netname: Nome da rede
        description: Descrição
        country: Código do país
        asn: Autonomous System Number
        asn_name: Nome do AS
        isp: Internet Service Provider
        org: Organização
        raw_data: Dados brutos
        success: Se foi bem-sucedido
        error: Mensagem de erro
    """
    ip: str
    network: str = ""
    netname: str = ""
    description: str = ""
    country: str = ""
    asn: str = ""
    asn_name: str = ""
    isp: str = ""
    org: str = ""
    raw_data: str = ""
    success: bool = True
    error: Optional[str] = None


@dataclass
class GeoIPResult:
    """
    Resultado de geolocalização.
    
    Attributes:
        ip: Endereço IP
        country: Nome do país
        country_code: Código do país (ISO)
        region: Região/Estado
        city: Cidade
        zip_code: Código postal
        latitude: Latitude
        longitude: Longitude
        timezone: Fuso horário
        isp: ISP
        org: Organização
        asn: ASN
        success: Se foi bem-sucedido
        error: Mensagem de erro
    """
    ip: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    zip_code: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    success: bool = True
    error: Optional[str] = None
    
    @property
    def coordinates(self) -> str:
        """Retorna coordenadas formatadas."""
        return f"{self.latitude}, {self.longitude}"
    
    @property
    def maps_url(self) -> str:
        """Retorna URL do Google Maps."""
        return f"https://www.google.com/maps?q={self.latitude},{self.longitude}"


# =============================================================================
# SERVIDORES WHOIS
# =============================================================================

WHOIS_SERVERS = {
    ".com": "whois.verisign-grs.com",
    ".net": "whois.verisign-grs.com",
    ".org": "whois.pir.org",
    ".info": "whois.afilias.net",
    ".io": "whois.nic.io",
    ".pt": "whois.dns.pt",
    ".br": "whois.registro.br",
    ".de": "whois.denic.de",
    ".uk": "whois.nic.uk",
    ".fr": "whois.nic.fr",
    ".it": "whois.nic.it",
    ".es": "whois.nic.es",
    ".eu": "whois.eu",
    ".nl": "whois.domain-registry.nl",
    ".ru": "whois.tcinet.ru",
    ".cn": "whois.cnnic.cn",
    ".jp": "whois.jprs.jp",
    ".au": "whois.auda.org.au",
    ".ca": "whois.cira.ca",
}


# =============================================================================
# CLASSE PRINCIPAL
# =============================================================================

class WhoisLookup:
    """
    Pesquisa Whois e geolocalização de IPs.
    
    Fornece métodos para consultar informações de registo de domínios
    e IPs, bem como geolocalização.
    
    Attributes:
        timeout: Tempo limite para consultas
        
    Exemplo:
        >>> whois = WhoisLookup()
        >>> domain_info = whois.lookup_domain("example.com")
        >>> ip_geo = whois.geolocate("8.8.8.8")
    """
    
    def __init__(self, timeout: float = 10.0):
        """
        Inicializa o módulo.
        
        Args:
            timeout: Tempo limite em segundos
        """
        self.timeout = timeout
    
    def lookup_domain(self, domain: str) -> WhoisDomainResult:
        """
        Pesquisa Whois para um domínio.
        
        Args:
            domain: Nome do domínio
            
        Returns:
            WhoisDomainResult com informações do registo
            
        Exemplo:
            >>> result = whois.lookup_domain("google.com")
            >>> print(f"Registrar: {result.registrar}")
            >>> print(f"Expira: {result.expiration_date}")
        """
        result = WhoisDomainResult(domain=domain)
        
        # Extrair TLD
        tld = "." + domain.split(".")[-1].lower()
        
        # Obter servidor Whois
        whois_server = WHOIS_SERVERS.get(tld, "whois.iana.org")
        
        try:
            # Conectar ao servidor Whois
            raw_data = self._query_whois(whois_server, domain)
            result.raw_data = raw_data
            
            # Se IANA, procurar servidor real
            if whois_server == "whois.iana.org":
                match = re.search(r"whois:\s*(\S+)", raw_data, re.IGNORECASE)
                if match:
                    whois_server = match.group(1)
                    raw_data = self._query_whois(whois_server, domain)
                    result.raw_data = raw_data
            
            # Parsear dados
            self._parse_domain_whois(result, raw_data)
            
        except Exception as e:
            result.success = False
            result.error = str(e)
        
        return result
    
    def lookup_ip(self, ip: str) -> WhoisIPResult:
        """
        Pesquisa Whois para um endereço IP.
        
        Args:
            ip: Endereço IP
            
        Returns:
            WhoisIPResult com informações da rede
            
        Exemplo:
            >>> result = whois.lookup_ip("8.8.8.8")
            >>> print(f"ASN: {result.asn}")
            >>> print(f"Org: {result.org}")
        """
        result = WhoisIPResult(ip=ip)
        
        try:
            # Usar ARIN para lookup de IP
            raw_data = self._query_whois("whois.arin.net", f"n {ip}")
            
            # Se referenciado para outro RIR
            if "RIPE" in raw_data:
                raw_data = self._query_whois("whois.ripe.net", ip)
            elif "APNIC" in raw_data:
                raw_data = self._query_whois("whois.apnic.net", ip)
            elif "AFRINIC" in raw_data:
                raw_data = self._query_whois("whois.afrinic.net", ip)
            elif "LACNIC" in raw_data:
                raw_data = self._query_whois("whois.lacnic.net", ip)
            
            result.raw_data = raw_data
            self._parse_ip_whois(result, raw_data)
            
        except Exception as e:
            result.success = False
            result.error = str(e)
        
        return result
    
    def geolocate(self, ip: str) -> GeoIPResult:
        """
        Geolocaliza um endereço IP.
        
        Usa serviços externos gratuitos para obter localização.
        
        Args:
            ip: Endereço IP
            
        Returns:
            GeoIPResult com informações de localização
            
        Exemplo:
            >>> geo = whois.geolocate("8.8.8.8")
            >>> print(f"País: {geo.country}")
            >>> print(f"Cidade: {geo.city}")
            >>> print(f"Mapa: {geo.maps_url}")
        """
        result = GeoIPResult(ip=ip)
        
        # Tentar múltiplos serviços
        services = [
            self._geolocate_ipapi,
            self._geolocate_ipinfo,
        ]
        
        for service in services:
            try:
                if service(ip, result):
                    return result
            except Exception:
                continue
        
        result.success = False
        result.error = "Não foi possível obter geolocalização"
        return result
    
    def _query_whois(self, server: str, query: str) -> str:
        """Executa consulta Whois a um servidor."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect((server, 43))
            sock.send((query + "\r\n").encode())
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            return response.decode('utf-8', errors='ignore')
    
    def _parse_domain_whois(self, result: WhoisDomainResult, data: str):
        """Parsear dados Whois de domínio."""
        patterns = {
            'registrar': [
                r"Registrar:\s*(.+)",
                r"Registrar Name:\s*(.+)",
            ],
            'creation_date': [
                r"Creation Date:\s*(.+)",
                r"Created:\s*(.+)",
                r"Registration Date:\s*(.+)",
            ],
            'expiration_date': [
                r"Registry Expiry Date:\s*(.+)",
                r"Expiration Date:\s*(.+)",
                r"Expiry Date:\s*(.+)",
            ],
            'updated_date': [
                r"Updated Date:\s*(.+)",
                r"Last Updated:\s*(.+)",
            ],
        }
        
        for field, field_patterns in patterns.items():
            for pattern in field_patterns:
                match = re.search(pattern, data, re.IGNORECASE)
                if match:
                    setattr(result, field, match.group(1).strip())
                    break
        
        # Name servers
        ns_matches = re.findall(r"Name Server:\s*(\S+)", data, re.IGNORECASE)
        result.name_servers = list(set(ns.lower() for ns in ns_matches))
        
        # Status
        status_matches = re.findall(r"Domain Status:\s*(\S+)", data, re.IGNORECASE)
        result.status = list(set(status_matches))
    
    def _parse_ip_whois(self, result: WhoisIPResult, data: str):
        """Parsear dados Whois de IP."""
        patterns = {
            'netname': r"NetName:\s*(.+)|netname:\s*(.+)",
            'description': r"descr:\s*(.+)|Organization:\s*(.+)",
            'country': r"Country:\s*(\w+)|country:\s*(\w+)",
            'org': r"OrgName:\s*(.+)|org-name:\s*(.+)",
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, data, re.IGNORECASE)
            if match:
                value = match.group(1) or match.group(2)
                setattr(result, field, value.strip() if value else "")
        
        # Network range
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)", data)
        if match:
            result.network = f"{match.group(1)} - {match.group(2)}"
        
        # ASN
        match = re.search(r"AS(\d+)", data)
        if match:
            result.asn = f"AS{match.group(1)}"
    
    def _geolocate_ipapi(self, ip: str, result: GeoIPResult) -> bool:
        """Geolocalização via ip-api.com."""
        url = f"http://ip-api.com/json/{ip}"
        
        with urllib.request.urlopen(url, timeout=self.timeout) as response:
            data = json.loads(response.read().decode())
            
            if data.get("status") == "success":
                result.country = data.get("country", "")
                result.country_code = data.get("countryCode", "")
                result.region = data.get("regionName", "")
                result.city = data.get("city", "")
                result.zip_code = data.get("zip", "")
                result.latitude = data.get("lat", 0.0)
                result.longitude = data.get("lon", 0.0)
                result.timezone = data.get("timezone", "")
                result.isp = data.get("isp", "")
                result.org = data.get("org", "")
                result.asn = data.get("as", "")
                return True
        
        return False
    
    def _geolocate_ipinfo(self, ip: str, result: GeoIPResult) -> bool:
        """Geolocalização via ipinfo.io."""
        url = f"https://ipinfo.io/{ip}/json"
        
        with urllib.request.urlopen(url, timeout=self.timeout) as response:
            data = json.loads(response.read().decode())
            
            result.country = data.get("country", "")
            result.country_code = data.get("country", "")
            result.region = data.get("region", "")
            result.city = data.get("city", "")
            result.zip_code = data.get("postal", "")
            
            loc = data.get("loc", "").split(",")
            if len(loc) == 2:
                result.latitude = float(loc[0])
                result.longitude = float(loc[1])
            
            result.timezone = data.get("timezone", "")
            result.org = data.get("org", "")
            
            return True
    
    def get_my_ip(self) -> str:
        """
        Obtém o IP público actual.
        
        Returns:
            Endereço IP público
        """
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
        ]
        
        for service in services:
            try:
                with urllib.request.urlopen(service, timeout=5) as response:
                    return response.read().decode().strip()
            except Exception:
                continue
        
        return ""


# =============================================================================
# TESTE DO MÓDULO
# =============================================================================

if __name__ == "__main__":
    print("=== Teste do módulo Whois Lookup ===\n")
    
    whois = WhoisLookup()
    
    # Teste geolocalização
    print("--- Geolocalização de 8.8.8.8 ---")
    geo = whois.geolocate("8.8.8.8")
    if geo.success:
        print(f"País: {geo.country} ({geo.country_code})")
        print(f"Cidade: {geo.city}, {geo.region}")
        print(f"Coordenadas: {geo.coordinates}")
        print(f"ISP: {geo.isp}")
        print(f"Organização: {geo.org}")
    else:
        print(f"Erro: {geo.error}")
    
    # Teste Whois domínio
    print("\n--- Whois de google.com ---")
    domain = whois.lookup_domain("google.com")
    if domain.success:
        print(f"Registrar: {domain.registrar}")
        print(f"Criado: {domain.creation_date}")
        print(f"Expira: {domain.expiration_date}")
        print(f"Name Servers: {', '.join(domain.name_servers[:3])}")
    else:
        print(f"Erro: {domain.error}")
    
    # Teste IP público
    print("\n--- IP Público ---")
    my_ip = whois.get_my_ip()
    print(f"O seu IP: {my_ip}")
