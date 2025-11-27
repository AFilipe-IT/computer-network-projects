# Network Tools

Coleção de ferramentas de rede para diagnóstico, monitoramento e automação. Este repositório reúne projetos práticos em Python e outras linguagens voltados para redes. Ideal para quem quer aprender protocolos, segurança e administração de redes através de exemplos reais e código aberto.

## Ferramentas disponíveis

### 1. IP Subnet Calculator
Calculadora de sub-redes IP com suporte a VLSM, divisão igual, modo interativo e saída JSON.

```powershell
cd network-tools
python -m ip_subnet_calculator.cli --network 192.168.0.0/24 --hosts 100,50 --json
```

📁 [Documentação completa](ip_subnet_calculator/README.md)

### 2. Port Scanner
Scanner de portas TCP simples com threads, timeouts configuráveis e interface amigável.

```powershell
cd network-tools
python -m port_scanner.scanner_cli --host 127.0.0.1 --start 1 --end 1024
```

📁 [Documentação completa](port_scanner/README.md)

### 3. Packet Sniffer
Analisador de tráfego de rede (captura de pacotes) com filtros BPF e exportação PCAP.

```powershell
cd network-tools
python -m packet_sniffer.sniffer_cli -c 50 -f tcp -o capture.pcap
```

📁 [Documentação completa](packet_sniffer/README.md)

**Nota**: Packet Sniffer requer Scapy (`pip install scapy`) e privilégios de administrador/root.

### 4. Network Analyzer Pro 🆕

Ferramenta **completa** de análise de rede com 11 módulos especializados e interface gráfica profissional.

#### Módulos Disponíveis:
| Módulo | Descrição |
|--------|-----------|
| 🏓 **Ping** | Teste de conectividade com estatísticas avançadas |
| 🛤️ **Traceroute** | Rastreamento de rota com geolocalização |
| 📋 **DNS Analyzer** | Consultas DNS (A, AAAA, MX, NS, TXT, CNAME, SOA) |
| 🌐 **HTTP Analyzer** | Análise de headers, SSL/TLS, timing |
| 🖥️ **Network Info** | Informações de interfaces, IP público, gateway |
| 🔍 **Port Scanner** | Scanner TCP com detecção de serviços e banners |
| 📝 **WHOIS Lookup** | Consultas WHOIS e geolocalização |
| 🔌 **Connection Monitor** | Monitor de conexões ativas por processo |
| ⚡ **Bandwidth Test** | Teste de velocidade de download/latência |
| 📡 **ARP Scanner** | Descoberta de hosts na rede local |
| 📏 **MTU Discovery** | Descoberta de Path MTU |

#### Execução:

```powershell
cd network-tools

# Instalar dependências
pip install -r requirements.txt

# Interface Gráfica Completa (RECOMENDADO)
python network_analyzer/run_gui_pro.py

# Interface Gráfica Simples (apenas Ping/Traceroute)
python network_analyzer/run_gui.py

# CLI: Ping com gráfico de latência
python -m network_analyzer.analyzer_cli --host google.com --count 10 --graph

# CLI: Traceroute com gráfico
python -m network_analyzer.analyzer_cli --host 8.8.8.8 --mode traceroute --graph
```

#### Uso como Biblioteca:

```python
from network_analyzer import modules

# Ping
result = modules.ping("google.com")
print(f"Latência: {result.time_ms}ms")

# DNS
dns = modules.dns_lookup("google.com")
for record in dns.records:
    print(f"{record.type}: {record.value}")

# Port Scan
ports = modules.scan_common_ports("192.168.1.1")
for p in ports:
    if p.is_open:
        print(f"Porta {p.port}: {p.service}")

# Descobrir hosts na rede
hosts = modules.scan_network("192.168.1.0/24")
for host in hosts.hosts:
    print(f"{host.ip} - {host.mac}")
```

📁 [Documentação completa](network_analyzer/README.md)

**Dependências**: `pip install matplotlib dnspython requests psutil`

---

## Instalação Rápida

```powershell
# Clonar repositório
git clone https://github.com/AFilipe-IT/computer-network-projects.git
cd computer-network-projects/network-tools

# Criar ambiente virtual
python -m venv .venv
.\.venv\Scripts\Activate

# Instalar dependências
pip install -r requirements.txt
```

---

> **Nota:** Este projeto foi desenvolvido com auxílio de IA (GitHub Copilot).

