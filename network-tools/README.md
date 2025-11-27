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

