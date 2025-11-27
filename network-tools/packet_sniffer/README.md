# Packet Sniffer (Analisador de Tráfego)

Ferramenta didática para captura e análise de pacotes de rede, similar ao tcpdump/Wireshark simplificado.

## Estrutura

- `core.py`       : lógica de captura usando Scapy (parse de headers, filtros, exportação PCAP).
- `sniffer.py`    : modo interativo (prompts simples para interface e filtro).
- `sniffer_cli.py`: modo por argumentos (flags para automação).

## Funcionalidades

- Captura de pacotes por interface de rede.
- Filtro por protocolo (TCP, UDP, ICMP) usando sintaxe BPF.
- Exibição de headers: endereços IP, portas, MAC, TTL, flags TCP.
- Exportação para formato PCAP (compatível com Wireshark).
- Dois modos de execução: interativo e CLI.

## Requisitos

- Python 3.7+
- Scapy: `pip install scapy`
- **Windows**: instalar [Npcap](https://npcap.com/) para captura de pacotes.
- **Linux/macOS**: privilégios de root/sudo podem ser necessários para captura raw.

Instalar dependências:

```powershell
pip install -r requirements.txt
```

## Modos de execução

### 1) Modo interativo (manual)

- Pede apenas interface, filtro e número de pacotes via prompts.

```powershell
cd network-tools
python -m packet_sniffer.sniffer
```

- Exemplo de sessão:
  - Interface: `Ethernet` ou número da lista
  - Filtro BPF: `tcp port 80` (ou Enter para capturar tudo)
  - Pacotes: `20` (ou `0` para contínuo)
  - Exportar: `s` para guardar PCAP

### 2) Modo por argumentos (CLI)

- Configuração completa via flags (útil para scripts).

```powershell
python -m packet_sniffer.sniffer_cli -i Ethernet -c 50 -f "tcp port 443" -o capture.pcap
```

- Listar interfaces disponíveis:

```powershell
python -m packet_sniffer.sniffer_cli --list-interfaces
```

- Captura contínua (parar com Ctrl+C):

```powershell
python -m packet_sniffer.sniffer_cli -i eth0 -c 0 -f icmp
```

## Argumentos CLI

- `-i`, `--interface`: Interface de rede (deixar vazio para todas).
- `-c`, `--count`: Número de pacotes (0 = contínuo, padrão: 10).
- `-f`, `--filter`: Filtro BPF (ex: `tcp`, `udp port 53`, `icmp`).
- `-t`, `--timeout`: Timeout em segundos.
- `-o`, `--output`: Exportar para ficheiro PCAP.
- `--list-interfaces`: Listar interfaces disponíveis.

## Exemplos de filtros BPF

- `tcp`: Apenas pacotes TCP.
- `udp`: Apenas pacotes UDP.
- `icmp`: Apenas pacotes ICMP (ping).
- `tcp port 80`: Tráfego HTTP (porta 80).
- `tcp port 443`: Tráfego HTTPS (porta 443).
- `udp port 53`: Tráfego DNS (porta 53).
- `host 192.168.1.1`: Tráfego de/para IP específico.
- `net 192.168.0.0/24`: Tráfego de/para sub-rede.

## Notas importantes

### Permissões

- **Windows**: executar como Administrador ou instalar Npcap.
- **Linux/macOS**: executar com `sudo` para captura raw de pacotes.

Exemplo Linux:

```bash
sudo python3 -m packet_sniffer.sniffer_cli -i eth0 -c 100 -f tcp
```

### Legalidade e Ética

- **Apenas captura tráfego da tua própria rede ou com autorização explícita.**
- Capturar tráfego de terceiros sem consentimento pode ser ilegal e violar políticas de privacidade.
- Esta ferramenta é para fins educacionais e diagnóstico de redes próprias.

## Exemplo de saída

```
======================================================================
Capturando pacotes...
Interface: Ethernet
Filtro: tcp port 443
Pacotes: 20
======================================================================

[14:23:45.123] TCP  192.168.1.10:52341 -> 93.184.216.34:443
[14:23:45.145] TCP  93.184.216.34:443  -> 192.168.1.10:52341
[14:23:45.167] TCP  192.168.1.10:52341 -> 93.184.216.34:443
...

Captura concluída: 20 pacotes.
20 pacotes exportados para: capture.pcap
```

## Estrutura do pacote capturado

Cada pacote exibe:
- `[Timestamp]`: Hora de captura (HH:MM:SS.mmm).
- `Protocolo`: TCP, UDP, ICMP, etc.
- `IP origem:porta` -> `IP destino:porta`.
- Informações adicionais: flags TCP, tipo ICMP, etc.

## Exportação PCAP

Os ficheiros `.pcap` gerados podem ser abertos no Wireshark para análise detalhada:

```powershell
wireshark capture.pcap
```

## Pequena nota sobre autoria

Foi utilizado um apoio automático (assistente de programação) de forma discreta para estruturar e documentar o código. O objetivo foi criar uma ferramenta educacional e clara — a lógica e decisões de design são do autor.
