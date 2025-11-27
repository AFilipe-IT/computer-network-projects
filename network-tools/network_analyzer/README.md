# Network Analyzer - Ping/Traceroute Avançado

Ferramenta de análise de rede que combina ping e traceroute com capacidade de gerar gráficos de desempenho. Inclui **interface gráfica (GUI)** para diagnóstico visual em tempo real.

> **Nota:** Este projeto foi desenvolvido com auxílio de IA (GitHub Copilot).

## Funcionalidades

- **Ping avançado**: Mede latência com estatísticas completas (min/max/média/jitter)
- **Traceroute**: Traça a rota até o destino com latência por hop
- **Gráficos**: Gera visualizações de latência ao longo do tempo
- **Interface Gráfica (GUI)**: Diagnóstico visual em tempo real com gráficos dinâmicos
- **Três modos de uso**: GUI, Interativo (terminal) e CLI (argumentos)

## Estrutura

```
network_analyzer/
├── __init__.py          # Marcador de pacote
├── core.py              # Lógica principal (ping, traceroute, gráficos)
├── gui.py               # Interface gráfica (Tkinter + Matplotlib)
├── run_gui.py           # Launcher para a GUI
├── analyzer.py          # Modo interativo
├── analyzer_cli.py      # Modo CLI (argumentos)
├── graphs/              # Pasta para gráficos gerados
└── README.md            # Este ficheiro
```

## Requisitos

- Python 3.x
- matplotlib (para gráficos)
- tkinter (incluído no Python)

```bash
pip install matplotlib
```

## Uso

### 🖥️ Interface Gráfica (GUI) - RECOMENDADO

```bash
cd network-tools
python network_analyzer/run_gui.py
```

A interface gráfica permite:
- Visualizar latência em **tempo real** com gráficos animados
- Alternar entre modo Ping e Traceroute
- Ver estatísticas actualizadas dinamicamente
- Iniciar/parar análise a qualquer momento

![GUI Preview](graphs/gui_preview.png)

### Modo Interativo

```bash
python -m network_analyzer.analyzer
```

O programa vai solicitar:
1. Host/IP de destino
2. Modo (ping ou traceroute)
3. Configurações específicas
4. Se deseja gerar gráfico

### Modo CLI

```bash
# Ping básico
python -m network_analyzer.analyzer_cli --host google.com

# Ping com 20 pacotes e gráfico
python -m network_analyzer.analyzer_cli --host 8.8.8.8 --mode ping --count 20 --graph

# Traceroute
python -m network_analyzer.analyzer_cli --host cloudflare.com --mode traceroute

# Traceroute com gráfico
python -m network_analyzer.analyzer_cli -H example.com -m traceroute --graph

# Opções avançadas
python -m network_analyzer.analyzer_cli --host 1.1.1.1 -c 50 -i 0.5 -t 3 --graph --show
```

### Argumentos CLI

| Argumento | Descrição | Default |
|-----------|-----------|---------|
| `-H, --host` | Host ou IP de destino (obrigatório) | - |
| `-m, --mode` | Modo: `ping` ou `traceroute` | `ping` |
| `-c, --count` | Número de pings (0=infinito) | `10` |
| `-i, --interval` | Intervalo entre pings (segundos) | `1.0` |
| `-t, --timeout` | Timeout por request (segundos) | `2.0` |
| `--max-hops` | Máximo de hops no traceroute | `30` |
| `-g, --graph` | Gerar gráfico de latência | - |
| `-o, --output` | Ficheiro de saída do gráfico | auto |
| `--show` | Exibir gráfico interactivamente | - |

## Exemplos de Output

### Ping

```
============================================================
Ping para google.com (10)
============================================================

[001] Resposta de 142.250.200.46: tempo=12.3ms TTL=118
[002] Resposta de 142.250.200.46: tempo=11.8ms TTL=118
[003] Resposta de 142.250.200.46: tempo=13.1ms TTL=118
...

============================================================
Estatísticas de ping para google.com (142.250.200.46):
  Pacotes: enviados=10, recebidos=10, perdidos=0 (0.0% perda)
  Tempos: mín=11.2ms, máx=15.4ms, média=12.6ms, jitter=1.2ms
============================================================
```

### Traceroute

```
============================================================
Traceroute para cloudflare.com
============================================================

 1  192.168.1.1 (router.local)  1.2ms  1.0ms  1.1ms
 2  10.0.0.1  8.5ms  7.9ms  8.2ms
 3  * * * Request timed out
 4  172.16.0.1 (isp-core.net)  15.3ms  14.8ms  15.1ms
...

============================================================
Destino cloudflare.com (104.16.132.229) alcançado em 12 hops
============================================================
```

## Gráficos

Os gráficos são salvos na pasta `graphs/` com nomes automáticos:
- `ping_google_com.png` - Gráfico de latência do ping
- `traceroute_google_com.png` - Gráfico de latência por hop

### Exemplo de Gráfico de Ping

O gráfico de ping mostra:
- Latência ao longo do tempo (linha azul)
- Média (linha verde tracejada)
- Área de jitter (sombra verde)
- Estatísticas no título

### Exemplo de Gráfico de Traceroute

O gráfico de traceroute mostra:
- Barras de latência por hop
- Identificação de cada hop (IP/hostname)
- Latência média em cada barra

## Como Funciona

### Ping

1. Usa o comando `ping` do sistema (Windows/Linux)
2. Parseia a saída para extrair TTL e latência
3. Calcula estatísticas: min, max, média, desvio padrão (jitter)
4. Opcional: gera gráfico com matplotlib

### Traceroute

1. Usa `tracert` (Windows) ou `traceroute` (Linux)
2. Parseia cada hop com IP e tempos
3. Tenta resolver hostname via DNS reverso
4. Opcional: gera gráfico de barras com latência por hop

## Notas

- **Privilégios**: Em alguns sistemas Linux, traceroute pode requerer sudo
- **Firewall**: Alguns routers podem bloquear ICMP, causando timeouts
- **Precisão**: A latência é extraída do comando do sistema para maior precisão
- **Matplotlib**: Se não instalado, a ferramenta funciona sem gráficos
