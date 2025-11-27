# Port Scanner (simplificado)

Pequeno utilitário para varredura de portas TCP em um host, implementado em Python.

Funcionalidades:

Exemplo de uso:

```powershell
python -m port_scanner.scanner --host 127.0.0.1 --start 1 --end 1024 --threads 200 --timeout 0.3
```

Notas:
```markdown
# Port Scanner (simplificado)

Pequeno utilitário para varredura de portas TCP em um host, implementado em Python.

Estrutura
- `core.py`  : lógica reutilizável da varredura (funções testáveis).
- `scanner.py`: entrada em modo interativo (pedidos via stdin).
- `scanner_cli.py`: entrada em modo por argumentos (`argparse`).

Funcionalidades:
- Varredura TCP por ligação (`connect`) — apenas TCP.
- Dois modos de execução: interativo (manual) e por argumentos (scripts/automação).
- Controle de concorrência via workers (threads) e timeout por conexão.

Modos de execução

1) Modo interativo (manual): pede apenas o `Host/Hostname` e executa a varredura com valores padrão.

	- Vá para a pasta `network-tools` e execute:

```powershell
python -m port_scanner.scanner
```

	- Será pedido apenas `Host/Hostname alvo`. As portas e parâmetros usados são:
	  - `start=1`, `end=1024`, `threads=100`, `timeout=0.5`.

2) Modo por argumentos (script CLI): não há prompts, tudo vem por flags.

```powershell
python -m port_scanner.scanner_cli --host 127.0.0.1 --start 1 --end 1024 --threads 100 --timeout 0.3
```

Notas rápidas
- Limites de porta: `--start` >= 1, `--end` <= 65535 e `--start` <= `--end`.
- Use `threads` com cuidado; muitos workers podem sobrecarregar o sistema.

Aviso legal
- Executar scans em hosts que não são de tua propriedade pode ser ilegal ou contra políticas. Usa com responsabilidade.

Pequena nota sobre autoria

Um apoio automático (assistente de programação) foi usado pontualmente para organizar e clarificar o código. A intenção foi manter o projeto simples e didático — a lógica principal e decisões são do autor.

```
