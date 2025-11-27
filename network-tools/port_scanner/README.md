# Port Scanner (simplificado)

Pequeno utilitário didático para varredura de portas TCP em um host, implementado em Python.

## Estrutura

- core.py       : lógica reutilizável da varredura (funções testáveis).
- scanner.py    : entrada em modo interativo (pergunta apenas o host).
- scanner_cli.py: entrada em modo por argumentos (rgparse).

## Funcionalidades

- Varredura TCP por ligação (connect)  apenas TCP.
- Dois modos de execução: interativo (manual) e por argumentos (scripts/automação).
- Controlo de concorrência via workers (threads) e timeout por conexão.

## Modos de execução

### 1) Modo interativo (manual)

- Executa apenas um prompt para o Host/Hostname e usa valores predefinidos para os restantes parâmetros.

- Exemplo (a partir da pasta do projecto):

```powershell
cd network-tools
python -m port_scanner.scanner
```

- Se estiveres na raiz do repositório e o pacote estiver instalado (por exemplo com
	`pip install -e .` a partir da pasta adequada), podes correr o modo CLI directamente:

```powershell
python -m port_scanner.scanner_cli --host 127.0.0.1 --start 1 --end 1024 --threads 100 --timeout 0.3
```

- O scanner pede apenas `Host/Hostname` e usa por omissão: `start=1`, `end=1024`, `threads=100`, `timeout=0.5`.

### 2) Modo por argumentos (CLI)

- Toda a configuração é passada por flags (útil para scripts e automação).

`powershell
python -m port_scanner.scanner_cli --host 127.0.0.1 --start 1 --end 1024 --threads 100 --timeout 0.3
`

- --threads pode ser omitido para usar um valor calculado automaticamente (ver nota no README principal).

## Notas rápidas

- Limites de porta: --start >= 1, --end <= 65535 e --start <= --end.
- Evita usar um número muito alto de 	hreads; preferível deixar o valor automático na maioria dos casos.

## Aviso legal

- Executar scans em hosts que não são da tua propriedade pode ser ilegal ou contra políticas. Usa com responsabilidade.

## Pequena nota sobre autoria

Foi utilizado um apoio automático (assistente de programação) de forma discreta para organizar e clarificar o código. O objetivo foi manter o projecto simples e didático  a lógica principal e as decisões são do autor.
