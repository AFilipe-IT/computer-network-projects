"""Port scanner simples (versão minimalista).

Esta versão usa threads limitadas via `queue.Queue` e workers fixos.
É pequena, fácil de entender e mantém opções de linhas de comando.
"""

import argparse
import socket
import time
from typing import List

from .core import port_scanner


def _prompt_int(prompt: str, default: int) -> int:
    raw = input(f"{prompt} [{default}]: ")
    if not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        print("Valor inválido, usando valor padrão.")
        return default


def interactive_mode() -> None:
    """Modo interactivo: pede valores ao utilizador via stdin."""
    host = input("Host/Hostname alvo: ").strip()
    if not host:
        print("Host obrigatório. Saindo.")
        raise SystemExit(1)

    start = _prompt_int("Porta inicial", 1)
    end = _prompt_int("Porta final", 1024)
    threads = _prompt_int("Número de workers", 100)
    try:
        timeout = float(input("Timeout por conexão (segundos) [0.5]: ") or 0.5)
    except ValueError:
        timeout = 0.5

    print(f"Iniciando varredura em {host} ({start}-{end}) com {threads} workers...")
    open_ports = []
    try:
        open_ports = port_scanner(host, start, end, threads, timeout)
    except ValueError as e:
        print(e)
        raise SystemExit(1)

    if open_ports:
        print(f"Portas abertas em {host}: {', '.join(map(str, open_ports))}")
    else:
        print(f"Nenhuma porta aberta encontrada em {host} no intervalo pedido.")


def build_parser():
    # Mantemos a função em scanner_cli.py; aqui deixamos um stub para import compat.
    raise RuntimeError("Use scanner_cli.py para execução por argumentos, ou execute sem argumentos para modo interativo")


if __name__ == "__main__":
    interactive_mode()

