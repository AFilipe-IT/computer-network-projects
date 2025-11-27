"""Modo por argumentos para o port_scanner.

Exemplo:
    python -m port_scanner.scanner_cli --host 127.0.0.1 --start 1 --end 1024 --threads 100 --timeout 0.3
"""

import argparse
import time

from .core import port_scanner


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Port scanner TCP simples (modo por argumentos)")
    p.add_argument("--host", required=True, help="Hostname ou IP alvo")
    p.add_argument("--start", type=int, default=1, help="Porta inicial (padrão: 1)")
    p.add_argument("--end", type=int, default=1024, help="Porta final (padrão: 1024)")
    p.add_argument("--threads", type=int, default=100, help="Número de workers (padrão: 100)")
    p.add_argument("--timeout", type=float, default=0.5, help="Timeout por conexão em segundos")
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("Intervalo inválido. --start >=1, --end <=65535, --start <= --end")
        raise SystemExit(1)

    print(f"Iniciando varredura em {args.host} ({args.start}-{args.end}) com {args.threads} workers...")
    t0 = time.time()
    try:
        open_ports = port_scanner(args.host, args.start, args.end, args.threads, args.timeout)
    except ValueError as e:
        print(e)
        raise SystemExit(1)

    elapsed = time.time() - t0
    if open_ports:
        print(f"Portas abertas em {args.host}: {', '.join(map(str, open_ports))}")
    else:
        print(f"Nenhuma porta aberta encontrada em {args.host} no intervalo pedido.")

    print(f"Varredura concluída em {elapsed:.2f}s")


if __name__ == "__main__":
    main()
