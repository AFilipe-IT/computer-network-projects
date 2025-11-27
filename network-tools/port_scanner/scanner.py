"""Port scanner simples e compacto.

Versão reduzida que usa ThreadPoolExecutor para concisão e melhor legibilidade.
Mensagens e comentários em pt-PT.
"""
from __future__ import annotations

import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List


def is_open(host: str, port: int, timeout: float) -> bool:
    """Tenta ligar a TCP socket; devolve True se a porta estiver aberta."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def run_scan(host: str, start: int, end: int, workers: int, timeout: float) -> List[int]:
    """Varre portas em paralelo e retorna lista ordenada de portas abertas."""
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{host}': {e}") from e

    ports = range(start, end + 1)
    open_ports: List[int] = []

    with ThreadPoolExecutor(max_workers=min(workers, len(list(ports)))) as exe:
        futures = {exe.submit(is_open, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                if fut.result():
                    open_ports.append(port)
            except Exception:
                # Ignorar erros individuais e continuar
                pass

    open_ports.sort()
    return open_ports


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Port scanner TCP simples")
    p.add_argument("--host", required=True, help="Hostname ou IP alvo")
    p.add_argument("--start", type=int, default=1, help="Porta inicial (padrão: 1)")
    p.add_argument("--end", type=int, default=1024, help="Porta final (padrão: 1024)")
    p.add_argument("--threads", type=int, default=100, help="Número de threads (padrão: 100)")
    p.add_argument("--timeout", type=float, default=0.5, help="Timeout por conexão em segundos")
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("Intervalo de portas inválido. --start >=1, --end <=65535 e --start <= --end.")
        raise SystemExit(1)

    print(f"Iniciando varredura em {args.host} ({args.start}-{args.end}) com {args.threads} threads...")
    t0 = time.time()
    try:
        open_ports = run_scan(args.host, args.start, args.end, args.threads, args.timeout)
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
