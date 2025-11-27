"""Port scanner simples (versão minimalista).

Esta versão usa threads limitadas via `queue.Queue` e workers fixos.
É pequena, fácil de entender e mantém opções de linhas de comando.
"""

import argparse
import socket
import time
from queue import Queue
from threading import Thread
from typing import List


def scan_port(ip: str, port: int, timeout: float) -> bool:
    """Tenta conectar a um par (ip, port). Retorna True se a porta estiver aberta."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def worker(ip: str, q: Queue, timeout: float, results: List[int]):
    while True:
        port = q.get()
        if port is None:
            q.task_done()
            break
        if scan_port(ip, port, timeout):
            results.append(port)
        q.task_done()


def port_scanner(host: str, start: int, end: int, threads: int = 100, timeout: float = 0.5) -> List[int]:
    """Varre o intervalo de portas e devolve lista de portas abertas."""
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{host}': {e}") from e

    q: Queue = Queue()
    results: List[int] = []

    # enfileira portas
    for p in range(start, end + 1):
        q.put(p)

    # limita número de workers
    num_workers = min(threads, end - start + 1)
    workers: List[Thread] = []
    for _ in range(num_workers):
        t = Thread(target=worker, args=(ip, q, timeout, results), daemon=True)
        t.start()
        workers.append(t)

    # aguarda conclusão da fila
    q.join()

    # sinaliza término e junta threads
    for _ in workers:
        q.put(None)
    for t in workers:
        t.join()

    results.sort()
    return results


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Port scanner TCP simples (versão minimalista)")
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
