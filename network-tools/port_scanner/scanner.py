"""Port scanner simples (estilo Nmap simplificado).

Funcionalidades:
- Recebe hostname/IP e intervalo de portas.
- Tenta conectar-se a cada porta usando sockets.
- Indica quais portas estão abertas ou fechadas.
- Usa threads para acelerar a varredura.
- Tratamento de exceções e mensagens claras para o utilizador.

Uso:
python -m port_scanner.scanner --host example.com --start 1 --end 1024 --threads 100 --timeout 0.5

O código é escrito de forma clara e comentada para fácil leitura.
"""
from __future__ import annotations

import argparse
import queue
import socket
import threading
import time
from typing import List


def scan_port(host: str, port: int, timeout: float) -> bool:
    """Tenta conectar ao host:port com timeout. Retorna True se aberta."""
    try:
        # create_connection faz a resolução e tenta estabelecer TCP
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False
    except OSError:
        # Outros erros de socket (ex.: rede inatingível)
        return False


def worker(host: str, ports: queue.Queue, timeout: float, results: List[int], lock: threading.Lock) -> None:
    """Thread worker que consome portas da fila e testa cada uma."""
    while True:
        try:
            port = ports.get_nowait()
        except queue.Empty:
            return

        is_open = scan_port(host, port, timeout)
        if is_open:
            with lock:
                results.append(port)
        ports.task_done()


def run_scan(host: str, start: int, end: int, threads: int = 100, timeout: float = 0.5) -> List[int]:
    """Executa a varredura e devolve lista de portas abertas (ordenadas).

    Parâmetros:
    - host: hostname ou IP (string)
    - start, end: intervalo de portas (inclusive)
    - threads: número de threads concorrentes
    - timeout: timeout por tentativa em segundos
    """
    # Resolver host para IP (boas mensagens de erro)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{host}': {e}") from e

    port_queue: queue.Queue[int] = queue.Queue()
    for p in range(start, end + 1):
        port_queue.put(p)

    results: List[int] = []
    lock = threading.Lock()

    # Limitar número de threads ao tamanho do intervalo
    num_threads = min(threads, max(1, end - start + 1))
    thread_list: List[threading.Thread] = []

    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(ip, port_queue, timeout, results, lock), daemon=True)
        t.start()
        thread_list.append(t)

    # Aguardar conclusão
    port_queue.join()

    # Garantir que todas as threads terminaram
    for t in thread_list:
        t.join(0.1)

    results.sort()
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Port scanner simples (estilo Nmap simplificado)")
    parser.add_argument("--host", required=True, help="Hostname ou IP alvo")
    parser.add_argument("--start", type=int, default=1, help="Porta inicial (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="Porta final (default: 1024)")
    parser.add_argument("--threads", type=int, default=100, help="Número de threads concorrentes (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout por conexão em segundos (default: 0.5)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Validações básicas
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("Intervalo de portas inválido. Use --start >= 1, --end <= 65535 e --start <= --end.")
        raise SystemExit(1)

    if args.threads < 1:
        print("--threads deve ser >= 1")
        raise SystemExit(1)

    print(f"Iniciando scan em {args.host} do porto {args.start} ao {args.end} com {args.threads} threads (timeout {args.timeout}s)")
    start_time = time.time()
    try:
        open_ports = run_scan(args.host, args.start, args.end, threads=args.threads, timeout=args.timeout)
    except ValueError as e:
        print(e)
        raise SystemExit(1)

    elapsed = time.time() - start_time
    if open_ports:
        print(f"Portas abertas em {args.host}: {', '.join(map(str, open_ports))}")
    else:
        print(f"Nenhuma porta aberta detectada em {args.host} no intervalo especificado.")

    print(f"Scan concluído em {elapsed:.2f}s")


if __name__ == "__main__":
    main()
