"""Módulo core do port_scanner.

Contém a lógica de varredura reutilizável (funções testáveis).
"""

import socket
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


def _worker(ip: str, q: Queue, timeout: float, results: List[int]):
    while True:
        port = q.get()
        if port is None:
            q.task_done()
            break
        if scan_port(ip, port, timeout):
            results.append(port)
        q.task_done()


def port_scanner(host: str, start: int, end: int, threads: int = 100, timeout: float = 0.5) -> List[int]:
    """Varre o intervalo de portas e devolve lista de portas abertas.

    - host: hostname ou IP
    - start, end: intervalo (inclusive)
    - threads: número máximo de workers
    - timeout: timeout por conexão em segundos
    """
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{host}': {e}") from e

    q: Queue = Queue()
    results: List[int] = []

    # enfileira portas
    for p in range(start, end + 1):
        q.put(p)

    # inicia workers
    num_workers = min(threads, end - start + 1)
    workers: List[Thread] = []
    for _ in range(num_workers):
        t = Thread(target=_worker, args=(ip, q, timeout, results), daemon=True)
        t.start()
        workers.append(t)

    q.join()

    # sinaliza término
    for _ in workers:
        q.put(None)
    for t in workers:
        t.join()

    results.sort()
    return results
