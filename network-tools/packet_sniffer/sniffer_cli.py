"""Packet Sniffer - Modo por argumentos (CLI).

Captura e exibe pacotes com configuração via flags.
"""

import argparse
import sys

from .core import (
    check_scapy,
    get_interfaces,
    capture_packets,
    parse_packet,
    format_packet_summary,
)


def print_packet(packet) -> None:
    """Callback para imprimir pacote capturado."""
    try:
        info = parse_packet(packet)
        print(format_packet_summary(info))
    except Exception as e:
        print(f"Erro ao processar pacote: {e}")


def print_packet_with_counter(packet) -> None:
    """Callback com contador para feedback visual."""
    if not hasattr(print_packet_with_counter, 'count'):
        print_packet_with_counter.count = 0
    print_packet_with_counter.count += 1
    try:
        info = parse_packet(packet)
        print(f"[{print_packet_with_counter.count:04d}] {format_packet_summary(info)}")
    except Exception as e:
        print(f"Erro ao processar pacote: {e}")


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos."""
    p = argparse.ArgumentParser(
        description="Packet Sniffer - Analisador de tráfego de rede (modo CLI)"
    )
    p.add_argument(
        "-i", "--interface",
        help="Interface de rede (deixe vazio para todas)",
    )
    p.add_argument(
        "-c", "--count",
        type=int,
        default=10,
        help="Número de pacotes a capturar (0 = contínuo, padrão: 10)",
    )
    p.add_argument(
        "-f", "--filter",
        help="Filtro BPF (ex: 'tcp', 'udp port 53', 'icmp')",
    )
    p.add_argument(
        "-t", "--timeout",
        type=int,
        help="Timeout em segundos (padrão: sem limite)",
    )
    p.add_argument(
        "-o", "--output",
        help="Exportar pacotes capturados para ficheiro PCAP",
    )
    p.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Listar interfaces disponíveis e sair",
    )
    return p


def main() -> None:
    """Ponto de entrada CLI."""
    parser = build_parser()
    args = parser.parse_args()

    # Verificar Scapy
    try:
        check_scapy()
    except ImportError as e:
        print(f"Erro: {e}")
        sys.exit(1)

    # Listar interfaces se solicitado
    if args.list_interfaces:
        print("Interfaces disponíveis:")
        for iface in get_interfaces():
            print(f"  - {iface}")
        sys.exit(0)

    # Informações da captura
    print(f"{'='*70}")
    print("Capturando pacotes...")
    if args.interface:
        print(f"Interface: {args.interface}")
    if args.filter:
        print(f"Filtro: {args.filter}")
    print(f"Pacotes: {args.count if args.count > 0 else 'contínuo (Ctrl+C para parar)'}")
    if args.timeout:
        print(f"Timeout: {args.timeout}s")
    if args.output:
        print(f"Exportar para: {args.output}")
    print(f"{'='*70}\n")

    if args.count == 0:
        print("Modo contínuo ativo. Pressione Ctrl+C para parar.\n")
    else:
        print(f"Aguardando pacotes... (pode demorar se não houver tráfego)\n")

    # Capturar pacotes
    try:
        packets = capture_packets(
            interface=args.interface,
            count=args.count,
            protocol_filter=args.filter,
            timeout=args.timeout,
            callback=print_packet_with_counter,
            output_file=args.output,
        )
        print(f"\nCaptura concluída: {len(packets)} pacotes.")
    except KeyboardInterrupt:
        print("\n\nCaptura interrompida pelo utilizador.")
    except PermissionError as e:
        print(f"\nErro: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nErro: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
