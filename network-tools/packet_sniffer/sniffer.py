"""Packet Sniffer - Modo interativo.

Captura e exibe pacotes de rede com prompts simples.
"""

import sys
from typing import Optional

from .core import (
    check_scapy,
    get_interfaces,
    get_interface_info,
    capture_packets,
    parse_packet,
    format_packet_summary,
)


def print_packet(packet) -> None:
    """Callback para imprimir pacote capturado."""
    if not hasattr(print_packet, 'count'):
        print_packet.count = 0
    print_packet.count += 1
    try:
        info = parse_packet(packet)
        print(f"[{print_packet.count:04d}] {format_packet_summary(info)}")
    except Exception as e:
        print(f"Erro ao processar pacote: {e}")


def interactive_mode() -> None:
    """Modo interativo: captura pacotes com configuração mínima."""
    print("=== Packet Sniffer (modo interativo) ===\n")

    # Verificar Scapy
    try:
        check_scapy()
    except ImportError as e:
        print(f"Erro: {e}")
        sys.exit(1)

    # Listar interfaces disponíveis
    print("Interfaces disponíveis:")
    interfaces = get_interfaces()
    for idx, iface in enumerate(interfaces, 1):
        friendly_name = get_interface_info(iface)
        print(f"  {idx}. {friendly_name}")
    print(f"  0. Todas as interfaces")

    # Prompt: interface
    iface_input = input("\nEscolha a interface (número ou Enter para todas): ").strip()
    if iface_input:
        if iface_input.isdigit():
            idx = int(iface_input)
            if idx == 0:
                interface = None
                print("→ Capturando em todas as interfaces")
            elif 1 <= idx <= len(interfaces):
                interface = interfaces[idx - 1]
                print(f"→ Capturando em: {get_interface_info(interface)}")
            else:
                print("Número inválido, usando todas as interfaces.")
                interface = None
        else:
            interface = iface_input
    else:
        interface = None
        print("→ Capturando em todas as interfaces")

    # Prompt: filtro de protocolo
    print("\nFiltros comuns: tcp, udp, icmp, tcp port 80, udp port 53")
    protocol_filter = input("Filtro BPF (Enter para nenhum): ").strip() or None

    # Prompt: número de pacotes
    count_input = input("Número de pacotes (Enter para 10, 0 para contínuo): ").strip()
    if count_input:
        try:
            count = int(count_input)
        except ValueError:
            print("Valor inválido, usando 10.")
            count = 10
    else:
        count = 10

    # Prompt: exportar PCAP
    export = input("Exportar para PCAP? (s/N): ").strip().lower()
    output_file = None
    if export in ["s", "sim", "y", "yes"]:
        output_file = input("Nome do ficheiro (ex: capture.pcap): ").strip()
        if not output_file:
            output_file = "capture.pcap"

    # Iniciar captura
    print(f"\n{'='*70}")
    print(f"Capturando pacotes...")
    if interface:
        print(f"Interface: {interface}")
    if protocol_filter:
        print(f"Filtro: {protocol_filter}")
    print(f"Pacotes: {count if count > 0 else 'contínuo (Ctrl+C para parar)'}")
    print(f"{'='*70}\n")

    if count == 0:
        print("Modo contínuo ativo. Pressione Ctrl+C para parar.\n")
    else:
        print(f"Aguardando pacotes... (pode demorar se não houver tráfego)\n")

    try:
        packets = capture_packets(
            interface=interface,
            count=count,
            protocol_filter=protocol_filter,
            timeout=None,
            callback=print_packet,
            output_file=output_file,
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
    interactive_mode()
