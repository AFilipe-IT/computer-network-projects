"""Módulo core do packet_sniffer.

Contém a lógica de captura e análise de pacotes usando Scapy.
"""

import os
from datetime import datetime
from typing import Callable, Optional, Dict, List

try:
    from scapy.all import sniff, wrpcap, get_if_list, Ether, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def check_scapy() -> None:
    """Verifica se Scapy está instalado."""
    if not SCAPY_AVAILABLE:
        raise ImportError(
            "Scapy não está instalado. Instale com: pip install scapy\n"
            "Nota: No Windows, pode ser necessário instalar Npcap: https://npcap.com/"
        )


def get_interfaces() -> List[str]:
    """Retorna lista de interfaces de rede disponíveis."""
    check_scapy()
    try:
        interfaces = get_if_list()
        return interfaces if interfaces else ["Nenhuma interface encontrada"]
    except Exception as e:
        return [f"Erro ao listar interfaces: {e}"]


def parse_packet(packet) -> Dict[str, str]:
    """Extrai informações relevantes de um pacote."""
    info = {
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "protocol": "Unknown",
        "src": "N/A",
        "dst": "N/A",
        "sport": "N/A",
        "dport": "N/A",
        "length": str(len(packet)),
    }

    # Camada Ethernet (MAC)
    if packet.haslayer(Ether):
        info["src_mac"] = packet[Ether].src
        info["dst_mac"] = packet[Ether].dst

    # Camada IP
    if packet.haslayer(IP):
        info["src"] = packet[IP].src
        info["dst"] = packet[IP].dst
        info["ttl"] = str(packet[IP].ttl)

    # Camada TCP
    if packet.haslayer(TCP):
        info["protocol"] = "TCP"
        info["sport"] = str(packet[TCP].sport)
        info["dport"] = str(packet[TCP].dport)
        info["flags"] = str(packet[TCP].flags)

    # Camada UDP
    elif packet.haslayer(UDP):
        info["protocol"] = "UDP"
        info["sport"] = str(packet[UDP].sport)
        info["dport"] = str(packet[UDP].dport)

    # Camada ICMP
    elif packet.haslayer(ICMP):
        info["protocol"] = "ICMP"
        info["icmp_type"] = str(packet[ICMP].type)
        info["icmp_code"] = str(packet[ICMP].code)

    return info


def format_packet_summary(packet_info: Dict[str, str]) -> str:
    """Formata resumo do pacote para exibição."""
    proto = packet_info.get("protocol", "Unknown")
    src = packet_info.get("src", "N/A")
    dst = packet_info.get("dst", "N/A")
    sport = packet_info.get("sport", "N/A")
    dport = packet_info.get("dport", "N/A")
    timestamp = packet_info.get("timestamp", "N/A")

    if proto in ["TCP", "UDP"]:
        return f"[{timestamp}] {proto:4} {src:15}:{sport:5} -> {dst:15}:{dport:5}"
    elif proto == "ICMP":
        icmp_type = packet_info.get("icmp_type", "N/A")
        return f"[{timestamp}] {proto:4} {src:15} -> {dst:15} (type={icmp_type})"
    else:
        return f"[{timestamp}] {proto:4} {src:15} -> {dst:15}"


def capture_packets(
    interface: Optional[str] = None,
    count: int = 10,
    protocol_filter: Optional[str] = None,
    timeout: Optional[int] = None,
    callback: Optional[Callable] = None,
    output_file: Optional[str] = None,
) -> List:
    """Captura pacotes de rede.

    Args:
        interface: Interface de rede (None = todas)
        count: Número de pacotes a capturar (0 = infinito)
        protocol_filter: Filtro BPF (ex: 'tcp', 'udp', 'icmp', 'tcp port 80')
        timeout: Timeout em segundos (None = sem limite)
        callback: Função a chamar para cada pacote capturado
        output_file: Caminho para exportar PCAP (None = não exportar)

    Returns:
        Lista de pacotes capturados
    """
    check_scapy()

    # Validar privilégios (necessário para captura raw)
    if os.name == 'nt':  # Windows
        # No Windows, verificação de privilégios é complexa, apenas avisar
        pass
    else:  # Linux/Unix
        if os.geteuid() != 0:
            print("Aviso: Pode ser necessário executar como root/admin para capturar pacotes.")

    try:
        # Se callback fornecido, exibir pacotes em tempo real
        # store=True para manter na memória mesmo com callback
        packets = sniff(
            iface=interface,
            count=count,
            filter=protocol_filter,
            timeout=timeout,
            prn=callback if callback else None,
            store=True,
        )

        # Exportar para PCAP se solicitado
        if output_file and packets:
            wrpcap(output_file, packets)
            print(f"\n{len(packets)} pacotes exportados para: {output_file}")

        return packets

    except PermissionError:
        raise PermissionError(
            "Permissão negada. Execute como administrador/root para capturar pacotes."
        )
    except Exception as e:
        raise RuntimeError(f"Erro ao capturar pacotes: {e}")
