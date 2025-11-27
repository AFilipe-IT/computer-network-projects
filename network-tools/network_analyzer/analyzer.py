"""Network Analyzer - Modo interativo.

Ping/Traceroute avançado com gráficos de desempenho.
"""

import sys

from .core import (
    ping,
    ping_once,
    traceroute,
    generate_ping_graph,
    generate_traceroute_graph,
    PingResult,
    PingStats,
    TracerouteHop,
    TracerouteResult,
    MATPLOTLIB_AVAILABLE,
)


def print_ping_result(result: PingResult) -> None:
    """Callback para exibir resultado de ping em tempo real."""
    if result.success:
        print(f"[{result.seq:03d}] Resposta de {result.ip}: tempo={result.time_ms:.1f}ms TTL={result.ttl}")
    else:
        print(f"[{result.seq:03d}] {result.error or 'Timeout'}")


def print_traceroute_hop(hop: TracerouteHop) -> None:
    """Callback para exibir hop em tempo real."""
    if hop.success:
        hostname = f" ({hop.hostname})" if hop.hostname else ""
        times_str = "  ".join(f"{t:.1f}ms" for t in hop.times_ms)
        print(f"{hop.hop:2d}  {hop.ip}{hostname}  {times_str}")
    else:
        print(f"{hop.hop:2d}  * * * Request timed out")


def interactive_mode() -> None:
    """Modo interativo: solicita configuração via prompts."""
    print("=== Network Analyzer (Ping/Traceroute avançado) ===\n")
    
    # Host
    host = input("Host/IP alvo: ").strip()
    if not host:
        print("Host obrigatório. Saindo.")
        sys.exit(1)
    
    # Modo
    print("\nModos disponíveis:")
    print("  1. Ping (medir latência)")
    print("  2. Traceroute (traçar rota)")
    mode = input("\nEscolha o modo (1 ou 2): ").strip()
    
    if mode == "2":
        # TRACEROUTE
        print(f"\n{'='*60}")
        print(f"Traceroute para {host}")
        print(f"{'='*60}\n")
        
        try:
            result = traceroute(host, callback=print_traceroute_hop)
            
            print(f"\n{'='*60}")
            if result.reached:
                print(f"Destino {result.target} ({result.target_ip}) alcançado em {len(result.hops)} hops")
            else:
                print(f"Destino não alcançado após {len(result.hops)} hops")
            
            # Gráfico?
            if MATPLOTLIB_AVAILABLE and result.hops:
                gen_graph = input("\nGerar gráfico de latência por hop? (s/N): ").strip().lower()
                if gen_graph in ["s", "sim", "y", "yes"]:
                    filename = f"traceroute_{host.replace('.', '_')}.png"
                    generate_traceroute_graph(result, output_file=filename)
            elif not MATPLOTLIB_AVAILABLE:
                print("\n(Matplotlib não instalado - gráficos não disponíveis)")
                
        except ValueError as e:
            print(f"Erro: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\nTraceroute interrompido.")
    
    else:
        # PING
        count_input = input("\nNúmero de pings (Enter para 10, 0 para contínuo): ").strip()
        try:
            count = int(count_input) if count_input else 10
        except ValueError:
            count = 10
        
        print(f"\n{'='*60}")
        print(f"Ping para {host} ({count if count > 0 else 'contínuo'})")
        print(f"{'='*60}\n")
        
        try:
            stats = ping(host, count=count, callback=print_ping_result)
            
            # Estatísticas
            print(f"\n{'='*60}")
            print(f"Estatísticas de ping para {stats.host} ({stats.ip}):")
            print(f"  Pacotes: enviados={stats.packets_sent}, recebidos={stats.packets_received}, "
                  f"perdidos={stats.packets_sent - stats.packets_received} ({stats.packet_loss_pct:.1f}% perda)")
            if stats.packets_received > 0:
                print(f"  Tempos: mín={stats.min_ms:.1f}ms, máx={stats.max_ms:.1f}ms, "
                      f"média={stats.avg_ms:.1f}ms, jitter={stats.jitter_ms:.1f}ms")
            print(f"{'='*60}")
            
            # Gráfico?
            if MATPLOTLIB_AVAILABLE and stats.packets_received > 0:
                gen_graph = input("\nGerar gráfico de latência? (s/N): ").strip().lower()
                if gen_graph in ["s", "sim", "y", "yes"]:
                    filename = f"ping_{host.replace('.', '_')}.png"
                    generate_ping_graph(stats, output_file=filename)
            elif not MATPLOTLIB_AVAILABLE:
                print("\n(Matplotlib não instalado - gráficos não disponíveis)")
                
        except ValueError as e:
            print(f"Erro: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\nPing interrompido.")


if __name__ == "__main__":
    interactive_mode()
