"""Network Analyzer - Interface CLI (linha de comandos).

Uso:
    python -m network_analyzer.analyzer_cli --host google.com --mode ping --count 5
    python -m network_analyzer.analyzer_cli --host google.com --mode traceroute --graph
"""

import argparse
import sys

from .core import (
    ping,
    traceroute,
    generate_ping_graph,
    generate_traceroute_graph,
    PingResult,
    TracerouteHop,
    MATPLOTLIB_AVAILABLE,
)


def print_ping_result(result: PingResult) -> None:
    """Callback para exibir resultado de ping."""
    if result.success:
        print(f"[{result.seq:03d}] Resposta de {result.ip}: tempo={result.time_ms:.1f}ms TTL={result.ttl}")
    else:
        print(f"[{result.seq:03d}] {result.error or 'Timeout'}")


def print_traceroute_hop(hop: TracerouteHop) -> None:
    """Callback para exibir hop."""
    if hop.success:
        hostname = f" ({hop.hostname})" if hop.hostname else ""
        times_str = "  ".join(f"{t:.1f}ms" for t in hop.times_ms)
        print(f"{hop.hop:2d}  {hop.ip}{hostname}  {times_str}")
    else:
        print(f"{hop.hop:2d}  * * * Request timed out")


def main() -> None:
    """Entry point CLI."""
    parser = argparse.ArgumentParser(
        description="Network Analyzer - Ping/Traceroute avançado com gráficos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s --host google.com --mode ping
  %(prog)s --host 8.8.8.8 --mode ping --count 20 --graph
  %(prog)s --host cloudflare.com --mode traceroute --graph
  %(prog)s -H example.com -m traceroute --max-hops 20
        """
    )
    
    parser.add_argument(
        "-H", "--host",
        required=True,
        help="Host ou IP de destino"
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["ping", "traceroute"],
        default="ping",
        help="Modo de operação (default: ping)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=10,
        help="Número de pings (0=infinito, default: 10)"
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=1.0,
        help="Intervalo entre pings em segundos (default: 1.0)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="Timeout por request em segundos (default: 2.0)"
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=30,
        help="Número máximo de hops no traceroute (default: 30)"
    )
    parser.add_argument(
        "-g", "--graph",
        action="store_true",
        help="Gerar gráfico de latência após conclusão"
    )
    parser.add_argument(
        "-o", "--output",
        help="Ficheiro de saída para o gráfico (PNG)"
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Exibir gráfico interactivamente"
    )
    
    args = parser.parse_args()
    
    # Verificar matplotlib se gráfico requisitado
    if args.graph and not MATPLOTLIB_AVAILABLE:
        print("Aviso: matplotlib não instalado. Gráficos não serão gerados.")
        print("Instale com: pip install matplotlib")
        args.graph = False
    
    if args.mode == "traceroute":
        # TRACEROUTE
        print(f"{'='*60}")
        print(f"Traceroute para {args.host}")
        print(f"{'='*60}\n")
        
        try:
            result = traceroute(
                args.host,
                max_hops=args.max_hops,
                timeout=args.timeout,
                callback=print_traceroute_hop
            )
            
            print(f"\n{'='*60}")
            if result.reached:
                print(f"Destino {result.target} ({result.target_ip}) alcançado em {len(result.hops)} hops")
            else:
                print(f"Destino não alcançado após {len(result.hops)} hops")
            print(f"{'='*60}")
            
            # Gerar gráfico
            if args.graph and result.hops:
                output_file = args.output or f"traceroute_{args.host.replace('.', '_')}.png"
                generate_traceroute_graph(result, output_file=output_file, show=args.show)
                
        except ValueError as e:
            print(f"Erro: {e}", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\nTraceroute interrompido.")
            sys.exit(0)
    
    else:
        # PING
        print(f"{'='*60}")
        print(f"Ping para {args.host} ({'contínuo' if args.count == 0 else args.count})")
        print(f"{'='*60}\n")
        
        try:
            stats = ping(
                args.host,
                count=args.count,
                interval=args.interval,
                timeout=args.timeout,
                callback=print_ping_result
            )
            
            print(f"\n{'='*60}")
            print(f"Estatísticas de ping para {stats.host} ({stats.ip}):")
            print(f"  Pacotes: enviados={stats.packets_sent}, recebidos={stats.packets_received}, "
                  f"perdidos={stats.packets_sent - stats.packets_received} ({stats.packet_loss_pct:.1f}% perda)")
            if stats.packets_received > 0:
                print(f"  Tempos: mín={stats.min_ms:.1f}ms, máx={stats.max_ms:.1f}ms, "
                      f"média={stats.avg_ms:.1f}ms, jitter={stats.jitter_ms:.1f}ms")
            print(f"{'='*60}")
            
            # Gerar gráfico
            if args.graph and stats.packets_received > 0:
                output_file = args.output or f"ping_{args.host.replace('.', '_')}.png"
                generate_ping_graph(stats, output_file=output_file, show=args.show)
                
        except ValueError as e:
            print(f"Erro: {e}", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\nPing interrompido.")
            sys.exit(0)


if __name__ == "__main__":
    main()
