"""
Network Analyzer Pro - GUI Avançada.

Interface gráfica completa com abas para todos os módulos de análise.
Inclui visualização em tempo real, gráficos e relatórios.

Exemplo de uso:
    python -m network_analyzer.gui_pro
    
Ou:
    from network_analyzer.gui_pro import NetworkAnalyzerProGUI
    app = NetworkAnalyzerProGUI()
    app.run()
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
import json

# Matplotlib para gráficos
try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# Módulos do Network Analyzer
from . import modules
from .modules import (
    ping, traceroute, dns_analyzer, http_analyzer,
    network_info, port_scanner, whois_lookup,
    connection_monitor, bandwidth, arp_scanner, mtu_discovery
)


# =============================================================================
# CONSTANTES DE ESTILO
# =============================================================================

COLORS = {
    "bg": "#1e1e1e",
    "bg_light": "#252526",
    "bg_lighter": "#2d2d30",
    "fg": "#d4d4d4",
    "fg_dim": "#808080",
    "accent": "#007acc",
    "accent_hover": "#1c97ea",
    "success": "#4ec9b0",
    "warning": "#dcdcaa",
    "error": "#f14c4c",
    "border": "#3c3c3c",
}

FONTS = {
    "default": ("Segoe UI", 10),
    "title": ("Segoe UI", 14, "bold"),
    "subtitle": ("Segoe UI", 11, "bold"),
    "mono": ("Consolas", 10),
    "small": ("Segoe UI", 9),
}


# =============================================================================
# WIDGET BASE - FRAME DE MÓDULO
# =============================================================================

class ModuleFrame(ttk.Frame):
    """Frame base para cada módulo."""
    
    def __init__(self, parent, title: str, **kwargs):
        super().__init__(parent, **kwargs)
        self.title = title
        self.result_queue = queue.Queue()
        self.is_running = False
        
        self._setup_ui()
        self._start_queue_checker()
    
    def _setup_ui(self):
        """Configura a UI básica."""
        # Frame de input
        self.input_frame = ttk.Frame(self)
        self.input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Frame de resultado
        self.result_frame = ttk.Frame(self)
        self.result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Área de texto para output
        self.output = scrolledtext.ScrolledText(
            self.result_frame,
            wrap=tk.WORD,
            font=FONTS["mono"],
            bg=COLORS["bg_lighter"],
            fg=COLORS["fg"],
            insertbackground=COLORS["fg"],
            selectbackground=COLORS["accent"],
            height=15
        )
        self.output.pack(fill=tk.BOTH, expand=True)
    
    def _start_queue_checker(self):
        """Inicia verificação periódica da queue."""
        self._check_queue()
    
    def _check_queue(self):
        """Verifica mensagens na queue."""
        try:
            while True:
                msg = self.result_queue.get_nowait()
                self._process_message(msg)
        except queue.Empty:
            pass
        self.after(100, self._check_queue)
    
    def _process_message(self, msg: Dict[str, Any]):
        """Processa mensagem da queue."""
        if msg.get("type") == "output":
            self.append_output(msg.get("text", ""))
        elif msg.get("type") == "clear":
            self.clear_output()
        elif msg.get("type") == "done":
            self.is_running = False
    
    def append_output(self, text: str, tag: str = None):
        """Adiciona texto ao output."""
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
    
    def clear_output(self):
        """Limpa output."""
        self.output.delete("1.0", tk.END)
    
    def run_async(self, func, *args, **kwargs):
        """Executa função em thread separada."""
        if self.is_running:
            return
        
        self.is_running = True
        thread = threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True)
        thread.start()


# =============================================================================
# FRAME - PING
# =============================================================================

class PingFrame(ModuleFrame):
    """Frame para teste de Ping."""
    
    def __init__(self, parent):
        super().__init__(parent, "Ping")
        self._setup_ping_ui()
    
    def _setup_ping_ui(self):
        """Configura UI específica do ping."""
        # Host
        ttk.Label(self.input_frame, text="Host:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="google.com")
        self.host_entry = ttk.Entry(self.input_frame, textvariable=self.host_var, width=30)
        self.host_entry.pack(side=tk.LEFT, padx=5)
        
        # Count
        ttk.Label(self.input_frame, text="Count:").pack(side=tk.LEFT, padx=(10, 0))
        self.count_var = tk.StringVar(value="10")
        self.count_entry = ttk.Entry(self.input_frame, textvariable=self.count_var, width=5)
        self.count_entry.pack(side=tk.LEFT, padx=5)
        
        # Botão
        self.run_btn = ttk.Button(self.input_frame, text="▶ Ping", command=self._run_ping)
        self.run_btn.pack(side=tk.LEFT, padx=10)
    
    def _run_ping(self):
        """Executa ping."""
        host = self.host_var.get().strip()
        if not host:
            return
        
        try:
            count = int(self.count_var.get())
        except ValueError:
            count = 10
        
        self.clear_output()
        self.append_output(f"🔍 Ping para {host} ({count} pacotes)...\n")
        
        self.run_async(self._do_ping, host, count)
    
    def _do_ping(self, host: str, count: int):
        """Realiza ping em thread."""
        try:
            # Callback para cada ping
            def on_ping(result):
                if result.success:
                    msg = f"  [{result.seq}] {result.time_ms:.1f} ms (TTL={result.ttl})"
                else:
                    msg = f"  [{result.seq}] Timeout"
                self.result_queue.put({"type": "output", "text": msg})
            
            # Executar ping com callback
            stats = ping.ping(host, count=count, callback=on_ping)
            
            # Estatísticas
            self.result_queue.put({"type": "output", "text": f"\n📊 Estatísticas:"})
            self.result_queue.put({"type": "output", "text": f"   Enviados: {stats.packets_sent}, Recebidos: {stats.packets_received}"})
            self.result_queue.put({"type": "output", "text": f"   Perda: {stats.packet_loss_pct:.1f}%"})
            self.result_queue.put({"type": "output", "text": f"   Min/Avg/Max: {stats.min_ms:.1f}/{stats.avg_ms:.1f}/{stats.max_ms:.1f} ms"})
            self.result_queue.put({"type": "output", "text": f"   Jitter: {stats.jitter_ms:.2f} ms"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# FRAME - TRACEROUTE
# =============================================================================

class TracerouteFrame(ModuleFrame):
    """Frame para Traceroute."""
    
    def __init__(self, parent):
        super().__init__(parent, "Traceroute")
        self._setup_traceroute_ui()
    
    def _setup_traceroute_ui(self):
        """Configura UI."""
        ttk.Label(self.input_frame, text="Host:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="google.com")
        self.host_entry = ttk.Entry(self.input_frame, textvariable=self.host_var, width=30)
        self.host_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(self.input_frame, text="Max Hops:").pack(side=tk.LEFT, padx=(10, 0))
        self.hops_var = tk.StringVar(value="30")
        self.hops_entry = ttk.Entry(self.input_frame, textvariable=self.hops_var, width=5)
        self.hops_entry.pack(side=tk.LEFT, padx=5)
        
        self.run_btn = ttk.Button(self.input_frame, text="▶ Traceroute", command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=10)
    
    def _run(self):
        """Executa traceroute."""
        host = self.host_var.get().strip()
        if not host:
            return
        
        try:
            max_hops = int(self.hops_var.get())
        except ValueError:
            max_hops = 30
        
        self.clear_output()
        self.append_output(f"🛤️ Traceroute para {host}...\n")
        
        self.run_async(self._do_trace, host, max_hops)
    
    def _do_trace(self, host: str, max_hops: int):
        """Realiza traceroute em thread."""
        try:
            result = traceroute.traceroute(host, max_hops=max_hops)
            
            for hop in result.hops:
                if hop.ip:
                    hostname = f" ({hop.hostname})" if hop.hostname and hop.hostname != hop.ip else ""
                    times = "/".join([f"{t:.1f}" if t else "*" for t in hop.times])
                    msg = f"  {hop.hop:2d}  {hop.ip:15}{hostname}  {times} ms"
                else:
                    msg = f"  {hop.hop:2d}  * * *"
                self.result_queue.put({"type": "output", "text": msg})
            
            self.result_queue.put({"type": "output", "text": f"\n✅ Concluído em {result.total_time:.2f}s"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# FRAME - DNS
# =============================================================================

class DNSFrame(ModuleFrame):
    """Frame para análise DNS."""
    
    def __init__(self, parent):
        super().__init__(parent, "DNS")
        self._setup_dns_ui()
    
    def _setup_dns_ui(self):
        """Configura UI."""
        ttk.Label(self.input_frame, text="Domain:").pack(side=tk.LEFT)
        self.domain_var = tk.StringVar(value="google.com")
        self.domain_entry = ttk.Entry(self.input_frame, textvariable=self.domain_var, width=30)
        self.domain_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(self.input_frame, text="Type:").pack(side=tk.LEFT, padx=(10, 0))
        self.type_var = tk.StringVar(value="ALL")
        types = ["ALL", "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        self.type_combo = ttk.Combobox(self.input_frame, textvariable=self.type_var, values=types, width=8)
        self.type_combo.pack(side=tk.LEFT, padx=5)
        
        self.run_btn = ttk.Button(self.input_frame, text="▶ Lookup", command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=10)
    
    def _run(self):
        """Executa DNS lookup."""
        domain = self.domain_var.get().strip()
        if not domain:
            return
        
        record_type = self.type_var.get()
        
        self.clear_output()
        self.append_output(f"🔍 DNS Lookup: {domain} ({record_type})...\n")
        
        self.run_async(self._do_lookup, domain, record_type)
    
    def _do_lookup(self, domain: str, record_type: str):
        """Realiza lookup em thread."""
        try:
            dns = dns_analyzer.DNSAnalyzer()
            
            if record_type == "ALL":
                results = dns.lookup_all(domain)
                for rec_type, result in results.items():
                    if result.success and result.records:
                        self.result_queue.put({"type": "output", "text": f"\n📋 {rec_type}:"})
                        for rec in result.records:
                            self.result_queue.put({"type": "output", "text": f"   {rec.value}"})
            else:
                result = dns.lookup(domain, record_type)
                if result.success and result.records:
                    for rec in result.records:
                        self.result_queue.put({"type": "output", "text": f"   {rec.value}"})
                else:
                    msg = result.error if result.error else "Nenhum registro encontrado"
                    self.result_queue.put({"type": "output", "text": f"   {msg}"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# FRAME - PORT SCANNER
# =============================================================================

class PortScannerFrame(ModuleFrame):
    """Frame para port scanner."""
    
    def __init__(self, parent):
        super().__init__(parent, "Port Scanner")
        self._setup_ui()
    
    def _setup_ui(self):
        """Configura UI."""
        ttk.Label(self.input_frame, text="Host:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.host_entry = ttk.Entry(self.input_frame, textvariable=self.host_var, width=20)
        self.host_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(self.input_frame, text="Ports:").pack(side=tk.LEFT, padx=(10, 0))
        self.ports_var = tk.StringVar(value="1-1024")
        self.ports_entry = ttk.Entry(self.input_frame, textvariable=self.ports_var, width=15)
        self.ports_entry.pack(side=tk.LEFT, padx=5)
        
        self.run_btn = ttk.Button(self.input_frame, text="▶ Scan", command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=10)
    
    def _run(self):
        """Executa scan."""
        host = self.host_var.get().strip()
        ports_str = self.ports_var.get().strip()
        if not host:
            return
        
        self.clear_output()
        self.append_output(f"🔍 Scanning {host} ({ports_str})...\n")
        
        self.run_async(self._do_scan, host, ports_str)
    
    def _do_scan(self, host: str, ports_str: str):
        """Realiza scan em thread."""
        try:
            # Parse ports
            if "-" in ports_str:
                start, end = map(int, ports_str.split("-"))
                ports = range(start, end + 1)
            elif "," in ports_str:
                ports = [int(p) for p in ports_str.split(",")]
            else:
                ports = [int(ports_str)]
            
            scanner = port_scanner.PortScanner(timeout=1, threads=50)
            result = scanner.scan_range(host, list(ports))
            
            open_ports = [p for p in result.ports if p.is_open]
            
            if open_ports:
                self.result_queue.put({"type": "output", "text": f"🟢 Portas abertas ({len(open_ports)}):\n"})
                for p in open_ports:
                    service = p.service or "?"
                    banner = f" - {p.banner[:50]}" if p.banner else ""
                    self.result_queue.put({"type": "output", "text": f"   {p.port:5d}  {service:15}{banner}"})
            else:
                self.result_queue.put({"type": "output", "text": "   Nenhuma porta aberta encontrada"})
            
            self.result_queue.put({"type": "output", "text": f"\n⏱️ Tempo: {result.scan_time:.2f}s"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# FRAME - NETWORK INFO
# =============================================================================

class NetworkInfoFrame(ModuleFrame):
    """Frame para informações de rede."""
    
    def __init__(self, parent):
        super().__init__(parent, "Network Info")
        self._setup_ui()
    
    def _setup_ui(self):
        """Configura UI."""
        self.run_btn = ttk.Button(self.input_frame, text="🔄 Refresh", command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=5)
        
        # Auto-run
        self.after(100, self._run)
    
    def _run(self):
        """Obtém informações."""
        self.clear_output()
        self.append_output("🖥️ Informações de Rede\n" + "=" * 50 + "\n")
        
        self.run_async(self._do_get_info)
    
    def _do_get_info(self):
        """Obtém info em thread."""
        try:
            net_info = network_info.NetworkInfo()
            
            # IP público
            try:
                public_ip = net_info.get_public_ip()
                self.result_queue.put({"type": "output", "text": f"🌐 IP Público: {public_ip}"})
            except Exception:
                self.result_queue.put({"type": "output", "text": "🌐 IP Público: N/A"})
            
            # Gateway
            try:
                gateway = net_info.get_default_gateway()
                self.result_queue.put({"type": "output", "text": f"🚪 Gateway: {gateway}\n"})
            except Exception:
                self.result_queue.put({"type": "output", "text": "🚪 Gateway: N/A\n"})
            
            # Interfaces
            interfaces = net_info.get_interfaces()
            self.result_queue.put({"type": "output", "text": "📡 Interfaces:\n"})
            
            for iface in interfaces:
                self.result_queue.put({"type": "output", "text": f"   {iface.name}:"})
                if hasattr(iface, 'addresses'):
                    for addr in iface.addresses:
                        self.result_queue.put({"type": "output", "text": f"      {addr.family}: {addr.address}"})
                if hasattr(iface, 'mac') and iface.mac:
                    self.result_queue.put({"type": "output", "text": f"      MAC: {iface.mac}"})
                self.result_queue.put({"type": "output", "text": ""})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# FRAME - HTTP ANALYZER
# =============================================================================

class HTTPFrame(ModuleFrame):
    """Frame para análise HTTP."""
    
    def __init__(self, parent):
        super().__init__(parent, "HTTP")
        self._setup_ui()
    
    def _setup_ui(self):
        """Configura UI."""
        ttk.Label(self.input_frame, text="URL:").pack(side=tk.LEFT)
        self.url_var = tk.StringVar(value="https://google.com")
        self.url_entry = ttk.Entry(self.input_frame, textvariable=self.url_var, width=40)
        self.url_entry.pack(side=tk.LEFT, padx=5)
        
        self.run_btn = ttk.Button(self.input_frame, text="▶ Analyze", command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=10)
    
    def _run(self):
        """Executa análise."""
        url = self.url_var.get().strip()
        if not url:
            return
        
        self.clear_output()
        self.append_output(f"🌐 Analisando {url}...\n")
        
        self.run_async(self._do_analyze, url)
    
    def _do_analyze(self, url: str):
        """Analisa URL em thread."""
        try:
            http = http_analyzer.HTTPAnalyzer()
            result = http.analyze(url)
            
            self.result_queue.put({"type": "output", "text": f"📊 Status: {result.status_code}"})
            self.result_queue.put({"type": "output", "text": f"⏱️ Tempo: {result.response_time_ms/1000:.3f}s"})
            
            if hasattr(result, 'ssl_info') and result.ssl_info:
                self.result_queue.put({"type": "output", "text": f"\n🔒 SSL/TLS:"})
                self.result_queue.put({"type": "output", "text": f"   Issuer: {result.ssl_info.issuer}"})
                self.result_queue.put({"type": "output", "text": f"   Expira: {result.ssl_info.not_after}"})
            
            if hasattr(result, 'headers') and result.headers:
                self.result_queue.put({"type": "output", "text": f"\n📋 Headers:"})
                for header in result.headers[:10]:
                    self.result_queue.put({"type": "output", "text": f"   {header.name}: {str(header.value)[:60]}"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# FRAME - ARP SCANNER
# =============================================================================

class ARPFrame(ModuleFrame):
    """Frame para ARP scanner."""
    
    def __init__(self, parent):
        super().__init__(parent, "ARP Scanner")
        self._setup_ui()
    
    def _setup_ui(self):
        """Configura UI."""
        ttk.Label(self.input_frame, text="Network:").pack(side=tk.LEFT)
        self.net_var = tk.StringVar(value="192.168.1.0/24")
        self.net_entry = ttk.Entry(self.input_frame, textvariable=self.net_var, width=20)
        self.net_entry.pack(side=tk.LEFT, padx=5)
        
        self.run_btn = ttk.Button(self.input_frame, text="▶ Scan", command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=10)
        
        self.arp_btn = ttk.Button(self.input_frame, text="📋 ARP Table", command=self._show_arp)
        self.arp_btn.pack(side=tk.LEFT)
    
    def _show_arp(self):
        """Mostra tabela ARP."""
        self.clear_output()
        self.append_output("📋 Tabela ARP Local\n" + "=" * 50 + "\n")
        
        try:
            scanner = arp_scanner.ARPScanner()
            hosts = scanner.get_local_arp()
            
            for host in hosts:
                vendor = f"({host.vendor})" if host.vendor != "Unknown" else ""
                self.append_output(f"   {host.ip:15} {host.mac:17} {vendor}")
                
        except Exception as e:
            self.append_output(f"❌ Erro: {e}")
    
    def _run(self):
        """Executa scan."""
        network = self.net_var.get().strip()
        if not network:
            return
        
        self.clear_output()
        self.append_output(f"🔍 Scanning {network}...\n")
        
        self.run_async(self._do_scan, network)
    
    def _do_scan(self, network: str):
        """Realiza scan em thread."""
        try:
            scanner = arp_scanner.ARPScanner(timeout=0.5, threads=100)
            
            def progress(ip, found, pct):
                if int(pct * 100) % 10 == 0:
                    self.result_queue.put({"type": "output", "text": f"   Progresso: {pct*100:.0f}%"})
            
            result = scanner.scan(network, callback=progress)
            
            self.result_queue.put({"type": "output", "text": f"\n🟢 Hosts encontrados ({result.hosts_found}):\n"})
            
            for host in result.hosts:
                mac = host.mac if host.mac else "N/A"
                vendor = f"({host.vendor})" if host.vendor and host.vendor != "Unknown" else ""
                self.result_queue.put({"type": "output", "text": f"   {host.ip:15} {mac:17} {vendor}"})
            
            self.result_queue.put({"type": "output", "text": f"\n⏱️ Tempo: {result.scan_time:.2f}s"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# FRAME - WHOIS
# =============================================================================

class WhoisFrame(ModuleFrame):
    """Frame para WHOIS lookup."""
    
    def __init__(self, parent):
        super().__init__(parent, "WHOIS")
        self._setup_ui()
    
    def _setup_ui(self):
        """Configura UI."""
        ttk.Label(self.input_frame, text="Domain/IP:").pack(side=tk.LEFT)
        self.query_var = tk.StringVar(value="google.com")
        self.query_entry = ttk.Entry(self.input_frame, textvariable=self.query_var, width=30)
        self.query_entry.pack(side=tk.LEFT, padx=5)
        
        self.run_btn = ttk.Button(self.input_frame, text="▶ Lookup", command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=10)
    
    def _run(self):
        """Executa lookup."""
        query = self.query_var.get().strip()
        if not query:
            return
        
        self.clear_output()
        self.append_output(f"🔍 WHOIS: {query}...\n")
        
        self.run_async(self._do_lookup, query)
    
    def _do_lookup(self, query: str):
        """Realiza lookup em thread."""
        try:
            whois = whois_lookup.WhoisLookup()
            
            # Detectar se é IP ou domínio
            if query.replace(".", "").isdigit():
                result = whois.lookup_ip(query)
            else:
                result = whois.lookup_domain(query)
            
            if result.success:
                self.result_queue.put({"type": "output", "text": f"📋 Resultado:\n"})
                self.result_queue.put({"type": "output", "text": result.raw_data[:2000]})
            else:
                error = result.error if hasattr(result, 'error') else "Erro desconhecido"
                self.result_queue.put({"type": "output", "text": f"❌ Erro: {error}"})
            
            # Geolocalização para IPs
            if query.replace(".", "").isdigit():
                geo = whois.geolocate(query)
                if geo and geo.success:
                    self.result_queue.put({"type": "output", "text": f"\n🌍 Geolocalização:"})
                    self.result_queue.put({"type": "output", "text": f"   País: {geo.country}"})
                    self.result_queue.put({"type": "output", "text": f"   Cidade: {geo.city}"})
                    if hasattr(geo, 'isp'):
                        self.result_queue.put({"type": "output", "text": f"   ISP: {geo.isp}"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# FRAME - CONNECTIONS
# =============================================================================

class ConnectionsFrame(ModuleFrame):
    """Frame para monitor de conexões."""
    
    def __init__(self, parent):
        super().__init__(parent, "Connections")
        self._setup_ui()
    
    def _setup_ui(self):
        """Configura UI."""
        self.run_btn = ttk.Button(self.input_frame, text="🔄 Refresh", command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(self.input_frame, text="Filter:").pack(side=tk.LEFT, padx=(10, 0))
        self.filter_var = tk.StringVar(value="established")
        filters = ["all", "established", "listen", "time_wait"]
        self.filter_combo = ttk.Combobox(self.input_frame, textvariable=self.filter_var, values=filters, width=12)
        self.filter_combo.pack(side=tk.LEFT, padx=5)
        
        # Auto-run
        self.after(100, self._run)
    
    def _run(self):
        """Obtém conexões."""
        self.clear_output()
        self.append_output("🔌 Conexões Ativas\n" + "=" * 50 + "\n")
        
        self.run_async(self._do_get)
    
    def _do_get(self):
        """Obtém conexões em thread."""
        try:
            filter_state = self.filter_var.get()
            state = None if filter_state == "all" else filter_state
            
            monitor = connection_monitor.ConnectionMonitor()
            connections = monitor.get_connections(state=state)
            
            # Agrupar por processo
            by_process = {}
            for conn in connections[:100]:  # Limitar
                pid = conn.pid or 0
                if pid not in by_process:
                    by_process[pid] = []
                by_process[pid].append(conn)
            
            for pid, conns in list(by_process.items())[:20]:
                process = conns[0].process if hasattr(conns[0], 'process') else "Unknown"
                self.result_queue.put({"type": "output", "text": f"\n📦 {process} (PID: {pid})"})
                
                for conn in conns[:5]:
                    local = f"{conn.local_address}:{conn.local_port}"
                    remote = f"{conn.remote_address}:{conn.remote_port}" if conn.remote_address else ""
                    conn_type = conn.type if hasattr(conn, 'type') else "?"
                    status = conn.status if hasattr(conn, 'status') else ""
                    self.result_queue.put({"type": "output", "text": f"   {conn_type:4} {local:25} → {remote:25} {status}"})
            
            stats = monitor.get_stats()
            self.result_queue.put({"type": "output", "text": f"\n📊 Total: {stats.total} | TCP: {stats.tcp} | UDP: {stats.udp}"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# FRAME - BANDWIDTH
# =============================================================================

class BandwidthFrame(ModuleFrame):
    """Frame para teste de velocidade."""
    
    def __init__(self, parent):
        super().__init__(parent, "Bandwidth")
        self._setup_ui()
    
    def _setup_ui(self):
        """Configura UI."""
        self.run_btn = ttk.Button(self.input_frame, text="▶ Speed Test", command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=5)
        
        self.quick_btn = ttk.Button(self.input_frame, text="⚡ Quick Test", command=self._quick)
        self.quick_btn.pack(side=tk.LEFT, padx=5)
    
    def _quick(self):
        """Teste rápido."""
        self.clear_output()
        self.append_output("⚡ Teste rápido de velocidade...\n")
        
        self.run_async(self._do_quick)
    
    def _do_quick(self):
        """Teste rápido em thread."""
        try:
            bw = bandwidth.BandwidthTest(timeout=10)
            result = bw.quick_test()
            
            self.result_queue.put({"type": "output", "text": f"📥 Download: {result['download']}"})
            self.result_queue.put({"type": "output", "text": f"📶 Ping: {result['ping']}"})
            self.result_queue.put({"type": "output", "text": f"📊 Jitter: {result['jitter']}"})
            self.result_queue.put({"type": "output", "text": f"🌐 IP: {result['client_ip']}"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})
    
    def _run(self):
        """Teste completo."""
        self.clear_output()
        self.append_output("🚀 Teste completo de velocidade...\n")
        
        self.run_async(self._do_full)
    
    def _do_full(self):
        """Teste completo em thread."""
        try:
            bw = bandwidth.BandwidthTest(timeout=15)
            
            # Latência
            self.result_queue.put({"type": "output", "text": "📶 Testando latência..."})
            latency = bw.test_latency()
            if "error" not in latency:
                self.result_queue.put({"type": "output", "text": f"   Ping: {latency['avg']:.1f} ms"})
                self.result_queue.put({"type": "output", "text": f"   Jitter: {latency['jitter']:.1f} ms"})
            
            # Download
            self.result_queue.put({"type": "output", "text": "\n📥 Testando download..."})
            dl = bw.test_download()
            if dl.success:
                self.result_queue.put({"type": "output", "text": f"   Velocidade: {dl.speed_human}"})
                self.result_queue.put({"type": "output", "text": f"   Transferido: {dl.bytes_transferred/1e6:.1f} MB"})
            else:
                self.result_queue.put({"type": "output", "text": f"   Erro: {dl.error}"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# FRAME - MTU
# =============================================================================

class MTUFrame(ModuleFrame):
    """Frame para MTU discovery."""
    
    def __init__(self, parent):
        super().__init__(parent, "MTU Discovery")
        self._setup_ui()
    
    def _setup_ui(self):
        """Configura UI."""
        ttk.Label(self.input_frame, text="Host:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="8.8.8.8")
        self.host_entry = ttk.Entry(self.input_frame, textvariable=self.host_var, width=20)
        self.host_entry.pack(side=tk.LEFT, padx=5)
        
        self.run_btn = ttk.Button(self.input_frame, text="▶ Discover", command=self._run)
        self.run_btn.pack(side=tk.LEFT, padx=10)
        
        self.iface_btn = ttk.Button(self.input_frame, text="📋 Local MTU", command=self._show_local)
        self.iface_btn.pack(side=tk.LEFT)
    
    def _show_local(self):
        """Mostra MTU local."""
        self.clear_output()
        self.append_output("📋 MTU das Interfaces Locais\n" + "=" * 50 + "\n")
        
        try:
            mtu = mtu_discovery.MTUDiscovery()
            interfaces = mtu.get_interface_mtu()
            
            for iface, mtu_val in interfaces.items():
                desc = mtu_discovery.MTU_VALUES.get(mtu_val, "")
                self.append_output(f"   {iface}: {mtu_val} bytes {desc}")
                
        except Exception as e:
            self.append_output(f"❌ Erro: {e}")
    
    def _run(self):
        """Executa discovery."""
        host = self.host_var.get().strip()
        if not host:
            return
        
        self.clear_output()
        self.append_output(f"🔍 Descobrindo Path MTU para {host}...\n")
        
        self.run_async(self._do_discover, host)
    
    def _do_discover(self, host: str):
        """Descoberta em thread."""
        try:
            mtu = mtu_discovery.MTUDiscovery(timeout=2)
            
            def on_test(test_mtu, ok, pct):
                status = "✓" if ok else "✗"
                self.result_queue.put({"type": "output", "text": f"   MTU {test_mtu}: {status}"})
            
            result = mtu.discover(host, callback=on_test)
            
            if result.success:
                self.result_queue.put({"type": "output", "text": f"\n🎯 Path MTU: {result.mtu} bytes"})
                self.result_queue.put({"type": "output", "text": f"   Descrição: {result.mtu_description}"})
                self.result_queue.put({"type": "output", "text": f"   ICMP Payload: {result.icmp_payload} bytes"})
                self.result_queue.put({"type": "output", "text": f"   Tempo: {result.discovery_time:.2f}s"})
            else:
                self.result_queue.put({"type": "output", "text": f"❌ Erro: {result.error}"})
            
        except Exception as e:
            self.result_queue.put({"type": "output", "text": f"❌ Erro: {e}"})
        finally:
            self.result_queue.put({"type": "done"})


# =============================================================================
# APLICAÇÃO PRINCIPAL
# =============================================================================

class NetworkAnalyzerProGUI:
    """
    GUI principal do Network Analyzer Pro.
    
    Janela com abas para todos os módulos de análise.
    """
    
    def __init__(self):
        """Inicializa a aplicação."""
        self.root = tk.Tk()
        self.root.title("Network Analyzer Pro v2.0")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Configurar estilo
        self._setup_style()
        
        # Configurar UI
        self._setup_ui()
    
    def _setup_style(self):
        """Configura estilo dark mode."""
        style = ttk.Style()
        
        self.root.configure(bg=COLORS["bg"])
        
        # Configurar tema
        style.configure(".", 
            background=COLORS["bg"],
            foreground=COLORS["fg"],
            font=FONTS["default"]
        )
        
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["fg"])
        style.configure("TButton", padding=5)
        style.configure("TEntry", fieldbackground=COLORS["bg_lighter"])
        style.configure("TCombobox", fieldbackground=COLORS["bg_lighter"])
        
        style.configure("TNotebook", background=COLORS["bg"])
        style.configure("TNotebook.Tab", padding=[10, 5])
    
    def _setup_ui(self):
        """Configura interface."""
        # Header
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, padx=10, pady=5)
        
        title = ttk.Label(header, text="🔍 Network Analyzer Pro", font=FONTS["title"])
        title.pack(side=tk.LEFT)
        
        version = ttk.Label(header, text="v2.0", font=FONTS["small"], foreground=COLORS["fg_dim"])
        version.pack(side=tk.LEFT, padx=10)
        
        # Notebook (abas)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Adicionar abas
        self._add_tab(PingFrame, "🏓 Ping")
        self._add_tab(TracerouteFrame, "🛤️ Traceroute")
        self._add_tab(DNSFrame, "📋 DNS")
        self._add_tab(PortScannerFrame, "🔍 Ports")
        self._add_tab(NetworkInfoFrame, "🖥️ Info")
        self._add_tab(HTTPFrame, "🌐 HTTP")
        self._add_tab(ARPFrame, "📡 ARP")
        self._add_tab(WhoisFrame, "📝 WHOIS")
        self._add_tab(ConnectionsFrame, "🔌 Conn")
        self._add_tab(BandwidthFrame, "⚡ Speed")
        self._add_tab(MTUFrame, "📏 MTU")
        
        # Status bar
        self.status = ttk.Label(self.root, text="Ready", foreground=COLORS["fg_dim"])
        self.status.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
    
    def _add_tab(self, frame_class, title: str):
        """Adiciona uma aba."""
        frame = frame_class(self.notebook)
        self.notebook.add(frame, text=title)
    
    def run(self):
        """Inicia a aplicação."""
        self.root.mainloop()


def main():
    """Ponto de entrada."""
    app = NetworkAnalyzerProGUI()
    app.run()


if __name__ == "__main__":
    main()
