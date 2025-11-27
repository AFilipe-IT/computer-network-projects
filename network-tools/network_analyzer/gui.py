"""Network Analyzer - Interface Gráfica (GUI).

Interface visual para diagnóstico de rede em tempo real.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
from datetime import datetime
from typing import Optional

# Tentar importar matplotlib para gráficos embebidos
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import matplotlib.animation as animation
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from .core import (
    ping_once,
    traceroute,
    resolve_host,
    PingResult,
    TracerouteHop,
)


class NetworkAnalyzerGUI:
    """Interface gráfica principal do Network Analyzer."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Analyzer - Diagnóstico de Rede")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Estado
        self.is_running = False
        self.ping_thread: Optional[threading.Thread] = None
        self.results_queue = queue.Queue()
        self.ping_results: list[PingResult] = []
        self.traceroute_hops: list[TracerouteHop] = []
        
        # Configurar estilo
        self._setup_style()
        
        # Criar interface
        self._create_widgets()
        
        # Iniciar loop de actualização
        self._update_loop()
    
    def _setup_style(self):
        """Configurar estilos visuais."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Cores
        self.colors = {
            'bg': '#1e1e1e',
            'fg': '#ffffff',
            'accent': '#007acc',
            'success': '#4ec9b0',
            'error': '#f14c4c',
            'warning': '#dcdcaa',
            'grid': '#333333',
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TButton', padding=10)
        style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'))
        style.configure('Stats.TLabel', font=('Consolas', 11))
    
    def _create_widgets(self):
        """Criar todos os widgets da interface."""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # === HEADER ===
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="🌐 Network Analyzer", style='Header.TLabel').pack(side=tk.LEFT)
        
        # === CONTROLES ===
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        # Host
        ttk.Label(control_frame, text="Host/IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.host_entry = ttk.Entry(control_frame, width=30, font=('Consolas', 11))
        self.host_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.host_entry.insert(0, "google.com")
        self.host_entry.bind('<Return>', lambda e: self._start_analysis())
        
        # Modo
        ttk.Label(control_frame, text="Modo:").pack(side=tk.LEFT, padx=(0, 5))
        self.mode_var = tk.StringVar(value="ping")
        mode_combo = ttk.Combobox(control_frame, textvariable=self.mode_var, 
                                   values=["ping", "traceroute"], state="readonly", width=12)
        mode_combo.pack(side=tk.LEFT, padx=(0, 10))
        
        # Botões
        self.start_btn = ttk.Button(control_frame, text="▶ Iniciar", command=self._start_analysis)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="⏹ Parar", command=self._stop_analysis, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(control_frame, text="🗑 Limpar", command=self._clear_results)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # === ÁREA PRINCIPAL (gráfico + resultados) ===
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Painel esquerdo: Gráfico
        graph_frame = ttk.Frame(paned)
        paned.add(graph_frame, weight=2)
        
        if MATPLOTLIB_AVAILABLE:
            self._create_graph(graph_frame)
        else:
            ttk.Label(graph_frame, text="Matplotlib não instalado.\nInstale com: pip install matplotlib",
                     font=('Consolas', 12)).pack(expand=True)
        
        # Painel direito: Log de resultados
        log_frame = ttk.Frame(paned)
        paned.add(log_frame, weight=1)
        
        ttk.Label(log_frame, text="📋 Resultados", style='Header.TLabel').pack(anchor=tk.W)
        
        # Treeview para resultados
        columns = ('seq', 'ip', 'time', 'ttl', 'status')
        self.results_tree = ttk.Treeview(log_frame, columns=columns, show='headings', height=15)
        self.results_tree.heading('seq', text='#')
        self.results_tree.heading('ip', text='IP')
        self.results_tree.heading('time', text='Tempo')
        self.results_tree.heading('ttl', text='TTL')
        self.results_tree.heading('status', text='Estado')
        
        self.results_tree.column('seq', width=40, anchor=tk.CENTER)
        self.results_tree.column('ip', width=120)
        self.results_tree.column('time', width=80, anchor=tk.CENTER)
        self.results_tree.column('ttl', width=50, anchor=tk.CENTER)
        self.results_tree.column('status', width=80, anchor=tk.CENTER)
        
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # === ESTATÍSTICAS ===
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.stats_labels = {}
        stats = [
            ('host', 'Host: -'),
            ('ip', 'IP: -'),
            ('sent', 'Enviados: 0'),
            ('received', 'Recebidos: 0'),
            ('loss', 'Perda: 0%'),
            ('min', 'Mín: -'),
            ('max', 'Máx: -'),
            ('avg', 'Média: -'),
            ('jitter', 'Jitter: -'),
        ]
        
        for key, text in stats:
            label = ttk.Label(stats_frame, text=text, style='Stats.TLabel')
            label.pack(side=tk.LEFT, padx=10)
            self.stats_labels[key] = label
        
        # === STATUS BAR ===
        self.status_var = tk.StringVar(value="Pronto")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
    
    def _create_graph(self, parent):
        """Criar gráfico matplotlib embebido."""
        self.fig = Figure(figsize=(6, 4), dpi=100, facecolor=self.colors['bg'])
        self.ax = self.fig.add_subplot(111)
        self._setup_graph_style()
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Dados do gráfico
        self.graph_times: list[float] = []
        self.graph_seq: list[int] = []
    
    def _setup_graph_style(self):
        """Configurar estilo do gráfico (tema escuro)."""
        self.ax.set_facecolor(self.colors['bg'])
        self.ax.tick_params(colors=self.colors['fg'])
        self.ax.xaxis.label.set_color(self.colors['fg'])
        self.ax.yaxis.label.set_color(self.colors['fg'])
        self.ax.title.set_color(self.colors['fg'])
        for spine in self.ax.spines.values():
            spine.set_color(self.colors['grid'])
        self.ax.grid(True, alpha=0.3, color=self.colors['grid'])
        self.ax.set_xlabel('Sequência')
        self.ax.set_ylabel('Latência (ms)')
        self.ax.set_title('Latência em Tempo Real')
    
    def _update_graph(self):
        """Actualizar gráfico com novos dados."""
        if not MATPLOTLIB_AVAILABLE or not self.graph_times:
            return
        
        self.ax.clear()
        self._setup_graph_style()
        
        # Plotar linha de latência
        self.ax.plot(self.graph_seq, self.graph_times, 'o-', 
                    color=self.colors['accent'], linewidth=2, markersize=6)
        
        # Linha média
        if self.graph_times:
            avg = sum(self.graph_times) / len(self.graph_times)
            self.ax.axhline(y=avg, color=self.colors['success'], linestyle='--', 
                          linewidth=1, label=f'Média: {avg:.1f}ms')
            self.ax.legend(loc='upper right', facecolor=self.colors['bg'], 
                          labelcolor=self.colors['fg'])
        
        # Limites
        if self.graph_times:
            max_time = max(self.graph_times)
            self.ax.set_ylim(0, max_time * 1.3 if max_time > 0 else 100)
        
        self.canvas.draw()
    
    def _update_traceroute_graph(self):
        """Actualizar gráfico para modo traceroute."""
        if not MATPLOTLIB_AVAILABLE or not self.traceroute_hops:
            return
        
        self.ax.clear()
        self._setup_graph_style()
        self.ax.set_xlabel('Hop')
        self.ax.set_ylabel('Latência (ms)')
        self.ax.set_title('Traceroute - Latência por Hop')
        
        hops = []
        times = []
        labels = []
        
        for hop in self.traceroute_hops:
            if hop.success and hop.times_ms:
                hops.append(hop.hop)
                times.append(hop.avg_ms)
                label = hop.ip[:15] if hop.ip else '*'
                labels.append(f"{hop.hop}: {label}")
        
        if hops:
            bars = self.ax.bar(hops, times, color=self.colors['accent'], edgecolor=self.colors['fg'])
            self.ax.set_xticks(hops)
            
            # Valores nas barras
            for bar, t in zip(bars, times):
                self.ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                           f'{t:.0f}', ha='center', va='bottom', 
                           color=self.colors['fg'], fontsize=8)
        
        self.canvas.draw()
    
    def _start_analysis(self):
        """Iniciar análise de rede."""
        host = self.host_entry.get().strip()
        if not host:
            messagebox.showerror("Erro", "Introduza um host/IP válido")
            return
        
        # Resolver host primeiro
        try:
            ip = resolve_host(host)
            self.stats_labels['host'].config(text=f"Host: {host}")
            self.stats_labels['ip'].config(text=f"IP: {ip}")
        except ValueError as e:
            messagebox.showerror("Erro", str(e))
            return
        
        self.is_running = True
        self._clear_results()
        
        # Actualizar UI
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.host_entry.config(state=tk.DISABLED)
        
        mode = self.mode_var.get()
        
        if mode == "ping":
            self.status_var.set(f"A fazer ping a {host}...")
            self.ping_thread = threading.Thread(target=self._ping_worker, args=(host,), daemon=True)
        else:
            self.status_var.set(f"Traceroute para {host}...")
            self.ping_thread = threading.Thread(target=self._traceroute_worker, args=(host,), daemon=True)
        
        self.ping_thread.start()
    
    def _ping_worker(self, host: str):
        """Worker thread para ping contínuo."""
        seq = 0
        while self.is_running:
            seq += 1
            result = ping_once(host, seq)
            self.results_queue.put(('ping', result))
            
            # Esperar 1 segundo entre pings
            if self.is_running:
                import time
                time.sleep(1)
    
    def _traceroute_worker(self, host: str):
        """Worker thread para traceroute."""
        def hop_callback(hop: TracerouteHop):
            self.results_queue.put(('traceroute', hop))
        
        try:
            result = traceroute(host, callback=hop_callback)
            self.results_queue.put(('traceroute_done', result))
        except Exception as e:
            self.results_queue.put(('error', str(e)))
    
    def _stop_analysis(self):
        """Parar análise."""
        self.is_running = False
        self.status_var.set("Parado")
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.host_entry.config(state=tk.NORMAL)
    
    def _clear_results(self):
        """Limpar resultados."""
        self.ping_results.clear()
        self.traceroute_hops.clear()
        self.graph_times.clear()
        self.graph_seq.clear()
        
        # Limpar treeview
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Limpar gráfico
        if MATPLOTLIB_AVAILABLE:
            self.ax.clear()
            self._setup_graph_style()
            self.canvas.draw()
        
        # Reset estatísticas
        for key in ['sent', 'received', 'loss', 'min', 'max', 'avg', 'jitter']:
            if key in ['sent', 'received']:
                self.stats_labels[key].config(text=f"{key.capitalize()}: 0")
            elif key == 'loss':
                self.stats_labels[key].config(text="Perda: 0%")
            else:
                self.stats_labels[key].config(text=f"{key.capitalize()}: -")
    
    def _update_loop(self):
        """Loop de actualização da interface (polling da queue)."""
        try:
            while True:
                msg_type, data = self.results_queue.get_nowait()
                
                if msg_type == 'ping':
                    self._handle_ping_result(data)
                elif msg_type == 'traceroute':
                    self._handle_traceroute_hop(data)
                elif msg_type == 'traceroute_done':
                    self._handle_traceroute_done(data)
                elif msg_type == 'error':
                    messagebox.showerror("Erro", data)
                    self._stop_analysis()
                    
        except queue.Empty:
            pass
        
        # Reagendar
        self.root.after(100, self._update_loop)
    
    def _handle_ping_result(self, result: PingResult):
        """Processar resultado de ping."""
        self.ping_results.append(result)
        
        # Adicionar à treeview
        status = "✓ OK" if result.success else "✗ Falha"
        time_str = f"{result.time_ms:.1f}ms" if result.success else "-"
        ttl_str = str(result.ttl) if result.success and result.ttl > 0 else "-"
        
        self.results_tree.insert('', 'end', values=(
            result.seq, result.ip, time_str, ttl_str, status
        ))
        
        # Scroll para o fim
        self.results_tree.yview_moveto(1)
        
        # Actualizar gráfico
        if result.success:
            self.graph_seq.append(result.seq)
            self.graph_times.append(result.time_ms)
            self._update_graph()
        
        # Actualizar estatísticas
        self._update_ping_stats()
    
    def _handle_traceroute_hop(self, hop: TracerouteHop):
        """Processar hop do traceroute."""
        self.traceroute_hops.append(hop)
        
        # Adicionar à treeview
        if hop.success:
            time_str = f"{hop.avg_ms:.1f}ms"
            status = "✓ OK"
        else:
            time_str = "-"
            status = "* Timeout"
        
        ip_str = hop.ip or "*"
        if hop.hostname and hop.hostname != hop.ip:
            ip_str = f"{hop.ip} ({hop.hostname[:20]})"
        
        self.results_tree.insert('', 'end', values=(
            hop.hop, ip_str, time_str, "-", status
        ))
        
        self.results_tree.yview_moveto(1)
        
        # Actualizar gráfico
        self._update_traceroute_graph()
        
        # Actualizar status
        self.status_var.set(f"Traceroute: hop {hop.hop}...")
    
    def _handle_traceroute_done(self, result):
        """Traceroute completo."""
        self._stop_analysis()
        
        if result.reached:
            self.status_var.set(f"✓ Destino alcançado em {len(result.hops)} hops")
        else:
            self.status_var.set(f"✗ Destino não alcançado após {len(result.hops)} hops")
    
    def _update_ping_stats(self):
        """Actualizar estatísticas de ping."""
        sent = len(self.ping_results)
        received = sum(1 for r in self.ping_results if r.success)
        loss = ((sent - received) / sent * 100) if sent > 0 else 0
        
        self.stats_labels['sent'].config(text=f"Enviados: {sent}")
        self.stats_labels['received'].config(text=f"Recebidos: {received}")
        self.stats_labels['loss'].config(text=f"Perda: {loss:.1f}%")
        
        success_times = [r.time_ms for r in self.ping_results if r.success]
        if success_times:
            import statistics
            min_t = min(success_times)
            max_t = max(success_times)
            avg_t = statistics.mean(success_times)
            jitter = statistics.stdev(success_times) if len(success_times) > 1 else 0
            
            self.stats_labels['min'].config(text=f"Mín: {min_t:.1f}ms")
            self.stats_labels['max'].config(text=f"Máx: {max_t:.1f}ms")
            self.stats_labels['avg'].config(text=f"Média: {avg_t:.1f}ms")
            self.stats_labels['jitter'].config(text=f"Jitter: {jitter:.1f}ms")
    
    def run(self):
        """Iniciar aplicação."""
        self.root.mainloop()


def main():
    """Entry point para GUI."""
    if not MATPLOTLIB_AVAILABLE:
        print("Aviso: matplotlib não instalado. Gráficos limitados.")
        print("Instale com: pip install matplotlib")
    
    app = NetworkAnalyzerGUI()
    app.run()


if __name__ == "__main__":
    main()
