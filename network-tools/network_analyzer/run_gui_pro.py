"""
Launcher para o Network Analyzer Pro GUI.

Execute este script para iniciar a interface gráfica completa.

Uso:
    python run_gui_pro.py
"""

import sys
import os

# Adicionar o directório pai ao path para imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == "__main__":
    try:
        from network_analyzer.gui_pro import main
        main()
    except ImportError as e:
        print(f"Erro ao importar módulos: {e}")
        print("\nVerifique se as dependências estão instaladas:")
        print("  pip install matplotlib dnspython requests psutil")
        sys.exit(1)
    except Exception as e:
        print(f"Erro ao iniciar: {e}")
        sys.exit(1)
