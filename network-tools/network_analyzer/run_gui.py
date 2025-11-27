"""Launcher para a GUI do Network Analyzer."""
import sys
import os

# Adicionar o directório pai ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network_analyzer.gui import main

if __name__ == "__main__":
    main()
