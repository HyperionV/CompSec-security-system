import sys
import os
from gui.app import main as gui_main

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    gui_main() 