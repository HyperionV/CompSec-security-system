#!/usr/bin/env python3
"""
Security Application - Main Entry Point
A comprehensive security application with PyQt5 GUI interface
"""

import sys
import os

# Add modules directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Main entry point for Security Application - launches GUI"""
    try:
        print("=" * 60)
        print("    SECURITY APPLICATION - CRYPTOGRAPHIC SYSTEM")
        print("=" * 60)
        print("Starting PyQt5 GUI Application...")
        print("=" * 60)
        
        # Import and run the GUI application
        from gui.app import run_gui
        
        exit_code = run_gui()
        sys.exit(exit_code)
        
    except ImportError as e:
        print(f"❌ Failed to import GUI components: {e}")
        print("Please ensure PyQt5 is installed: pip install PyQt5")
        sys.exit(1)
    except Exception as e:
        print(f"❌ GUI Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 