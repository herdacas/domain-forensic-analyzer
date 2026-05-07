"""Entry point for Domain Forensic Analyzer. Run from project root: python run.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.core.domain_analyzer import main

if __name__ == "__main__":
    main()
