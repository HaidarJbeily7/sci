"""
Entry point for running SCI as a module.

Usage:
    python -m sci [COMMAND] [OPTIONS]
"""

from sci.cli.main import app

if __name__ == "__main__":
    app()
