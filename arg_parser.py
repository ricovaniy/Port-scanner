import argparse
from dataclasses import dataclass


@dataclass
class ScannerArgs:
    target: str
    ports: str
    timeout: int
    threads_num: int
    verbose: bool
    guess: bool


def configure_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog = "scanner",
        description = "port_scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("ports", nargs="+", help="Port(s) to scan")
    parser.add_argument("--timeout", type=float, default=4,
                        help="Timeout for response in seconds (default: 2)", dest="timeout")
    parser.add_argument("-j", "--num-threads", type=int, default=50,
                        help="Number of threads (default: 1)", dest="threads_num")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode", dest="verbose")
    parser.add_argument("-g", "--guess", action="store_true", help="Guess protocols", dest="guess")
    return parser
