import socket
import threading
from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanResult:
    port: int
    state: str
    service: Optional[str] = None
    banner: Optional[str] = None


class PortScanner:
    def __init__(self, target: str, timeout: float = 1.0, max_threads: int = 50):
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.results: list[ScanResult] = []
        self._lock = threading.Lock()

    def _resolve_target(self) -> str:
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            raise ValueError(f"Could not resolve target: {self.target}")

    def _scan_port(self, port: int) -> ScanResult:
        ip = self._resolve_target()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        result = ScanResult(port=port, state="closed")
        try:
            conn = sock.connect_ex((ip, port))
            if conn == 0:
                result.state = "open"
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    if banner:
                        result.banner = banner
                except OSError:
                    pass
                result.service = self._guess_service(port)
        except OSError:
            pass
        finally:
            sock.close()
        return result

    @staticmethod
    def _guess_service(port: int) -> str:
        common = {22: "SSH", 80: "HTTP", 443: "HTTPS", 21: "FTP",
                  25: "SMTP", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"}
        return common.get(port, "unknown")

    def scan(self, ports: range) -> list[ScanResult]:
        self.results = []
        threads = []
        for port in ports:
            t = threading.Thread(target=lambda p=port: self._scan_and_store(p))
            threads.append(t)
            t.start()
            if len(threads) >= self.max_threads:
                for t in threads:
                    t.join()
                threads = []
        for t in threads:
            t.join()
        return self.results

    def _scan_and_store(self, port: int):
        result = self._scan_port(port)
        with self._lock:
            self.results.append(result)

    def open_ports(self) -> list[ScanResult]:
        return [r for r in self.results if r.state == "open"]

    def summary(self) -> dict:
        total = len(self.results)
        open_count = len(self.open_ports())
        return {"target": self.target, "ports_scanned": total, "open_ports": open_count}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Multi-threaded network port scanner")
    parser.add_argument("--target", required=True, help="Target hostname or IP")
    parser.add_argument("--ports", default="1-1024", help="Port range (e.g. 1-1024)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout")
    parser.add_argument("--threads", type=int, default=50, help="Max threads")
    args = parser.parse_args()

    parts = args.ports.split("-")
    start, end = int(parts[0]), int(parts[1]) if len(parts) > 1 else int(parts[0])

    scanner = PortScanner(args.target, timeout=args.timeout, max_threads=args.threads)
    scanner.scan(range(start, end + 1))
    for r in scanner.open_ports():
        banner = f" [{r.banner}]" if r.banner else ""
        print(f"Port {r.port}/tcp open - {r.service}{banner}")
    print(f"\n{scanner.summary()}")


if __name__ == "__main__":
    main()
