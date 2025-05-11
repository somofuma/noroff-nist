"""
Network Mapper Module - Scans networks for open ports and services
"""

import socket
import threading
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor


class NetworkMapper:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.results = {}
        
    def scan_port(self, target: str, port: int) -> Tuple[int, bool]:
        """
        Scan a single port on the target host.
        
        Args:
            target: Target IP address
            port: Port number to scan
            
        Returns:
            Tuple of (port, is_open)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((target, port))
            is_open = result == 0
            if is_open:
                try:
                    service = socket.getservbyport(port)
                except (socket.error, OSError):
                    service = "unknown"
                self.results[port] = {
                    "open": True,
                    "service": service
                }
            return port, is_open
        except socket.error:
            return port, False
        finally:
            sock.close()
            
    def scan_target(self, target: str, start_port: int = 1, end_port: int = 1024, threads: int = 100) -> Dict[int, Dict]:
        """
        Scan a range of ports on the target host.
        
        Args:
            target: Target IP address
            start_port: First port to scan
            end_port: Last port to scan
            threads: Number of concurrent threads
            
        Returns:
            Dictionary of port scan results
        """
        self.results.clear()
        ports = range(start_port, end_port + 1)
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self.scan_port, target, port) for port in ports]
            for future in futures:
                port, is_open = future.result()
        
        return self.results
    
    def save_results(self, output_file: str) -> None:
        """
        Save scan results to a file.
        
        Args:
            output_file: Path to save the results
        """
        with open(output_file, 'w') as f:
            for port, info in self.results.items():
                f.write(f"Port {port}: {'Open' if info['open'] else 'Closed'} - Service: {info['service']}\n") 