"""
Directory Buster Module - Discovers hidden directories and files on web servers
"""

import requests
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin


class DirectoryBuster:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def check_url(self, base_url: str, path: str) -> Dict:
        """
        Check if a specific URL path exists.
        
        Args:
            base_url: Base URL of the target
            path: Path to check
            
        Returns:
            Dictionary containing response information
        """
        url = urljoin(base_url.rstrip('/') + '/', path)
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            result = {
                'url': url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'redirect_url': response.url if response.history else None
            }
            
            if response.status_code != 404:
                self.results[url] = result
                
            return result
            
        except requests.RequestException as e:
            return {
                'url': url,
                'status_code': 0,
                'error': str(e)
            }

    def bust_directories(self, target_url: str, wordlist_path: str, threads: int = 10) -> Dict[str, Dict]:
        """
        Perform directory busting on the target URL.
        
        Args:
            target_url: Target URL to scan
            wordlist_path: Path to wordlist file
            threads: Number of concurrent threads
            
        Returns:
            Dictionary of results for each discovered path
        """
        self.results.clear()
        
        try:
            with open(wordlist_path, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [
                executor.submit(self.check_url, target_url, path)
                for path in paths
            ]
            for future in futures:
                future.result()

        return self.results

    def save_results(self, output_file: str) -> None:
        """
        Save directory busting results to a file.
        
        Args:
            output_file: Path to save the results
        """
        with open(output_file, 'w') as f:
            for url, info in self.results.items():
                redirect_info = f" -> {info['redirect_url']}" if info.get('redirect_url') else ""
                f.write(f"{url} [Status: {info['status_code']}] [Size: {info.get('content_length', 0)}]{redirect_info}\n") 