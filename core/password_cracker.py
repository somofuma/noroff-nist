"""
Password Cracker Module - Attempts to crack password hashes using dictionary attacks
"""

import hashlib
from typing import Optional, Dict
from pathlib import Path


class PasswordCracker:
    def __init__(self):
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        self.results = {}

    def crack_hash(self, target_hash: str, wordlist_path: str, algorithm: str = 'md5') -> Optional[str]:
        """
        Attempt to crack a password hash using a dictionary attack.
        
        Args:
            target_hash: The hash to crack
            wordlist_path: Path to the wordlist file
            algorithm: Hash algorithm to use (md5, sha256, sha512)
            
        Returns:
            The cracked password if found, None otherwise
        """
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        hash_func = self.supported_algorithms[algorithm]
        target_hash = target_hash.lower()

        try:
            with open(wordlist_path, 'r', encoding='utf-8') as wordlist:
                for word in wordlist:
                    word = word.strip()
                    current_hash = hash_func(word.encode()).hexdigest()
                    
                    if current_hash == target_hash:
                        self.results[target_hash] = word
                        return word
                        
        except FileNotFoundError:
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
            
        return None

    def save_results(self, output_file: str) -> None:
        """
        Save cracked passwords to a file.
        
        Args:
            output_file: Path to save the results
        """
        with open(output_file, 'w') as f:
            for hash_value, password in self.results.items():
                f.write(f"{hash_value}:{password}\n") 