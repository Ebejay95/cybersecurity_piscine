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

You must validate each project in that

## (Optional) Cybersecurity - Iron Dome - Malware

You must validate each project in that

## Cybersecurity - Inquisitor - Network

You must validate each project in that

## Cybersecurity - Vaccine - Web

You must validate each project in that
