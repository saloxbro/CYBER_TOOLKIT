# CYBER_TOOLKIT

A modular, open-source cybersecurity toolkit for Windows, developed in C.  
Features include port scanning, DNS lookups (A, AAAA, CNAME, TXT, NS), and MD5 password hash generation and cracking.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Compilation](#compilation)
- [Usage](#usage)
- [Group Members](#group-members)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Features

**Port Scanner**
- Scan specific ports on any IPv4 address or hostname.
- Multi-threaded for speed.
- Logs open and closed ports to a report file.

**DNS Lookup**
- Resolve domain names to IP addresses.
- Query for multiple DNS record types: A, AAAA, CNAME, TXT, NS.
- All results logged for later review.

**Password Cracker / MD5 Hasher**
- Generate MD5 hashes for any input string.
- Crack MD5 hashes using a dictionary-based approach with a custom wordlist.

## Requirements

- Windows Operating System
- GCC Compiler (MinGW or MSYS2 recommended)
- OpenSSL Library (for cryptographic functions)
- Winsock2 Library (for networking)

## Compilation

**Quick Start (using build script):**
1. Download or clone the repository.
2. Open Command Prompt and navigate to the project directory.
3. Run:
    ```sh
    build.bat
    ```
    or double-click `build.bat`.

**Manual Compilation:**
```sh
gcc -o cyber_toolkit.exe *.c -lws2_32 -lssl -lcrypto
Usage
Run the program:

sh
Copy
Edit
cyber_toolkit.exe
Follow the on-screen menu to select a tool:

[1] Port Scanner — Scan open ports on a host

[2] DNS Lookup — Perform DNS reconnaissance

[3] MD5 Cracker/Hasher — MD5 hash generator and cracker

Results are saved in the working directory (e.g., scan_report.txt, dns_results.log).

Tip: To add more wordlists for password cracking, place your file as wordlist.txt in the project directory.

Group Members
BITF24M043: Haider Ali

BITF24M059: Wahaj

BITF24M044: M. Salman Shahid

Acknowledgments
This project was developed as part of a cybersecurity coursework assignment.
Special thanks to all group members for their hard work and contributions!

License
This project is licensed under the MIT License.
Feel free to use, modify, or redistribute this code in accordance with the license.
For questions, improvements, or bug reports, please open an issue or pull request!
