# CYBERSECURITY TOOLKIT

A multi-functional, open-source cybersecurity toolkit built in C for Windows, featuring port scanning, DNS lookup, and password cracking (MD5).

---

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Compilation](#compilation)
- [Usage](#usage)
- [Group Members](#group-members)
- [Acknowledgments](#acknowledgments)
- [License](#license)

---

## Features

### Port Scanner
- Scan specified ports on a target IP address or hostname.
- Provides detailed results for open and closed ports.

### DNS Lookup
- Resolves domain names to IP addresses.
- Supports various DNS record types: **A, AAAA, CNAME, TXT, NS**.

### Password Cracker
- Generates MD5 hashes for input strings.
- Cracks MD5 hashes using a dictionary-based approach.

---

## Requirements

- Windows Operating System
- GCC Compiler (MinGW or MSYS2)
- [OpenSSL Library](https://www.openssl.org/)
- Winsock2 Library

---

## Compilation

To compile the project:

1. **Navigate to the project directory.**
2. Run the `build.bat` file:

   ```sh
   build.bat
