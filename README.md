CYBERSECURITY TOOLKIT v1.1
========================================

Project Description:
--------------------
The Cybersecurity Toolkit is a multi-functional program designed to assist in various cybersecurity tasks, including:
1. Port Scanning
2. DNS Lookup
3. Password Cracking (MD5 Hash Generator and Dictionary Cracker)

This toolkit is built using C and leverages libraries such as Winsock2, OpenSSL, and Windows APIs for network and cryptographic operations.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Compilation](#compilation)
- [Usage](#usage)
- [Group Members](#group-members)
- [Acknowledgments](#acknowledgments)
- [License](#license)

Features:
---------
1. **Port Scanner**:
   - Scans specified ports on a target IP address or hostname.
   - Provides detailed results for open and closed ports.

2. **DNS Lookup**:
   - Resolves domain names to IP addresses.
   - Supports various DNS record types (e.g., A, AAAA, CNAME, TXT, NS).

3. **Password Cracker**:
   - Generates MD5 hashes for input strings.
   - Cracks MD5 hashes using a dictionary-based approach.

## Requirements:
-------------
- Windows Operating System
- GCC Compiler (MinGW or MSYS2)
- OpenSSL Library
- Winsock2 Library

Compilation:
------------
To compile the project, run the `build.bat` file:
1. Navigate to the project directory.
2. Double-click `build.bat` or run it via Command Prompt:

Usage:
------
1. Run the compiled executable `cyber_toolkit.exe`.
2. Follow the on-screen menu to select a tool and perform tasks.

Group Members:
--------------
- **BITF24M043**: Haider Ali
- **BITF24M059**: Wahaj
- **BITF24M044**: M. Salman Shahid

Acknowledgments:
----------------
This project was developed as part of a group assignment for cybersecurity coursework. Special thanks to all group members for their contributions.

License:
--------
This project is open-source and can be modified or redistributed under the terms of the MIT License.
