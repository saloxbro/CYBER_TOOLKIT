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
````

Or, compile manually via MinGW/MSYS2:

```sh
gcc -o cyber_toolkit.exe *.c -lws2_32 -lssl -lcrypto
```

---

## Usage

1. **Run the executable:**

   ```sh
   cyber_toolkit.exe
   ```

2. **Use the on-screen menu** to select a tool and perform tasks.

> **Tip:**
> Results and logs are saved in local text files such as `scan_report.txt` and `dns_results.log`.

---

## Example Screenshot

*(Insert a screenshot here!)*

---

## Group Members

* **BITF24M043:** Haider Ali
* **BITF24M059:** Wahaj
* **BITF24M044:** M. Salman Shahid

---

## Acknowledgments

This project was developed as part of a group assignment for cybersecurity coursework.
Special thanks to all group members for their contributions.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

```

---

## **How To Use This**

1. **Copy and paste** this markdown into your `README.md`.
2. Fill in the screenshot and any additional info as you update your project.
3. Keep your LICENSE file in the root folder.

---

**If you want a more compact or more detailed README, or want me to generate a badge or logo for you, just let me know!**
```
