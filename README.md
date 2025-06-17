# 🔍 Port Scanner with Service Detection

A multithreaded Python-based port scanner that scans a range of TCP ports on a target host and performs basic service detection using common ports and banner grabbing.

## 🚀 Features

- ✅ Scans TCP ports on any target IP/hostname
- ✅ Detects common services (HTTP, SSH, FTP, etc.)
- ✅ Simple banner grabbing for open ports
- ✅ Multithreaded for faster scanning
- ✅ Works cross-platform (Linux, Windows, Mac)

---

## 📦 Requirements

- Python 3.x  
- No external libraries required (uses only `socket`, `threading`, and `sys`)

---

## 🛠️ Usage

### 🔧 Command Format

```bash
python portscanner.py <target_host> <start_port-end_port>
