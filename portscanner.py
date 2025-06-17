import socket
import threading
import sys

# Common ports and their common services for simple detection
COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "Microsoft-DS",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy",
}

# Timeout for socket operations
TIMEOUT = 1

# Thread lock for synchronized output
print_lock = threading.Lock()


def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = COMMON_SERVICES.get(port, "Unknown")
                banner = get_banner(s)
                with print_lock:
                    print(f"Port {port:5} OPEN\tService: {service}")
                    if banner:
                        print(f"  Banner: {banner.strip()}")
    except Exception:
        pass


def get_banner(sock):
    try:
        sock.settimeout(1)
        sock.sendall(b"\r\n")
        banner = sock.recv(1024)
        return banner.decode('utf-8', errors='ignore')
    except Exception:
        return None


def main():
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <target_host> <port_range>")
        print("Example: python portscanner.py 192.168.1.1 20-1024")
        sys.exit(1)

    target = sys.argv[1]
    port_range = sys.argv[2]

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Cannot resolve {target}")
        sys.exit(1)

    try:
        start_port, end_port = map(int, port_range.split('-'))
        if not (0 < start_port < 65536 and 0 < end_port < 65536 and start_port <= end_port):
            raise ValueError
    except ValueError:
        print("Invalid port range. Use format: start-end (e.g., 1-1024)")
        sys.exit(1)

    print(f"Scanning {target} ({ip}) from port {start_port} to {end_port}...")

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("Scan completed.")


if __name__ == "__main__":
    main()
