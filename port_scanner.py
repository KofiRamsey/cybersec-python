import socket


def scan_ports(host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            socket.setdefaulttimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port} is open.")
            else:
                print(f"Port {port} is closed.")
    return open_ports


if __name__ == "__main__":
    target_host = input("Enter the target host (e.g., 192.168.1.1 or example.com): ")
    start = int(input("Enter the start port number (e.g., 1): "))
    end = int(input("Enter the end port number (e.g., 100): "))

    print(f"\nScanning ports from {start} to {end} on {target_host}...\n")
    open_ports_list = scan_ports(target_host, start, end)
    print(f"\nOpen ports on {target_host}: {', '.join(map(str, open_ports_list))}")
