import socket
import json
from datetime import datetime


def scanner_port(ip, port):
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.5)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    sock.send(b"BannerCheck\r\n")
                    banner = sock.recv(1024).decode().strip()
                except:
                    banner = "Serviço identificado, mas sem banner."
                return True, banner
        except socket.gaierror:
            return None, "Erro de DNS"  # Host inválido
    return False, None


common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 5432, 8080]

target = input("Digite o IP/Site: ")
relatorio = {
    "alvo": target,
    "data_scan": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
    "portas_abertas": []
}

print(f"\n[+] Iniciando scan em: {target}")
print("-" * 40)

for port in common_ports:
    is_open, info = scanner_port(target, port)

    if is_open is None:
        print(f"[!] Erro: Não foi possível resolver o host {target}")
        break

    if is_open:
        print(f"[#] Porta {port}: ABERTA | Banner: {info}")
        relatorio["portas_abertas"].append({"porta": port, "banner": info})

if relatorio["portas_abertas"]:
    filename = f"scan_{target.replace('.', '_').replace(':', '_')}.json"
    with open(filename, "w") as f:
        json.dump(relatorio, f, indent=4)
    print("-" * 40)
    print(f"[V] Scan finalizado. Relatório: {filename}")
else:
    print("[!] Nenhuma porta aberta encontrada.")