from collections import defaultdict
import time

class PortScanDetector:
    def __init__(self, time_window=10, port_threshold=5):
        """
        Inicializa o detector de port scans.
        
        :param time_window: Janela de tempo em segundos para considerar as tentativas de conexão.
        :param port_threshold: Número mínimo de portas diferentes que indicam um possível scan.
        """
        self.time_window = time_window
        self.port_threshold = port_threshold
        self.connection_records = defaultdict(list)

    def detect_scan(self, packet):
        """
        Verifica se o pacote faz parte de um possível scan de portas.
        
        :param packet: Pacote capturado pelo sniffer.
        :return: Boolean indicando se um scan foi detectado.
        """
        if packet.haslayer("IP") and packet.haslayer("TCP"):
            src_ip = packet["IP"].src
            dst_port = packet["TCP"].dport
            current_time = time.time()
            
            # Registra a conexão
            self.connection_records[src_ip].append((dst_port, current_time))
            
            # Limpa registros antigos
            self._cleanup_old_records(src_ip, current_time)
            
            # Verifica se o número de portas únicas excede o limite
            unique_ports = set(port for port, timestamp in self.connection_records[src_ip])
            if len(unique_ports) > self.port_threshold:
                return True  # Scan detectado
        return False

    def _cleanup_old_records(self, src_ip, current_time):
        """
        Remove registros antigos fora da janela de tempo.
        
        :param src_ip: Endereço IP de origem.
        :param current_time: Timestamp atual.
        """
        self.connection_records[src_ip] = [
            (port, timestamp) for port, timestamp in self.connection_records[src_ip]
            if current_time - timestamp <= self.time_window
        ]

