import logging
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

class ScanTracker:
    def __init__(self):
        self.detected_scans = {}

    def add_detection(self, ip):
        self.detected_scans[ip] = datetime.now()

    def is_recently_detected(self, ip, timeout=10):
        if ip in self.detected_scans:
            last_detection_time = self.detected_scans[ip]
            if (datetime.now() - last_detection_time).seconds < timeout:
                return True
        return False

def setup_logger():
    logger = logging.getLogger("scan_detector")
    logger.setLevel(logging.INFO)
    
    dt = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    handler = logging.FileHandler("./logs/scan_detector_" + dt + ".log")
    handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    return logger

def detect_udp_scan(packet):
    if UDP in packet:
        return True
    return False

def detect_service_os_scan(packet):
    """
    Verifica a presença de pacotes que indicam um scan de serviço ou SO.
    Esses pacotes geralmente envolvem várias portas e pacotes com diferentes opções TCP.
    """
    if TCP in packet:
        # Verifica por flags que indicam tentativa de descoberta de SO
        flags = packet[TCP].flags
        options = packet[TCP].options
        
        # Verificar se flags são SYN e também opções TCP como Timestamps (indicativo de detecção de SO)
        if flags == "S" and any(opt[0] == "Timestamp" for opt in options):
            return True
        
        # Verifica múltiplas tentativas de conexão (SYN) para diferentes portas
        if flags == "S":
            return True
        
    return False

def packet_callback(packet, port_scan_detector, evasion_detector, scan_tracker, logger):
    ip_src = packet[IP].src

    if not scan_tracker.is_recently_detected(ip_src):
        if port_scan_detector.detect_scan(packet):
            alert_msg = f"TCP Scan detectado de {ip_src}!"
            print(alert_msg)
            logger.info(alert_msg)
            scan_tracker.add_detection(ip_src)
        
        if detect_udp_scan(packet):
            alert_msg = f"UDP Scan detectado de {ip_src}!"
            print(alert_msg)
            logger.info(alert_msg)
            scan_tracker.add_detection(ip_src)

        if detect_service_os_scan(packet):
            alert_msg = f"Scan de Serviço/SO detectado de {ip_src}!"
            print(alert_msg)
            logger.info(alert_msg)
            scan_tracker.add_detection(ip_src)

        if evasion_detector.detect_fragmentation(packet):
            alert_msg = f"Tentativa de evasão por fragmentação detectada de {ip_src}!"
            print(alert_msg)
            logger.info(alert_msg)
            scan_tracker.add_detection(ip_src)

def start_sniffing(interface, port_scan_detector, evasion_detector):
    scan_tracker = ScanTracker()
    logger = setup_logger()
    
    print(f"Analisando interface {interface}...")
    sniff(
        iface=interface,
        prn=lambda x: packet_callback(x, port_scan_detector, evasion_detector, scan_tracker, logger),
        store=False
    )
