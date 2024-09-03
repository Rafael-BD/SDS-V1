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
    Check for packets indicating a service or OS scan.
    These packets usually involve multiple ports and packets with different TCP options.
    """
    if TCP in packet:
        # Check for flags indicating OS discovery attempt
        flags = packet[TCP].flags
        options = packet[TCP].options
        
        # Check if flags are SYN and TCP options like Timestamps (indicative of OS detection)
        if flags == "S" and any(opt[0] == "Timestamp" for opt in options):
            return True
        
        # Check for multiple connection attempts (SYN) to different ports
        if flags == "S":
            return True
        
    return False

def packet_callback(packet, port_scan_detector, evasion_detector, scan_tracker, logger):
    ip_src = packet[IP].src

    if not scan_tracker.is_recently_detected(ip_src):
        if port_scan_detector.detect_scan(packet):
            alert_msg = f"TCP Scan detected from {ip_src}!"
            print(alert_msg)
            logger.info(alert_msg)
            scan_tracker.add_detection(ip_src)
        
        if detect_udp_scan(packet):
            alert_msg = f"UDP Scan detected from {ip_src}!"
            print(alert_msg)
            logger.info(alert_msg)
            scan_tracker.add_detection(ip_src)

        if detect_service_os_scan(packet):
            alert_msg = f"Service/OS Scan detected from {ip_src}!"
            print(alert_msg)
            logger.info(alert_msg)
            scan_tracker.add_detection(ip_src)

        if evasion_detector.detect_fragmentation(packet):
            alert_msg = f"Fragmentation evasion attempt detected from {ip_src}!"
            print(alert_msg)
            logger.info(alert_msg)
            scan_tracker.add_detection(ip_src)

def start_sniffing(interface, port_scan_detector, evasion_detector):
    scan_tracker = ScanTracker()
    logger = setup_logger()
    
    print(f"Analyzing interface {interface}...")
    sniff(
        iface=interface,
        prn=lambda x: packet_callback(x, port_scan_detector, evasion_detector, scan_tracker, logger),
        store=False
    )
