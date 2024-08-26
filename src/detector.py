from .packet_sniffer import start_sniffing
from .pattern_analyzer import PortScanDetector
from .evasion_detection import EvasionDetector

class ScanDetector:
    def __init__(self, interface="eth0", time_window=10, port_threshold=5, fragmentation_limit=5):
        self.interface = interface
        self.port_scan_detector = PortScanDetector(time_window, port_threshold)
        self.evasion_detector = EvasionDetector(fragmentation_limit)

    def start(self):
        start_sniffing(self.interface, self.port_scan_detector, self.evasion_detector)

if __name__ == "__main__":
    detector = ScanDetector()
    detector.start()
