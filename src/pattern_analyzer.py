from collections import defaultdict
import time

class PortScanDetector:
    def __init__(self, time_window=10, port_threshold=5):
        """
        Initializes the port scan detector.
        
        :param time_window: Time window in seconds to consider connection attempts.
        :param port_threshold: Minimum number of different ports indicating a possible scan.
        """
        self.time_window = time_window
        self.port_threshold = port_threshold
        self.connection_records = defaultdict(list)

    def detect_scan(self, packet):
        """
        Checks if the packet is part of a possible port scan.
        
        :param packet: Packet captured by the sniffer.
        :return: Boolean indicating if a scan was detected.
        """
        if packet.haslayer("IP") and packet.haslayer("TCP"):
            src_ip = packet["IP"].src
            dst_port = packet["TCP"].dport
            current_time = time.time()
            
            # Register the connection
            self.connection_records[src_ip].append((dst_port, current_time))
            
            # Clean up old records
            self._cleanup_old_records(src_ip, current_time)
            
            # Check if the number of unique ports exceeds the threshold
            unique_ports = set(port for port, timestamp in self.connection_records[src_ip])
            if len(unique_ports) > self.port_threshold:
                return True  # Scan detected
        return False

    def _cleanup_old_records(self, src_ip, current_time):
        """
        Removes old records outside the time window.
        
        :param src_ip: Source IP address.
        :param current_time: Current timestamp.
        """
        self.connection_records[src_ip] = [
            (port, timestamp) for port, timestamp in self.connection_records[src_ip]
            if current_time - timestamp <= self.time_window
        ]
