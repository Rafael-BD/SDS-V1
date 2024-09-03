from scapy.layers.inet import TCP

class EvasionDetector:
    def __init__(self, fragmentation_limit=5):
        self.fragmented_packets = {}
        self.fragmentation_limit = fragmentation_limit

    def detect_fragmentation(self, packet):
        """
        Detects fragmentation evasion attempts.

        :param packet: Captured packet.
        :return: Boolean indicating whether a fragmentation evasion was detected.
        """
        
        if packet.haslayer("IP"):
            ip_id = packet["IP"].id
            ip_frag = packet["IP"].frag
            src_ip = packet["IP"].src
            
            if ip_frag > 0:
                if src_ip not in self.fragmented_packets:
                    self.fragmented_packets[src_ip] = []
                
                self.fragmented_packets[src_ip].append(ip_id)
                
                if len(self.fragmented_packets[src_ip]) > self.fragmentation_limit:
                    return True
        
        return False

    def detect_decoy_scan(self, packet):
        """
        Detects scans that use multiple IPs (decoy scan).
        
        :param packet: Captured packet.
        :return: Boolean indicating whether a decoy scan was detected.
        """
        
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            
            if src_ip != dst_ip:
                return True
        
        return False
