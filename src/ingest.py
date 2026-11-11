from collections import deque
from pathlib import Path
from scapy.all import PcapReader

class PCAPIngestor:
    """Passive PCAP streaming ingestor providing sliding time windows."""
    def __init__(self, pcap_path):
        self.pcap_path = Path(pcap_path)

    def stream_windows(self, window_seconds=5, slide_seconds=1):
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        buffer = deque()
        window_start = None
        last_timestamp = None

        with PcapReader(str(self.pcap_path)) as pcap_reader:
            for packet in pcap_reader:
                if not hasattr(packet, 'time'):
                    continue

                timestamp = float(packet.time)
                if window_start is None:
                    window_start = timestamp

                last_timestamp = timestamp
                buffer.append(packet)

                # Emit every complete window
                while timestamp >= window_start + window_seconds:
                    window_end = window_start + window_seconds
                    current_window = [
                        pkt for pkt in buffer
                        if window_start <= float(pkt.time) < window_end
                    ]
                    if current_window:
                        yield (window_start, window_end, current_window)

                    window_start += slide_seconds
                    # Remove packets older than the next window
                    while buffer and float(buffer[0].time) < window_start:
                        buffer.popleft()

        # Process remaining partial windows at end of file
        if last_timestamp is not None:
            while window_start <= last_timestamp:
                window_end = window_start + window_seconds
                current_window = [
                    pkt for pkt in buffer
                    if window_start <= float(pkt.time) < window_end
                ]
                if current_window:
                    yield (window_start, window_end, current_window)

                window_start += slide_seconds
                while buffer and float(buffer[0].time) < window_start:
                    buffer.popleft()