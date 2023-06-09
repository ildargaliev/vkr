from signal import pthread_kill, SIGTSTP
from scapy.all import *
from threading import Thread, Event

class STPCheck():
    def __init__(self, app) -> None:
        self.iface = 'eth0'
        self.app = app
        self.hasTraffic = False
        self.sniffer = None
        self.is_packet_sending = False
        self.sending_thread = None
        self.stop_event = None


    def start_sniffing(self):
        self.sniffer = AsyncSniffer(filter='stp', prn=self.app.add_row)
        self.sniffer.start()

    def stop_sniffing(self):
        self.sniffer.stop()
    
    def start_sending_packets(self):
        self.stop_event = Event()
        self.sending_thread = Thread(target=self._send_packets, args=(self.stop_event,))
        self.sending_thread.start()
        

    def _send_packets(self, event):
        our_mac = get_if_hwaddr(self.iface)
        pkt = Dot3(src=our_mac, dst="01:80:C2:00:00:00")\
            / LLC(dsap=0x042, ssap=0x042, ctrl=3)\
            / STP(rootmac=get_if_hwaddr(self.iface), bpduflags=0x01, bridgemac=our_mac)
        
        self.is_packet_sending = True
        while True:
            if event.is_set():
                break
            sendp(pkt, iface=self.iface, verbose=1)
            time.sleep(2)

    def stop_sending_packets(self):
        self.stop_event.set()
        self.is_packet_sending = False

class DTPCheck():

    STATUS_MAP = {b'\x03': '03 ACCESS/DESIRABLE' , b'\x04': '04 ACCESS/AUTO', b'\x84': '84 TRUNK/AUTO'}

    def __init__(self, app) -> None:
        self.iface = 'eth0'
        self.app = app
        self.hasTraffic = False
        self.sniffer = None
        self.is_packet_sending = False
        self.sending_thread = None
        self.stop_event = None


    def start_sniffing(self):
        self.sniffer = AsyncSniffer(filter='ether dst 01:00:0c:cc:cc:cc', prn=self.app.dtp_add_row)
        self.sniffer.start()

    def stop_sniffing(self):
        self.sniffer.stop()
    
    def start_sending_packets(self):
        self.stop_event = Event()
        self.sending_thread = Thread(target=self._send_packets, args=(self.stop_event,))
        self.sending_thread.start()
        

    def _send_packets(self, event):
        our_mac = get_if_hwaddr(self.iface)
	
        # DTP SNAP code = 0x2004
        # DTPStatus = 03 ACCESS/DESIRABLE
        pkt = Dot3(src=our_mac, dst="01:00:0C:CC:CC:CC")\
        / LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0x0c, code = 0x2004)\
        / DTP(tlvlist=[DTPDomain(),DTPStatus(),DTPType(),DTPNeighbor(neighbor=our_mac)])
        
        self.is_packet_sending = True
        while True:
            if event.is_set():
                break
            sendp(pkt, iface=self.iface, verbose=1)
            time.sleep(3)

    def stop_sending_packets(self):
        self.stop_event.set()
        # pthread_kill(self.sending_thread.ident, SIGTSTP)
        self.is_packet_sending = False

class CAMCheck():

    def __init__(self, app) -> None:
        self.iface = 'eth0'
        self.app = app
        self.hasTraffic = False
        self.sniffer = None
        self.is_packet_sending = False
        self.sending_thread = None
        self.stop_event = None


    def start_sniffing(self):
        self.sniffer = AsyncSniffer(filter='ip', prn=self.app.cam_add_row)
        self.sniffer.start()

    def stop_sniffing(self):
        self.sniffer.stop()
    
    def start_sending_packets(self):
        self.stop_event = Event()
        self.sending_thread = Thread(target=self._send_packets, args=(self.stop_event,))
        self.sending_thread.start()
        

    def _send_packets(self, event):
	
        pkt = Ether(src = RandMAC(),dst= RandMAC())/IP(src=RandIP(),dst=RandIP())
        
        self.is_packet_sending = True
        while True:
            if event.is_set():
                break
            sendp(pkt, iface=self.iface, verbose=1)
            # time.sleep(0.)

    def stop_sending_packets(self):
        self.stop_event.set()
        self.is_packet_sending = False
    
