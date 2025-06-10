import socket
import struct
import os
from scapy.all import IP, TCP, Raw, fragment, sr1

class FileTransfer:
    def __init__(self):
        self.socket = None
        self.connected = False
        self.chunk_size = 8192  # 8KB chunks
        
    def connect(self, ip, port):
        """Connect to the server"""
        if self.connected:
            raise Exception("Already connected")
            
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((ip, port))
        self.connected = True
        
    def disconnect(self):
        """Disconnect from the server"""
        if not self.connected:
            raise Exception("Not connected")
            
        self.socket.close()
        self.socket = None
        self.connected = False
        
    def send_file(self, data, fragment_size=None, ttl=64, dont_fragment=False, frag_offset=0):
        """Send file data to the server with advanced IP header options"""
        if not self.connected:
            raise Exception("Not connected")
        # Komut gönder
        self.socket.sendall(b'SEND    ')
        # Dosya boyutunu gönder
        size = len(data)
        self.socket.sendall(struct.pack('!Q', size))
        header_info = None
        if fragment_size:
            # Fragment the data using Scapy
            ip = IP(dst=self.socket.getpeername()[0], ttl=ttl, flags='DF' if dont_fragment else 0, frag=frag_offset)
            tcp = TCP(dport=self.socket.getpeername()[1])
            raw = Raw(load=data)
            packet = ip/tcp/raw
            fragments = fragment(packet, fragsize=fragment_size)
            for frag in fragments:
                self.socket.sendall(bytes(frag))
            # Başlık bilgisi döndür
            header_info = {
                'ttl': ip.ttl,
                'df': bool(ip.flags.DF),
                'frag_offset': ip.frag,
                'checksum': ip.chksum
            }
        else:
            # Send data in chunks
            sent = 0
            while sent < size:
                chunk = data[sent:sent + self.chunk_size]
                self.socket.sendall(chunk)
                sent += len(chunk)
            # Standart başlık bilgisi döndür
            ip = IP(dst=self.socket.getpeername()[0], ttl=ttl, flags='DF' if dont_fragment else 0, frag=frag_offset)
            header_info = {
                'ttl': ip.ttl,
                'df': bool(ip.flags.DF),
                'frag_offset': ip.frag,
                'checksum': ip.chksum
            }
        return header_info
        
    def receive_file(self):
        """Receive file data from the server"""
        if not self.connected:
            raise Exception("Not connected")
            
        # Komut gönder
        self.socket.sendall(b'RECEIVE ')
        
        # Dosya boyutunu al
        size_data = self.socket.recv(8)
        size = struct.unpack('!Q', size_data)[0]
        
        if size == 0:
            raise Exception("Sunucuda gönderilecek dosya yok!")
        
        # Receive data in chunks
        data = bytearray()
        received = 0
        while received < size:
            chunk = self.socket.recv(min(self.chunk_size, size - received))
            if not chunk:
                raise Exception("Connection closed by server")
            data.extend(chunk)
            received += len(chunk)
            
        return bytes(data)
        
    def set_ttl(self, ttl):
        """Set TTL value for packets"""
        if not self.connected:
            raise Exception("Not connected")
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        
    def set_dont_fragment(self, value):
        """Set Don't Fragment flag"""
        if not self.connected:
            raise Exception("Not connected")
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_DF, 1 if value else 0)
        
    def calculate_checksum(self, data):
        """Calculate IP checksum for data"""
        if len(data) % 2 == 1:
            data += b'\0'
            
        words = struct.unpack('!%dH' % (len(data) // 2), data)
        checksum = sum(words)
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            
        return ~checksum & 0xFFFF 