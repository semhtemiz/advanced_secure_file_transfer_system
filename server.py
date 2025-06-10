import socket
import struct
import os
import threading
import time
from security import SecurityManager
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver

HOST = '0.0.0.0'  # Tüm arayüzlerden dinle
PORT = 5000
HTTP_PORT = 5000  # HTTP sunucu portu
RECEIVED_DIR = 'alinan_dosya'
SEND_DIR = 'gonderilecek_dosya'
RECEIVED_FILE = os.path.join(RECEIVED_DIR, 'alici_dosya')
SEND_FILE = os.path.join(SEND_DIR, 'gonderilecek_dosya')  # Sunucudan gönderilecek dosya adı

# HTTP sunucu için handler
class BandwidthTestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/bandwidth_test':
            content_length = int(self.headers['Content-Length'])
            # Veriyi oku ama bir şey yapma (bant genişliği testi için)
            data = self.rfile.read(content_length)
            # Başarılı yanıt döndür
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()
            
    def log_message(self, format, *args):
        # HTTP sunucu loglarını devre dışı bırak
        return

# Anahtar ve IV istemciden alınmalı veya GUI'den girilmeli
# Test için anahtar ve IV'yi kullanıcıdan al

def start_http_server():
    """HTTP sunucuyu başlat (bant genişliği testi için)"""
    try:
        httpd = socketserver.ThreadingTCPServer((HOST, HTTP_PORT), BandwidthTestHandler)
        print(f"HTTP sunucu başlatıldı: {HOST}:{HTTP_PORT}")
        # Ayrı bir thread'de çalıştır
        http_thread = threading.Thread(target=httpd.serve_forever)
        http_thread.daemon = True  # Ana program kapandığında bu thread de kapanır
        http_thread.start()
    except Exception as e:
        print(f"HTTP sunucu başlatılamadı: {e}")

def main():
    print(f"Sunucu başlatılıyor: {HOST}:{PORT}")
    # Klasörler yoksa oluştur
    os.makedirs(RECEIVED_DIR, exist_ok=True)
    os.makedirs(SEND_DIR, exist_ok=True)
    
    # HTTP sunucuyu başlat (bant genişliği testi için)
    if HTTP_PORT != PORT:  # Aynı port kullanılıyorsa çakışma olmasın
        start_http_server()
    
    # Ana dosya transfer sunucusu
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print("Bağlantı bekleniyor...")
    while True:
        conn, addr = s.accept()
        print(f"Bağlantı geldi: {addr}")
        try:
            # Komut oku (ilk 8 byte)
            cmd = conn.recv(8).decode().strip()
            print(f"Komut alındı: {cmd}")
            if cmd == 'SEND':
                handle_receive(conn)
            elif cmd == 'RECEIVE':
                handle_send(conn)
            else:
                print("Bilinmeyen komut!")
        except Exception as e:
            print(f"Hata: {e}")
        finally:
            conn.close()
            print("Bağlantı kapatıldı.")

def handle_receive(conn):
    # Dosya boyutunu al
    size_data = conn.recv(8)
    if not size_data:
        print("Dosya boyutu alınamadı!")
        return
    size = struct.unpack('!Q', size_data)[0]
    print(f"Gelen dosya boyutu: {size} byte")
    # Dosya verisini al
    data = bytearray()
    received = 0
    while received < size:
        chunk = conn.recv(min(8192, size - received))
        if not chunk:
            break
        data.extend(chunk)
        received += len(chunk)
    print(f"Toplam alınan veri: {len(data)} byte")
    # Anahtar, IV ve şifreli veri ayrıştır
    key = data[:32]
    iv = data[32:48]
    encrypted_data = data[48:]
    # Şifreyi çöz ve bütünlüğü kontrol et
    security = SecurityManager()
    try:
        decrypted = security.decrypt_file(encrypted_data, key, iv)
        with open(RECEIVED_FILE, 'wb') as f:
            f.write(decrypted)
        # Şifreli dosyayı da SEND klasörüne kopyala (alıcı tekrar gönderebilsin diye)
        with open(SEND_FILE, 'wb') as f:
            f.write(data)
        print(f"Dosya başarıyla çözüldü ve kaydedildi: {RECEIVED_FILE}")
    except Exception as e:
        print(f"Hata: {e}")

def handle_send(conn):
    # Gönderilecek dosya var mı kontrol et
    if not os.path.exists(SEND_FILE):
        print(f"Gönderilecek dosya bulunamadı: {SEND_FILE}")
        conn.sendall(struct.pack('!Q', 0))
        return
    with open(SEND_FILE, 'rb') as f:
        data = f.read()
    size = len(data)
    conn.sendall(struct.pack('!Q', size))
    sent = 0
    while sent < size:
        chunk = data[sent:sent+8192]
        conn.sendall(chunk)
        sent += len(chunk)
    print(f"Dosya gönderildi: {SEND_FILE}")

if __name__ == '__main__':
    main() 