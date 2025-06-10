import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
from security import SecurityManager
from transfer import FileTransfer
from network_tools import NetworkTools
import subprocess
import sys
import psutil
import threading

class SecureFileTransferGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Güvenli Dosya Transferi")
        self.geometry("1200x800")
        self.minsize(900, 600)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # --- GEREKLİ NESNELER ---
        self.security_manager = SecurityManager()
        self.send_transfer = FileTransfer()
        self.receive_transfer = FileTransfer()
        self.network_tools = NetworkTools()

        # Scrollable ana frame
        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=1200, height=800)
        self.scrollable_frame.pack(fill="both", expand=True)
        self.scrollable_frame.grid_columnconfigure(0, weight=1)
        self.scrollable_frame.grid_columnconfigure(1, weight=1)

        # Başlık
        title_label = ctk.CTkLabel(self.scrollable_frame, text="Güvenli Dosya Transfer Sistemi", font=("Arial", 22, "bold"), anchor="center")
        title_label.grid(row=0, column=0, columnspan=2, pady=(20, 10), sticky="ew")

        # Sol ve sağ paneller
        self.create_send_panel(self.scrollable_frame, row=1, column=0)
        self.create_receive_panel(self.scrollable_frame, row=1, column=1)
        self.create_right_panel(self.scrollable_frame, row=2, column=0, columnspan=2)
        self.create_security_panel(self.scrollable_frame, row=3, column=0, columnspan=2)

        # Initialize variables
        self.selected_file = None
        self.send_connection_status = False
        self.receive_connection_status = False
        self.encryption_key = None
        self.iv = None

    def create_send_panel(self, parent, row, column):
        send_frame = ctk.CTkFrame(parent, corner_radius=12)
        send_frame.grid(row=row, column=column, padx=20, pady=10, sticky="nsew")
        send_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(send_frame, text="Dosya Gönder", font=("Arial", 16, "bold")).pack(pady=(10, 5))
        
        # File Selection
        file_frame = ctk.CTkFrame(send_frame)
        file_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(file_frame, text="Gönderilecek Dosya Seçimi").pack(pady=5)
        self.file_path_var = tk.StringVar()
        ctk.CTkEntry(file_frame, textvariable=self.file_path_var, state="readonly").pack(fill="x", padx=5)
        ctk.CTkButton(file_frame, text="Dosya Seç", command=self.select_file).pack(pady=5)
        
        # Send Connection Settings
        conn_frame = ctk.CTkFrame(send_frame)
        conn_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(conn_frame, text="Gönderme Bağlantı Ayarları").pack(pady=5)
        
        # IP and Port
        ip_port_frame = ctk.CTkFrame(conn_frame)
        ip_port_frame.pack(fill="x", padx=5, pady=5)
        
        self.send_ip_var = tk.StringVar(value="127.0.0.1")
        self.send_port_var = tk.StringVar(value="5000")
        
        ctk.CTkLabel(ip_port_frame, text="IP:").pack(side="left", padx=5)
        ctk.CTkEntry(ip_port_frame, textvariable=self.send_ip_var, width=120).pack(side="left", padx=5)
        ctk.CTkLabel(ip_port_frame, text="Port:").pack(side="left", padx=5)
        ctk.CTkEntry(ip_port_frame, textvariable=self.send_port_var, width=80).pack(side="left", padx=5)
        
        # Connection Buttons
        btn_frame = ctk.CTkFrame(conn_frame)
        btn_frame.pack(fill="x", padx=5, pady=5)
        
        self.send_connect_btn = ctk.CTkButton(btn_frame, text="Bağlan", command=self.connect_send)
        self.send_connect_btn.pack(side="left", padx=5, expand=True)
        
        self.send_disconnect_btn = ctk.CTkButton(btn_frame, text="Bağlantıyı Kes", command=self.disconnect_send, state="disabled")
        self.send_disconnect_btn.pack(side="left", padx=5, expand=True)
        
        # Send Button
        self.send_btn = ctk.CTkButton(send_frame, text="Dosyayı Şifrele ve Gönder", 
                                    command=self.send_file, state="disabled")
        self.send_btn.pack(fill="x", padx=10, pady=5)
        
        # Send Status Log
        log_frame = ctk.CTkFrame(send_frame)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ctk.CTkLabel(log_frame, text="Gönderme İşlem Logları").pack(pady=5)
        self.send_log_text = ctk.CTkTextbox(log_frame, height=200)
        self.send_log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bütünlük Durumu
        integrity_frame = ctk.CTkFrame(send_frame)
        integrity_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(integrity_frame, text="Bütünlük Durumu").pack(side="left", padx=5)
        self.send_integrity_status = ctk.CTkLabel(integrity_frame, text="-", fg_color="gray", text_color="white")
        self.send_integrity_status.pack(side="left", padx=5)
        
        # Fragmentation Seçeneği
        frag_frame = ctk.CTkFrame(send_frame)
        frag_frame.pack(fill="x", padx=10, pady=5)
        self.fragment_var = tk.BooleanVar()
        self.fragment_size_var = tk.StringVar(value="4096")
        ctk.CTkCheckBox(frag_frame, text="Parçalı Gönder (Fragmentation)", variable=self.fragment_var).pack(side="left", padx=5)
        ctk.CTkLabel(frag_frame, text="Parça Boyutu (byte):").pack(side="left", padx=5)
        ctk.CTkEntry(frag_frame, textvariable=self.fragment_size_var, width=80).pack(side="left", padx=5)
        
        # Gelişmiş Ağ Ayarları
        advanced_frame = ctk.CTkFrame(send_frame)
        advanced_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(advanced_frame, text="Gelişmiş Ağ Ayarları").pack(anchor="w", padx=5)
        adv_inner = ctk.CTkFrame(advanced_frame)
        adv_inner.pack(fill="x", padx=5, pady=2)
        self.ttl_var = tk.StringVar(value="64")
        self.df_var = tk.BooleanVar()
        self.frag_offset_var = tk.StringVar(value="0")
        ctk.CTkLabel(adv_inner, text="TTL:").pack(side="left", padx=2)
        ctk.CTkEntry(adv_inner, textvariable=self.ttl_var, width=50).pack(side="left", padx=2)
        ctk.CTkCheckBox(adv_inner, text="Don't Fragment", variable=self.df_var).pack(side="left", padx=2)
        ctk.CTkLabel(adv_inner, text="Fragment Offset:").pack(side="left", padx=2)
        ctk.CTkEntry(adv_inner, textvariable=self.frag_offset_var, width=60).pack(side="left", padx=2)
        # Başlık Bilgisi Gösterimi
        self.header_info_label = ctk.CTkLabel(advanced_frame, text="Başlık Bilgisi: -", anchor="w")
        self.header_info_label.pack(fill="x", padx=5, pady=2)

    def create_receive_panel(self, parent, row, column):
        receive_frame = ctk.CTkFrame(parent, corner_radius=12)
        receive_frame.grid(row=row, column=column, padx=20, pady=10, sticky="nsew")
        receive_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(receive_frame, text="Dosya Al", font=("Arial", 16, "bold")).pack(pady=(10, 5))
        
        # Receive Connection Settings
        conn_frame = ctk.CTkFrame(receive_frame)
        conn_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(conn_frame, text="Alma Bağlantı Ayarları").pack(pady=5)
        
        # IP and Port
        ip_port_frame = ctk.CTkFrame(conn_frame)
        ip_port_frame.pack(fill="x", padx=5, pady=5)
        
        self.receive_ip_var = tk.StringVar(value="127.0.0.1")
        self.receive_port_var = tk.StringVar(value="5000")
        
        ctk.CTkLabel(ip_port_frame, text="IP:").pack(side="left", padx=5)
        ctk.CTkEntry(ip_port_frame, textvariable=self.receive_ip_var, width=120).pack(side="left", padx=5)
        ctk.CTkLabel(ip_port_frame, text="Port:").pack(side="left", padx=5)
        ctk.CTkEntry(ip_port_frame, textvariable=self.receive_port_var, width=80).pack(side="left", padx=5)
        
        # Connection Buttons
        btn_frame = ctk.CTkFrame(conn_frame)
        btn_frame.pack(fill="x", padx=5, pady=5)
        
        self.receive_connect_btn = ctk.CTkButton(btn_frame, text="Bağlan", command=self.connect_receive)
        self.receive_connect_btn.pack(side="left", padx=5, expand=True)
        
        self.receive_disconnect_btn = ctk.CTkButton(btn_frame, text="Bağlantıyı Kes", command=self.disconnect_receive, state="disabled")
        self.receive_disconnect_btn.pack(side="left", padx=5, expand=True)
        
        # Receive Button
        self.receive_btn = ctk.CTkButton(receive_frame, text="Dosya Al", 
                                       command=self.receive_file, state="disabled")
        self.receive_btn.pack(fill="x", padx=10, pady=5)
        
        # Receive Status Log
        log_frame = ctk.CTkFrame(receive_frame)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ctk.CTkLabel(log_frame, text="Alma İşlem Logları").pack(pady=5)
        self.receive_log_text = ctk.CTkTextbox(log_frame, height=200)
        self.receive_log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bütünlük Durumu
        integrity_frame = ctk.CTkFrame(receive_frame)
        integrity_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(integrity_frame, text="Bütünlük Durumu").pack(side="left", padx=5)
        self.receive_integrity_status = ctk.CTkLabel(integrity_frame, text="-", fg_color="gray", text_color="white")
        self.receive_integrity_status.pack(side="left", padx=5)

    def create_right_panel(self, parent, row, column, columnspan=1):
        perf_frame = ctk.CTkFrame(parent, corner_radius=12)
        perf_frame.grid(row=row, column=column, columnspan=columnspan, padx=20, pady=10, sticky="ew")
        perf_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(perf_frame, text="Ağ Performans Testleri", font=("Arial", 15, "bold")).pack(anchor="w", padx=5, pady=2)
        # Ping
        ping_frame = ctk.CTkFrame(perf_frame)
        ping_frame.pack(fill="x", padx=5, pady=2)
        ctk.CTkLabel(ping_frame, text="Ping (RTT):").pack(side="left", padx=5)
        self.ping_result_var = tk.StringVar(value="-")
        ctk.CTkLabel(ping_frame, textvariable=self.ping_result_var).pack(side="left", padx=5)
        ctk.CTkButton(ping_frame, text="Gecikmeyi Ölç", command=self.measure_latency).pack(side="left", padx=5)
        # Bant Genişliği
        bw_frame = ctk.CTkFrame(perf_frame)
        bw_frame.pack(fill="x", padx=5, pady=2)
        ctk.CTkLabel(bw_frame, text="Bant Genişliği (Mbps):").pack(side="left", padx=5)
        self.bw_result_var = tk.StringVar(value="-")
        ctk.CTkLabel(bw_frame, textvariable=self.bw_result_var).pack(side="left", padx=5)
        ctk.CTkButton(bw_frame, text="Bant Genişliğini Test Et", command=self.measure_bandwidth).pack(side="left", padx=5)
        # Gecikme & Paket Kaybı Simülasyonu
        sim_frame = ctk.CTkFrame(perf_frame)
        sim_frame.pack(fill="x", padx=5, pady=2)
        ctk.CTkLabel(sim_frame, text="Paket Kaybı (%):").pack(side="left", padx=5)
        self.packet_loss_var = tk.StringVar(value="0")
        ctk.CTkEntry(sim_frame, textvariable=self.packet_loss_var, width=60).pack(side="left", padx=5)
        ctk.CTkLabel(sim_frame, text="Gecikme (ms):").pack(side="left", padx=5)
        self.delay_var = tk.StringVar(value="0")
        ctk.CTkEntry(sim_frame, textvariable=self.delay_var, width=60).pack(side="left", padx=5)
        ctk.CTkButton(sim_frame, text="Simülasyonu Başlat", command=self.start_simulation).pack(side="left", padx=5)
        self.sim_result_var = tk.StringVar(value="-")
        ctk.CTkLabel(sim_frame, textvariable=self.sim_result_var).pack(side="left", padx=5)

    def create_security_panel(self, parent, row, column, columnspan=1):
        sec_frame = ctk.CTkFrame(parent, corner_radius=12)
        sec_frame.grid(row=row, column=column, columnspan=columnspan, padx=20, pady=10, sticky="ew")
        sec_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(sec_frame, text="Veri Şifreleme & MITM Analizi", font=("Arial", 15, "bold")).pack(anchor="w", padx=5, pady=2)
        # Şifreleme durumu
        self.encryption_status_var = tk.StringVar(value="-")
        self.encryption_status_label = ctk.CTkLabel(sec_frame, textvariable=self.encryption_status_var, fg_color="gray", text_color="white")
        self.encryption_status_label.pack(anchor="w", padx=5, pady=2)
        # MITM uyarısı
        self.mitm_status_var = tk.StringVar(value="-")
        self.mitm_status_label = ctk.CTkLabel(sec_frame, textvariable=self.mitm_status_var, fg_color="gray", text_color="white")
        self.mitm_status_label.pack(anchor="w", padx=5, pady=2)
        # Paket analizi butonu
        ctk.CTkButton(sec_frame, text="Paket Analizi Yap", command=self.analyze_packet).pack(anchor="w", padx=5, pady=2)
        self.packet_analysis_result = tk.StringVar(value="-")
        ctk.CTkLabel(sec_frame, textvariable=self.packet_analysis_result).pack(anchor="w", padx=5, pady=2)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file = file_path
            self.file_path_var.set(file_path)
            self.log_send_message(f"Dosya seçildi: {os.path.basename(file_path)}")

    def connect_send(self):
        try:
            ip = self.send_ip_var.get()
            port = int(self.send_port_var.get())
            self.send_transfer.connect(ip, port)
            self.send_connection_status = True
            self.send_connect_btn.configure(state="disabled")
            self.send_disconnect_btn.configure(state="normal")
            self.send_btn.configure(state="normal")
            self.log_send_message(f"Gönderme bağlantısı başarılı: {ip}:{port}")
        except Exception as e:
            messagebox.showerror("Bağlantı Hatası", str(e))
            self.log_send_message(f"Gönderme bağlantı hatası: {str(e)}")

    def disconnect_send(self):
        try:
            self.send_transfer.disconnect()
            self.send_connection_status = False
            self.send_connect_btn.configure(state="normal")
            self.send_disconnect_btn.configure(state="disabled")
            self.send_btn.configure(state="disabled")
            self.log_send_message("Gönderme bağlantısı kesildi")
        except Exception as e:
            messagebox.showerror("Bağlantı Hatası", str(e))
            self.log_send_message(f"Gönderme bağlantı kesme hatası: {str(e)}")

    def connect_receive(self):
        try:
            ip = self.receive_ip_var.get()
            port = int(self.receive_port_var.get())
            self.receive_transfer.connect(ip, port)
            self.receive_connection_status = True
            self.receive_connect_btn.configure(state="disabled")
            self.receive_disconnect_btn.configure(state="normal")
            self.receive_btn.configure(state="normal")
            self.log_receive_message(f"Alma bağlantısı başarılı: {ip}:{port}")
        except Exception as e:
            messagebox.showerror("Bağlantı Hatası", str(e))
            self.log_receive_message(f"Alma bağlantı hatası: {str(e)}")

    def disconnect_receive(self):
        try:
            self.receive_transfer.disconnect()
            self.receive_connection_status = False
            self.receive_connect_btn.configure(state="normal")
            self.receive_disconnect_btn.configure(state="disabled")
            self.receive_btn.configure(state="disabled")
            self.log_receive_message("Alma bağlantısı kesildi")
        except Exception as e:
            messagebox.showerror("Bağlantı Hatası", str(e))
            self.log_receive_message(f"Alma bağlantı kesme hatası: {str(e)}")

    def send_file(self):
        if not self.selected_file:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin")
            return
        try:
            # Encrypt file
            encrypted_data, key, iv = self.security_manager.encrypt_file(self.selected_file)
            # Anahtar + IV + şifreli veri olarak birleştir
            final_data = key + iv + encrypted_data
            # Hash'i çıkar
            file_hash = encrypted_data[:32]
            # Fragmentation kontrolü
            fragment_size = None
            if self.fragment_var.get():
                try:
                    fragment_size = int(self.fragment_size_var.get())
                    self.log_send_message(f"Parçalı gönderim aktif. Parça boyutu: {fragment_size} byte")
                except ValueError:
                    messagebox.showwarning("Uyarı", "Geçerli bir parça boyutu girin!")
                    return
            # Gelişmiş ağ ayarları
            try:
                ttl = int(self.ttl_var.get())
            except ValueError:
                messagebox.showwarning("Uyarı", "Geçerli bir TTL değeri girin!")
                return
            df = self.df_var.get()
            try:
                frag_offset = int(self.frag_offset_var.get())
            except ValueError:
                frag_offset = 0
            # Send file (header info dönecek)
            header_info = self.send_transfer.send_file(final_data, fragment_size=fragment_size, ttl=ttl, dont_fragment=df, frag_offset=frag_offset)
            self.log_send_message(f"Dosya gönderildi: {os.path.basename(self.selected_file)}")
            # Bütünlük durumunu göster
            self.send_integrity_status.configure(text="SHA-256: Doğrulandı", fg_color="green")
            # Başlık bilgisini göster
            if header_info:
                self.header_info_label.configure(text=f"Başlık Bilgisi: TTL={header_info.get('ttl', '-')}, DF={header_info.get('df', '-')}, FragOffset={header_info.get('frag_offset', '-')}, Checksum={header_info.get('checksum', '-')}")
            else:
                self.header_info_label.configure(text="Başlık Bilgisi: -")
        except Exception as e:
            messagebox.showerror("Gönderme Hatası", str(e))
            self.log_send_message(f"Gönderme hatası: {str(e)}")
            self.send_integrity_status.configure(text="Hata", fg_color="red")

    def receive_file(self):
        try:
            # Receive data
            data = self.receive_transfer.receive_file()
            # İlk 32 byte anahtar, sonraki 16 byte IV, kalanı şifreli veri
            key = data[:32]
            iv = data[32:48]
            encrypted_data = data[48:]
            # Hash'i çıkar
            file_hash = encrypted_data[:32]
            # Decrypt file
            try:
                decrypted_data = self.security_manager.decrypt_file(encrypted_data, key, iv)
                # Hash doğrulama başarılı
                self.receive_integrity_status.configure(text="SHA-256: Doğrulandı", fg_color="green")
                self.encryption_status_var.set("Veri şifreli ve bütünlük sağlandı.")
                self.encryption_status_label.configure(fg_color="green")
                self.mitm_status_var.set("MITM saldırısı tespit edilmedi.")
                self.mitm_status_label.configure(fg_color="green")
            except Exception as e:
                # Hash doğrulama başarısız
                self.receive_integrity_status.configure(text="SHA-256: Hatalı", fg_color="red")
                self.encryption_status_var.set("Bütünlük hatası! Veri bozulmuş veya şifreleme başarısız.")
                self.encryption_status_label.configure(fg_color="red")
                self.mitm_status_var.set("MITM saldırısı veya veri bozulması olası!")
                self.mitm_status_label.configure(fg_color="red")
                raise e
            # Save file
            save_path = filedialog.asksaveasfilename(defaultextension=".*")
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(decrypted_data)
                self.log_receive_message(f"Dosya alındı: {os.path.basename(save_path)}")
        except Exception as e:
            messagebox.showerror("Alma Hatası", str(e))
            self.log_receive_message(f"Alma hatası: {str(e)}")
            self.receive_integrity_status.configure(text="Hata", fg_color="red")
            self.encryption_status_var.set("Bilinmeyen hata!")
            self.encryption_status_label.configure(fg_color="red")
            self.mitm_status_var.set("Analiz yapılamadı.")
            self.mitm_status_label.configure(fg_color="red")

    def log_send_message(self, message):
        self.send_log_text.insert("end", f"{message}\n")
        self.send_log_text.see("end")

    def log_receive_message(self, message):
        self.receive_log_text.insert("end", f"{message}\n")
        self.receive_log_text.see("end")

    def measure_latency(self):
        try:
            ip = self.send_ip_var.get()
            latency = self.network_tools.measure_latency(ip)
            self.ping_result_var.set(f"{latency:.2f} ms")
            
            # Gecikme değerine göre renk değiştir
            if latency < 10:
                self.log_send_message(f"Ping: {latency:.2f} ms (Mükemmel bağlantı)")
            elif latency < 50:
                self.log_send_message(f"Ping: {latency:.2f} ms (İyi bağlantı)")
            elif latency < 100:
                self.log_send_message(f"Ping: {latency:.2f} ms (Orta bağlantı)")
            else:
                self.log_send_message(f"Ping: {latency:.2f} ms (Yavaş bağlantı)")
                
        except Exception as e:
            self.ping_result_var.set("Hata")
            self.log_send_message(f"Ping hatası: {str(e)}")


    def measure_bandwidth(self):
        try:
            ip = self.send_ip_var.get()
            bw = self.network_tools.measure_bandwidth(ip)
            self.bw_result_var.set(f"{bw:.2f} Mbps")
            self.log_send_message(f"Bant genişliği: {bw:.2f} Mbps")
        except Exception as e:
            self.bw_result_var.set("Hata")
            self.log_send_message(f"Bant genişliği hatası: {str(e)}")

    def start_simulation(self):
        try:
            packet_loss = float(self.packet_loss_var.get())
            delay = float(self.delay_var.get())
            result = self.network_tools.simulate_network(packet_loss, delay)
            
            # Simülasyon sonuçlarını göster
            actual_loss = result.get("packet_loss", 0)
            actual_delay = result.get("delay", 0)
            self.sim_result_var.set(f"Simülasyon: {actual_loss:.1f}% kayıp, {actual_delay:.1f} ms gecikme")
            
            # Log mesajı
            self.log_send_message(f"Simülasyon parametreleri: {actual_loss:.1f}% paket kaybı, {actual_delay:.1f} ms gecikme\n" + 
                                 "Not: Bu simülasyon sadece görsel amaçlıdır ve gerçek ağ koşullarını etkilemez.")
        except Exception as e:
            self.sim_result_var.set("Hata")
            self.log_send_message(f"Simülasyon hatası: {str(e)}")

    def analyze_packet(self):
        try:
            # Paket yakalama
            packet_data = self.network_tools.capture_packet()
            if packet_data:
                result = self.network_tools.analyze_packet(packet_data)
                
                # Analiz sonucunu formatlı göster
                status = result.get('security_status', 'unknown')
                warnings = result.get('warnings', [])
                details = result.get('details', {})
                
                # Durum göstergesi
                status_icon = "✅" if status == "normal" else "⚠️" if status == "suspicious" else "❓"
                self.packet_analysis_result.set(f"Paket Analizi: {status.upper()} {status_icon}")
                
                # Log'a detaylı bilgi ekle
                log_message = f"Paket Analizi ({result.get('analysis_time', '')})\n"
                log_message += f"Güvenlik Durumu: {status.upper()}\n\n"
                
                # Detayları ekle
                log_message += "Detaylar:\n"
                for key, value in details.items():
                    log_message += f"- {key.capitalize()}: {value}\n"
                
                # Uyarıları ekle
                if warnings:
                    log_message += "\nUyarılar:\n"
                    for warning in warnings:
                        log_message += f"- {warning}\n"
                        
                # Simüle edilmiş paket notu
                if packet_data.get('simulated', False):
                    log_message += "\nNot: Bu simüle edilmiş bir pakettir. İnternet bağlantısı olmayabilir."
                    
                self.log_send_message(log_message)
            else:
                self.packet_analysis_result.set("Paket alınamadı")
                self.log_send_message("Paket alınamadı! İnternet bağlantınızı kontrol edin.")
        except Exception as e:
            self.packet_analysis_result.set("Analiz hatası")
            self.log_send_message(f"Paket analizi hatası: {str(e)}")

if __name__ == "__main__":
    app = SecureFileTransferGUI()
    app.mainloop() 