import subprocess
import sys
import os
import customtkinter as ctk
from gui import SecureFileTransferGUI

def start_server():
    python_exe = sys.executable
    server_path = os.path.join(os.path.dirname(__file__), "server.py")
    # Windows için yeni konsolda başlat
    subprocess.Popen([python_exe, server_path], creationflags=subprocess.CREATE_NEW_CONSOLE)

def main():
    start_server()  # Sunucuyu başlat
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = SecureFileTransferGUI()
    app.title("Güvenli Dosya Transfer Sistemi")
    app.geometry("1200x800")
    app.mainloop()

if __name__ == "__main__":
    main() 