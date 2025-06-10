# Güvenli Dosya Transfer Sistemi

Bu uygulama, güvenli dosya transferi için geliştirilmiş bir GUI tabanlı sistemdir. AES şifreleme, SHA-256 bütünlük kontrolü ve gelişmiş ağ özellikleri içerir.

## Özellikler

- 🔐 AES-256 şifreleme
- 🔒 SHA-256 bütünlük kontrolü
- 📤 Dosya parçalama ve birleştirme
- 📊 Ağ performans ölçümü
- 🛡️ IP başlık manipülasyonu
- 📈 Bant genişliği testi
- 🔍 Paket analizi

## Gereksinimler

- Python 3.8 veya üzeri
- Windows 10 veya Linux
- Yönetici/root izinleri (ağ simülasyonu için)

## Kurulum

1. Gerekli Python paketlerini yükleyin:
```bash
pip install -r requirements.txt
```

2. Windows için ek gereksinimler:
- iperf3 (https://iperf.fr/iperf-download.php)
- Npcap (https://npcap.com/#download)

3. Linux için ek gereksinimler:
```bash
sudo apt-get install iperf3
sudo apt-get install tc
```

## Kullanım

1. Uygulamayı başlatın:
```bash
python main.py
```

2. Arayüz üzerinden:
   - Dosya seçin
   - IP adresi ve port girin
   - "Bağlan" butonuna tıklayın
   - Dosyayı gönderin veya alın

## Güvenlik Özellikleri

- AES-256 şifreleme ile dosya güvenliği
- SHA-256 hash ile bütünlük kontrolü
- IP başlık manipülasyonu koruması
- Paket analizi ve güvenlik uyarıları

## Ağ Özellikleri

- Ping testi ile gecikme ölçümü
- iperf3 ile bant genişliği testi
- Paket kaybı ve gecikme simülasyonu
- IP başlık analizi

## Notlar

- Ağ simülasyonu için yönetici/root izinleri gereklidir
- Windows'ta netsh, Linux'ta tc komutları kullanılır
- iperf3 testleri için hedef makinede iperf3 sunucusu çalışmalıdır

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. 