#!/bin/bash

# Samba Web Manager Kurulum Scripti
# MIT License

set -e

echo "=================================="
echo "Samba Web Manager Kurulum"
echo "=================================="
echo ""

# Root kontrolü
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Bu scripti root olarak çalıştırmalısınız (sudo ./install.sh)"
    exit 1
fi

# Sistem güncellemesi
echo "📦 Sistem güncelleniyor..."
apt update

# Gerekli paketleri yükle
echo "📦 Gerekli paketler yükleniyor..."
apt install -y python3 python3-pip python3-venv samba samba-common-bin

# Python sanal ortamı oluştur
echo "🐍 Python sanal ortamı oluşturuluyor..."
python3 -m venv venv

# Paketleri yükle
echo "📦 Python paketleri yükleniyor..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install flask werkzeug

# Data klasörü oluştur
echo "📁 Data klasörü oluşturuluyor..."
mkdir -p data

# Systemd servisi oluştur
echo "⚙️  Systemd servisi oluşturuluyor..."
cat > /etc/systemd/system/samba-manager.service << 'EOFSERVICE'
[Unit]
Description=Samba Web Manager
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/samba-manager
Environment="PATH=/opt/samba-manager/venv/bin"
ExecStart=/opt/samba-manager/venv/bin/python /opt/samba-manager/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOFSERVICE

# Systemd'yi yeniden yükle
systemctl daemon-reload

# Servisi başlat ve etkinleştir
echo "🚀 Servis başlatılıyor..."
systemctl start samba-manager
systemctl enable samba-manager

# Samba'yı başlat
echo "🗂️  Samba başlatılıyor..."
systemctl start smbd
systemctl enable smbd

# Sudoers yapılandırması
echo "🔐 Sudo izinleri yapılandırılıyor..."
if ! grep -q "samba-manager" /etc/sudoers; then
    cat >> /etc/sudoers << 'EOFSUDOERS'

# Samba Web Manager
root ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart smbd
root ALL=(ALL) NOPASSWD: /usr/bin/systemctl status smbd
root ALL=(ALL) NOPASSWD: /usr/bin/smbpasswd
root ALL=(ALL) NOPASSWD: /usr/sbin/useradd
root ALL=(ALL) NOPASSWD: /usr/sbin/userdel
root ALL=(ALL) NOPASSWD: /usr/bin/chown
root ALL=(ALL) NOPASSWD: /usr/bin/chmod
root ALL=(ALL) NOPASSWD: /usr/bin/mkdir
root ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/samba/smb.conf
EOFSUDOERS
fi

# IP adresini al
IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=================================="
echo "✅ Kurulum Tamamlandı!"
echo "=================================="
echo ""
echo "🌐 Web Paneli: http://$IP:5000"
echo ""
echo "🔐 Varsayılan Giriş:"
echo "   Kullanıcı: admin"
echo "   Şifre: admin123"
echo ""
echo "⚠️  İlk girişten sonra şifrenizi değiştirin!"
echo ""
echo "📊 Servis Durumu:"
systemctl status samba-manager --no-pager
echo ""
echo "🛠️  Yararlı Komutlar:"
echo "   sudo systemctl status samba-manager  # Durum"
echo "   sudo systemctl restart samba-manager # Yeniden başlat"
echo "   sudo systemctl stop samba-manager    # Durdur"
echo "   sudo journalctl -u samba-manager -f  # Logları izle"
echo ""
