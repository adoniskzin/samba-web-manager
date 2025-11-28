 # 🗂️ Samba Web Manager

Modern, kullanıcı dostu web tabanlı Samba yönetim paneli. Flask ile geliştirilmiş, responsive tasarıma sahip.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)

## ✨ Özellikler

### 🔐 Kullanıcı Yönetimi
- ✅ Kullanıcı oluşturma/silme
- ✅ Şifre yönetimi (kullanıcı ve admin)
- ✅ Admin/Normal kullanıcı rolleri
- ✅ Güvenli oturum yönetimi

### 📁 Paylaşım Yönetimi
- ✅ Kolay paylaşım oluşturma (dizin ağacı ile)
- ✅ Paylaşım düzenleme ve silme
- ✅ Otomatik Samba konfigürasyonu
- ✅ Gerçek zamanlı disk kullanım takibi

### 📂 Dosya Yönetimi
- ✅ Web üzerinden dosya yükleme/indirme
- ✅ Metin dosyası düzenleme (txt, py, sh, conf vb.)
- ✅ Klasör oluşturma ve silme
- ✅ Breadcrumb navigasyon
- ✅ İzin bazlı erişim kontrolü

### 🎨 Kullanıcı Arayüzü
- ✅ Modern ve responsive tasarım
- ✅ Koyu tema desteği
- ✅ Modal popup'lar
- ✅ Gerçek zamanlı bildirimler
- ✅ Mobil uyumlu

### ⚙️ Sistem
- ✅ Systemd servisi (otomatik başlatma)
- ✅ Detaylı loglama
- ✅ Hata yönetimi
- ✅ Güvenli dosya işlemleri

## 📋 Gereksinimler

### Sistem Gereksinimleri
- Ubuntu/Debian tabanlı Linux dağıtımı
- Python 3.8 veya üzeri
- Samba kurulu olmalı
- Root/sudo erişimi

### Python Paketleri
- Flask
- Werkzeug

## 🚀 Kurulum

### 1. Sistem Güncellemesi
sudo apt update && sudo apt upgrade -y

### 2. Gerekli Paketleri Yükle
sudo apt install -y python3 python3-pip python3-venv samba samba-common-bin

### 3. Projeyi İndir
cd /opt
sudo git clone https://github.com/adoniskzin/samba-web-manager.git
cd samba-web-manager

### 4. Kurulum Scriptini Çalıştır
sudo chmod +x install.sh
sudo ./install.sh

Kurulum scripti otomatik olarak:
- Python sanal ortamı oluşturur
- Gerekli paketleri yükler
- Systemd servisi kurar
- Varsayılan admin kullanıcısı oluşturur

### 5. Servisi Başlat
sudo systemctl start samba-manager
sudo systemctl enable samba-manager

### 6. Durumu Kontrol Et
sudo systemctl status samba-manager

## 🌐 Kullanım

### Web Paneline Erişim
http://SUNUCU_IP:5000

### Varsayılan Giriş Bilgileri
Kullanıcı Adı: admin
Şifre: admin123

⚠️ **Güvenlik**: İlk girişten sonra mutlaka şifrenizi değiştirin!

## 📖 Kullanım Kılavuzu

### Admin Kullanıcı

1. **Kullanıcı Oluşturma**
   - "Kullanıcılar" sekmesine gidin
   - "+ Yeni Kullanıcı" butonuna tıklayın
   - Kullanıcı adı ve şifre belirleyin
   - Admin yetkisi vermek isterseniz checkbox'ı işaretleyin

2. **Paylaşım Oluşturma**
   - "Paylaşımlar" sekmesine gidin
   - "+ Yeni Paylaşım" butonuna tıklayın
   - Paylaşım adı girin (boşluk kullanmayın!)
   - Dizin ağacından klasör seçin
   - Oluştur'a tıklayın

3. **İzin Verme**
   - "İzinler" sekmesine gidin
   - Paylaşım ve kullanıcı seçin
   - İzin tipini belirleyin (Okuma/Yazma)
   - "İzin Ayarla" butonuna tıklayın

### Normal Kullanıcı

1. **Dosya Yükleme**
   - "Dosyalarım" sekmesine gidin
   - Paylaşım seçin
   - Yükleme alanına tıklayın veya dosya sürükleyin

2. **Dosya Düzenleme**
   - Düzenlenebilir dosyalarda "✏️ Düzenle" butonu görünür
   - Dosyayı düzenleyin
   - "💾 Kaydet" ile kaydedin

3. **Klasör Oluşturma**
   - "+ Yeni Klasör" butonuna tıklayın
   - Klasör adı girin
   - Oluştur'a tıklayın

## 🔧 Yapılandırma

### Port Değiştirme
/opt/samba-manager/app.py dosyasını düzenleyin ve son satırı değiştirin.

Servisi yeniden başlatın:
sudo systemctl restart samba-manager

### Güvenlik Duvarı
sudo ufw allow 5000/tcp
sudo ufw allow 139/tcp
sudo ufw allow 445/tcp

## 📁 Dizin Yapısı
/opt/samba-manager/
├── app.py                 # Ana uygulama
├── templates/
│   ├── index.html        # Ana sayfa
│   └── login.html        # Giriş sayfası
├── data/                 # Kullanıcı verileri
│   ├── users.json
│   ├── shares.json
│   ├── permissions.json
│   └── logs.json
├── venv/                 # Python sanal ortamı
├── README.md
├── LICENSE
└── .gitignore

## 🛠️ Sorun Giderme

### Servis Başlamıyor
sudo journalctl -u samba-manager -n 50
cd /opt/samba-manager
sudo venv/bin/python app.py

### Samba Çalışmıyor
sudo systemctl status smbd
sudo systemctl restart smbd
testparm

### Port 5000 Kullanımda
sudo lsof -i :5000
sudo kill -9 PID

### İzin Sorunları
sudo chown -R root:root /opt/samba-manager/data
sudo chmod -R 755 /opt/samba-manager/data

## 🔄 Güncelleme
cd /opt/samba-manager
sudo git pull
sudo systemctl restart samba-manager

## 🗑️ Kaldırma
sudo systemctl stop samba-manager
sudo systemctl disable samba-manager
sudo rm /etc/systemd/system/samba-manager.service
sudo systemctl daemon-reload
sudo rm -rf /opt/samba-manager

## 🤝 Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun
3. Commit edin
4. Push edin
5. Pull Request açın

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için LICENSE dosyasına bakın.

## 👨‍💻 Geliştirici

Developed with **Claude Sonnet 4.5** via Monica AI

Community Driven Project

## 🙏 Teşekkürler

- Flask Framework
- Samba Team
- Tüm katkıda bulunanlara

## 📞 İletişim

- GitHub Issues: Sorun Bildir
- Discussions: Tartışmalar

---

⭐ Projeyi beğendiyseniz yıldız vermeyi unutmayın!
EOFREADME
