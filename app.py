from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from functools import wraps
import json
import subprocess
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import shutil
import logging
import re

app = Flask(__name__)
app.secret_key = 'samba-manager-secret-key-change-this-in-production'
app.config['VERSION'] = '1.0.0'

DATA_DIR = '/opt/samba-manager/data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
SHARES_FILE = os.path.join(DATA_DIR, 'shares.json')
PERMISSIONS_FILE = os.path.join(DATA_DIR, 'permissions.json')
LOGS_FILE = os.path.join(DATA_DIR, 'logs.json')

# Düzenlenebilir dosya uzantıları
EDITABLE_EXTENSIONS = {'.txt', '.py', '.sh', '.conf', '.cfg', '.ini', '.json', '.xml', '.yaml', '.yml', 
                       '.md', '.log', '.html', '.css', '.js', '.php', '.sql', '.env', '.htaccess'}

os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(DATA_DIR, 'app.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def load_json(filepath, default=None):
    if default is None:
        default = {}
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def save_json(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def add_log(action, user, details=''):
    logs = load_json(LOGS_FILE, [])
    logs.append({
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'user': user,
        'details': details
    })
    if len(logs) > 1000:
        logs = logs[-1000:]
    save_json(LOGS_FILE, logs)
    logging.info(f"{user} - {action} - {details}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Oturum gerekli'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Oturum gerekli'}), 401
        if not session.get('is_admin', False):
            return jsonify({'error': 'Yönetici yetkisi gerekli'}), 403
        return f(*args, **kwargs)
    return decorated_function

def get_file_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def get_disk_usage(path):
    try:
        stat = os.statvfs(path)
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free
        return {
            'total': get_file_size(total),
            'used': get_file_size(used),
            'free': get_file_size(free),
            'percent': round((used / total) * 100, 1) if total > 0 else 0
        }
    except:
        return None

def run_command(cmd):
    """Komut çalıştır ve sonucu döndür"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr
    except FileNotFoundError:
        return False, "Komut bulunamadı"

def validate_share_name(name):
    """Paylaşım adını doğrula - boşluk ve özel karakterler yasak"""
    if not name:
        return False, "Paylaşım adı boş olamaz"
    if ' ' in name:
        return False, "Paylaşım adında boşluk kullanılamaz"
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return False, "Paylaşım adı sadece harf, rakam, tire ve alt çizgi içerebilir"
    return True, ""

def update_smb_conf():
    shares = load_json(SHARES_FILE, {})
    permissions = load_json(PERMISSIONS_FILE, {})

    conf_content = """[global]
   workgroup = WORKGROUP
   server string = Samba Server
   security = user
   map to guest = Bad User
   dns proxy = no

"""

    for share_name, share_data in shares.items():
        path = share_data['path']
        conf_content += f"""[{share_name}]
   path = {path}
   browseable = yes
   writable = yes
   guest ok = no
   create mask = 0666
   directory mask = 0777
   force user = nobody
   force group = nogroup
   valid users = """

        valid_users = []
        for username, perms in permissions.get(share_name, {}).items():
            if perms != 'none':
                valid_users.append(username)

        conf_content += " ".join(valid_users) if valid_users else "@nobody"
        conf_content += "\n\n"

    try:
        with open('/etc/samba/smb.conf', 'w') as f:
            f.write(conf_content)
    except PermissionError:
        run_command(['/usr/bin/sudo', 'tee', '/etc/samba/smb.conf'])

def restart_samba():
    run_command(['/usr/bin/sudo', '/usr/bin/systemctl', 'restart', 'smbd'])

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', version=app.config['VERSION'])
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html', version=app.config['VERSION'])

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    users = load_json(USERS_FILE, {})
    
    if username in users and check_password_hash(users[username]['password'], password):
        session['username'] = username
        session['is_admin'] = users[username].get('is_admin', False)
        add_log('Giriş', username, 'Başarılı giriş')
        return jsonify({
            'message': 'Giriş başarılı', 
            'is_admin': session['is_admin'],
            'username': username
        }), 200
    
    add_log('Giriş', username or 'Bilinmeyen', 'Başarısız giriş denemesi')
    return jsonify({'error': 'Kullanıcı adı veya şifre hatalı'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    username = session.get('username', 'Bilinmeyen')
    add_log('Çıkış', username, 'Oturum kapatıldı')
    session.clear()
    return jsonify({'message': 'Çıkış yapıldı'}), 200

@app.route('/api/me', methods=['GET'])
@login_required
def get_me():
    return jsonify({
        'username': session.get('username'),
        'is_admin': session.get('is_admin', False)
    }), 200

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not old_password or not new_password:
        return jsonify({'error': 'Eski ve yeni şifre gerekli'}), 400
    
    users = load_json(USERS_FILE, {})
    username = session['username']
    
    if not check_password_hash(users[username]['password'], old_password):
        return jsonify({'error': 'Eski şifre hatalı'}), 401
    
    users[username]['password'] = generate_password_hash(new_password)
    save_json(USERS_FILE, users)
    
    process = subprocess.Popen(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-a', username], 
                              stdin=subprocess.PIPE, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
    process.communicate(input=f'{new_password}\n{new_password}\n'.encode())
    run_command(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-e', username])
    
    add_log('Şifre Değişikliği', username, 'Şifre başarıyla değiştirildi')
    return jsonify({'message': 'Şifre değiştirildi'}), 200

@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    users = load_json(USERS_FILE, {})
    user_list = []
    for username, user_data in users.items():
        user_list.append({
            'username': username,
            'is_admin': user_data.get('is_admin', False),
            'created': user_data.get('created', '')
        })
    return jsonify(user_list), 200

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    
    if not username or not password:
        return jsonify({'error': 'Kullanıcı adı ve şifre gerekli'}), 400
    
    users = load_json(USERS_FILE, {})
    
    if username in users:
        return jsonify({'error': 'Bu kullanıcı zaten mevcut'}), 400
    
    users[username] = {
        'password': generate_password_hash(password),
        'is_admin': is_admin,
        'created': datetime.now().isoformat()
    }
    save_json(USERS_FILE, users)
    
    run_command(['/usr/bin/sudo', '/usr/sbin/useradd', '-M', '-s', '/sbin/nologin', username])
    
    process = subprocess.Popen(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-a', username], 
                              stdin=subprocess.PIPE, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
    process.communicate(input=f'{password}\n{password}\n'.encode())
    run_command(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-e', username])
    
    add_log('Kullanıcı Oluşturma', session['username'], f'{username} kullanıcısı oluşturuldu')
    return jsonify({'message': 'Kullanıcı oluşturuldu'}), 201

@app.route('/api/users/<username>/password', methods=['POST'])
@admin_required
def change_user_password(username):
    data = request.json
    new_password = data.get('new_password')
    
    if not new_password:
        return jsonify({'error': 'Yeni şifre gerekli'}), 400
    
    users = load_json(USERS_FILE, {})
    
    if username not in users:
        return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
    
    users[username]['password'] = generate_password_hash(new_password)
    save_json(USERS_FILE, users)
    
    process = subprocess.Popen(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-a', username], 
                              stdin=subprocess.PIPE, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
    process.communicate(input=f'{new_password}\n{new_password}\n'.encode())
    run_command(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-e', username])
    
    add_log('Şifre Değişikliği (Admin)', session['username'], f'{username} kullanıcısının şifresi değiştirildi')
    return jsonify({'message': 'Şifre değiştirildi'}), 200

@app.route('/api/users/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    if username == 'admin':
        return jsonify({'error': 'Admin kullanıcısı silinemez'}), 400
    
    users = load_json(USERS_FILE, {})
    
    if username not in users:
        return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
    
    del users[username]
    save_json(USERS_FILE, users)
    
    permissions = load_json(PERMISSIONS_FILE, {})
    for share_name in permissions:
        if username in permissions[share_name]:
            del permissions[share_name][username]
    save_json(PERMISSIONS_FILE, permissions)
    
    run_command(['/usr/bin/sudo', '/usr/bin/smbpasswd', '-x', username])
    run_command(['/usr/bin/sudo', '/usr/sbin/userdel', username])
    
    update_smb_conf()
    restart_samba()
    
    add_log('Kullanıcı Silme', session['username'], f'{username} kullanıcısı silindi')
    return jsonify({'message': 'Kullanıcı silindi'}), 200

@app.route('/api/shares', methods=['GET'])
@login_required
def get_shares():
    shares = load_json(SHARES_FILE, {})
    share_list = []
    for share_name, share_data in shares.items():
        share_list.append({
            'name': share_name,
            'path': share_data['path'],
            'created': share_data.get('created', '')
        })
    return jsonify(share_list), 200

@app.route('/api/directories', methods=['GET'])
@admin_required
def get_directories():
    path = request.args.get('path', '/')
    
    try:
        items = []
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if os.path.isdir(item_path):
                try:
                    has_children = len([x for x in os.listdir(item_path) if os.path.isdir(os.path.join(item_path, x))]) > 0
                except:
                    has_children = False
                items.append({
                    'name': item,
                    'path': item_path,
                    'has_children': has_children
                })
        items.sort(key=lambda x: x['name'].lower())
        return jsonify(items), 200
    except PermissionError:
        return jsonify([]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/shares', methods=['POST'])
@admin_required
def create_share():
    data = request.json
    share_name = data.get('name')
    path = data.get('path')
    
    if not share_name or not path:
        return jsonify({'error': 'Ad ve yol gerekli'}), 400
    
    # Paylaşım adını doğrula
    valid, error_msg = validate_share_name(share_name)
    if not valid:
        return jsonify({'error': error_msg}), 400
    
    shares = load_json(SHARES_FILE, {})
    
    if share_name in shares:
        return jsonify({'error': 'Bu paylaşım zaten mevcut'}), 400
    
    if not os.path.exists(path):
        run_command(['/usr/bin/sudo', '/usr/bin/mkdir', '-p', path])
        run_command(['/usr/bin/sudo', '/usr/bin/chown', '-R', 'nobody:nogroup', path])
        run_command(['/usr/bin/sudo', '/usr/bin/chmod', '-R', '777', path])
    
    shares[share_name] = {
        'path': path,
        'created': datetime.now().isoformat()
    }
    
    save_json(SHARES_FILE, shares)
    update_smb_conf()
    restart_samba()
    
    add_log('Paylaşım Oluşturma', session['username'], f'{share_name} paylaşımı oluşturuldu')
    return jsonify({'message': 'Paylaşım oluşturuldu'}), 201

@app.route('/api/shares/<share_name>', methods=['PUT'])
@admin_required
def update_share(share_name):
    data = request.json
    new_name = data.get('new_name')
    new_path = data.get('new_path')
    
    if not new_name:
        return jsonify({'error': 'Yeni ad gerekli'}), 400
    
    # Yeni adı doğrula
    valid, error_msg = validate_share_name(new_name)
    if not valid:
        return jsonify({'error': error_msg}), 400
    
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Paylaşım bulunamadı'}), 404
    
    if new_name != share_name and new_name in shares:
        return jsonify({'error': 'Bu isimde paylaşım zaten mevcut'}), 400
    
    # Paylaşımı güncelle
    share_data = shares[share_name]
    if new_path:
        share_data['path'] = new_path
    
    if new_name != share_name:
        shares[new_name] = share_data
        del shares[share_name]
        
        # İzinleri de güncelle
        permissions = load_json(PERMISSIONS_FILE, {})
        if share_name in permissions:
            permissions[new_name] = permissions[share_name]
            del permissions[share_name]
            save_json(PERMISSIONS_FILE, permissions)
    else:
        shares[share_name] = share_data
    
    save_json(SHARES_FILE, shares)
    update_smb_conf()
    restart_samba()
    
    add_log('Paylaşım Güncelleme', session['username'], f'{share_name} paylaşımı güncellendi')
    return jsonify({'message': 'Paylaşım güncellendi'}), 200

@app.route('/api/shares/<share_name>', methods=['DELETE'])
@admin_required
def delete_share(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Paylaşım bulunamadı'}), 404
    
    del shares[share_name]
    save_json(SHARES_FILE, shares)
    
    permissions = load_json(PERMISSIONS_FILE, {})
    if share_name in permissions:
        del permissions[share_name]
    save_json(PERMISSIONS_FILE, permissions)
    
    update_smb_conf()
    restart_samba()
    
    add_log('Paylaşım Silme', session['username'], f'{share_name} paylaşımı silindi')
    return jsonify({'message': 'Paylaşım silindi'}), 200

@app.route('/api/permissions', methods=['GET'])
@login_required
def get_permissions():
    permissions = load_json(PERMISSIONS_FILE, {})
    return jsonify(permissions), 200

@app.route('/api/permissions', methods=['POST'])
@admin_required
def set_permission():
    data = request.json
    share_name = data.get('share')
    username = data.get('user')
    permission = data.get('permission')
    
    if not share_name or not username or not permission:
        return jsonify({'error': 'Paylaşım, kullanıcı ve izin gerekli'}), 400
    
    shares = load_json(SHARES_FILE, {})
    users = load_json(USERS_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Paylaşım bulunamadı'}), 404
    
    if username not in users:
        return jsonify({'error': 'Kullanıcı bulunamadı'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    
    if share_name not in permissions:
        permissions[share_name] = {}
    
    if permission == 'none':
        if username in permissions[share_name]:
            del permissions[share_name][username]
    else:
        permissions[share_name][username] = permission
    
    save_json(PERMISSIONS_FILE, permissions)
    update_smb_conf()
    restart_samba()
    
    add_log('İzin Ayarlama', session['username'], f'{username} için {share_name} paylaşımına {permission} izni verildi')
    return jsonify({'message': 'İzin ayarlandı'}), 200

@app.route('/api/my-shares', methods=['GET'])
@login_required
def get_my_shares():
    username = session['username']
    is_admin = session.get('is_admin', False)
    permissions = load_json(PERMISSIONS_FILE, {})
    shares = load_json(SHARES_FILE, {})
    
    my_shares = []
    for share_name, share_data in shares.items():
        if is_admin:
            # Admin tüm paylaşımları görebilir
            my_shares.append({
                'name': share_name,
                'path': share_data['path'],
                'permission': 'write'  # Admin her zaman yazma iznine sahip
            })
        elif username in permissions.get(share_name, {}):
            my_shares.append({
                'name': share_name,
                'path': share_data['path'],
                'permission': permissions[share_name][username]
            })
    
    return jsonify(my_shares), 200

@app.route('/api/files/<share_name>', methods=['GET'])
@login_required
def list_files(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Paylaşım bulunamadı'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if not user_perm and not session.get('is_admin'):
        return jsonify({'error': 'Bu paylaşıma erişim izniniz yok'}), 403
    
    path = shares[share_name]['path']
    subpath = request.args.get('path', '')
    full_path = os.path.join(path, subpath)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Geçersiz yol'}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'Dizin bulunamadı'}), 404
    
    files = []
    try:
        for item in os.listdir(full_path):
            item_path = os.path.join(full_path, item)
            stat = os.stat(item_path)
            
            # Dosya uzantısını kontrol et
            _, ext = os.path.splitext(item)
            is_editable = ext.lower() in EDITABLE_EXTENSIONS and os.path.isfile(item_path)
            
            files.append({
                'name': item,
                'type': 'directory' if os.path.isdir(item_path) else 'file',
                'size': get_file_size(stat.st_size) if os.path.isfile(item_path) else '-',
                'size_bytes': stat.st_size if os.path.isfile(item_path) else 0,
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'editable': is_editable
            })
    except PermissionError:
        return jsonify({'error': 'Dizin okunamadı'}), 403
    
    files.sort(key=lambda x: (x['type'] != 'directory', x['name'].lower()))
    
    return jsonify({
        'files': files,
        'current_path': subpath,
        'can_write': user_perm == 'write' or session.get('is_admin')
    }), 200

@app.route('/api/files/<share_name>/read', methods=['POST'])
@login_required
def read_file(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Paylaşım bulunamadı'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if not user_perm and not session.get('is_admin'):
        return jsonify({'error': 'Bu paylaşıma erişim izniniz yok'}), 403
    
    data = request.json
    file_path = data.get('path', '')
    
    path = shares[share_name]['path']
    full_path = os.path.join(path, file_path)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Geçersiz yol'}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'Dosya bulunamadı'}), 404
    
    if os.path.isdir(full_path):
        return jsonify({'error': 'Klasör okunamaz'}), 400
    
    # Dosya boyutu kontrolü (max 1MB)
    if os.path.getsize(full_path) > 1024 * 1024:
        return jsonify({'error': 'Dosya çok büyük (max 1MB)'}), 400
    
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        add_log('Dosya Okuma', session['username'], f'{share_name}/{file_path} okundu')
        return jsonify({'content': content}), 200
    except UnicodeDecodeError:
        return jsonify({'error': 'Dosya metin formatında değil'}), 400
    except Exception as e:
        return jsonify({'error': f'Dosya okunamadı: {str(e)}'}), 500

@app.route('/api/files/<share_name>/write', methods=['POST'])
@login_required
def write_file(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Paylaşım bulunamadı'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if user_perm != 'write' and not session.get('is_admin'):
        return jsonify({'error': 'Yazma izniniz yok'}), 403
    
    data = request.json
    file_path = data.get('path', '')
    content = data.get('content', '')
    
    path = shares[share_name]['path']
    full_path = os.path.join(path, file_path)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Geçersiz yol'}), 400
    
    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        os.chmod(full_path, 0o666)
        run_command(['/usr/bin/sudo', '/usr/bin/chown', 'nobody:nogroup', full_path])
        
        add_log('Dosya Yazma', session['username'], f'{share_name}/{file_path} kaydedildi')
        return jsonify({'message': 'Dosya kaydedildi'}), 200
    except Exception as e:
        return jsonify({'error': f'Dosya kaydedilemedi: {str(e)}'}), 500

@app.route('/api/files/<share_name>/download', methods=['GET'])
@login_required
def download_file(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Paylaşım bulunamadı'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if not user_perm and not session.get('is_admin'):
        return jsonify({'error': 'Bu paylaşıma erişim izniniz yok'}), 403
    
    path = shares[share_name]['path']
    file_path = request.args.get('path', '')
    full_path = os.path.join(path, file_path)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Geçersiz yol'}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'Dosya bulunamadı'}), 404
    
    if os.path.isdir(full_path):
        return jsonify({'error': 'Klasör indirilemez'}), 400
    
    add_log('Dosya İndirme', session['username'], f'{share_name}/{file_path} indirildi')
    return send_file(full_path, as_attachment=True, download_name=os.path.basename(full_path))

@app.route('/api/files/<share_name>/upload', methods=['POST'])
@login_required
def upload_file(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Paylaşım bulunamadı'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if user_perm != 'write' and not session.get('is_admin'):
        return jsonify({'error': 'Yazma izniniz yok'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'Dosya seçilmedi'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Dosya seçilmedi'}), 400
    
    path = shares[share_name]['path']
    subpath = request.form.get('path', '')
    full_path = os.path.join(path, subpath)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Geçersiz yol'}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'Dizin bulunamadı'}), 404
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(full_path, filename)
    
    try:
        file.save(file_path)
        os.chmod(file_path, 0o666)
        run_command(['/usr/bin/sudo', '/usr/bin/chown', 'nobody:nogroup', file_path])
    except Exception as e:
        return jsonify({'error': f'Dosya yüklenemedi: {str(e)}'}), 500
    
    add_log('Dosya Yükleme', session['username'], f'{share_name}/{subpath}/{filename} yüklendi')
    return jsonify({'message': 'Dosya yüklendi', 'filename': filename}), 201

@app.route('/api/files/<share_name>/delete', methods=['POST'])
@login_required
def delete_file(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Paylaşım bulunamadı'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if user_perm != 'write' and not session.get('is_admin'):
        return jsonify({'error': 'Silme izniniz yok'}), 403
    
    data = request.json
    file_path = data.get('path', '')
    
    path = shares[share_name]['path']
    full_path = os.path.join(path, file_path)
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Geçersiz yol'}), 400
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'Dosya/Klasör bulunamadı'}), 404
    
    try:
        if os.path.isdir(full_path):
            shutil.rmtree(full_path)
        else:
            os.remove(full_path)
    except Exception as e:
        return jsonify({'error': f'Silinemedi: {str(e)}'}), 500
    
    add_log('Dosya Silme', session['username'], f'{share_name}/{file_path} silindi')
    return jsonify({'message': 'Silindi'}), 200

@app.route('/api/files/<share_name>/mkdir', methods=['POST'])
@login_required
def create_folder(share_name):
    shares = load_json(SHARES_FILE, {})
    
    if share_name not in shares:
        return jsonify({'error': 'Paylaşım bulunamadı'}), 404
    
    permissions = load_json(PERMISSIONS_FILE, {})
    user_perm = permissions.get(share_name, {}).get(session['username'])
    
    if user_perm != 'write' and not session.get('is_admin'):
        return jsonify({'error': 'Yazma izniniz yok'}), 403
    
    data = request.json
    folder_name = data.get('name', '')
    current_path = data.get('path', '')
    
    if not folder_name:
        return jsonify({'error': 'Klasör adı gerekli'}), 400
    
    path = shares[share_name]['path']
    full_path = os.path.join(path, current_path, secure_filename(folder_name))
    
    if not os.path.abspath(full_path).startswith(os.path.abspath(path)):
        return jsonify({'error': 'Geçersiz yol'}), 400
    
    if os.path.exists(full_path):
        return jsonify({'error': 'Bu isimde klasör zaten var'}), 400
    
    try:
        os.makedirs(full_path, mode=0o777)
        run_command(['/usr/bin/sudo', '/usr/bin/chown', 'nobody:nogroup', full_path])
    except Exception as e:
        return jsonify({'error': f'Klasör oluşturulamadı: {str(e)}'}), 500
    
    add_log('Klasör Oluşturma', session['username'], f'{share_name}/{current_path}/{folder_name} oluşturuldu')
    return jsonify({'message': 'Klasör oluşturuldu'}), 201

@app.route('/api/status', methods=['GET'])
@login_required
def get_status():
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'is-active', 'smbd'], 
                              capture_output=True, text=True)
        samba_status = result.stdout.strip()
    except:
        samba_status = 'unknown'
    
    shares = load_json(SHARES_FILE, {})
    disk_info = {}
    for share_name, share_data in shares.items():
        usage = get_disk_usage(share_data['path'])
        if usage:
            disk_info[share_name] = usage
    
    return jsonify({
        'samba': samba_status,
        'users_count': len(load_json(USERS_FILE, {})),
        'shares_count': len(load_json(SHARES_FILE, {})),
        'disk_usage': disk_info
    }), 200

@app.route('/api/logs', methods=['GET'])
@admin_required
def get_logs():
    logs = load_json(LOGS_FILE, [])
    limit = int(request.args.get('limit', 100))
    return jsonify(logs[-limit:]), 200

def init_admin():
    users = load_json(USERS_FILE, {})
    if 'admin' not in users:
        users['admin'] = {
            'password': generate_password_hash('admin123'),
            'is_admin': True,
            'created': datetime.now().isoformat()
        }
        save_json(USERS_FILE, users)
        print("Admin kullanıcısı oluşturuldu: admin / admin123")

if __name__ == '__main__':
    init_admin()
    app.run(host='0.0.0.0', port=5000, debug=False)
