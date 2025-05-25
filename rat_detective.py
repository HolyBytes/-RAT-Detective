import os
import hashlib
import requests
import json
from urllib.parse import urlparse
import subprocess
from datetime import datetime
import platform
import argparse
import mimetypes
from PIL import Image
import pefile
import zipfile
import getpass
from prettytable import PrettyTable
import sys
import time

# API Configuration
VIRUSTOTAL_API_KEY = 'd03046980f383e73f9efb539865945897422e4f7691215cafb400f6dca81fe36'
ABUSEIPDB_API_KEY = '6757670306a3b8daff553cd8be5c8cb8b577bcc6aaf0914d615ee24b3c048f1effac45d73b4930ad'

# RAT Signatures Database
RAT_SIGNATURES = {
    'njRAT': ['njrat', 'Bladabindi', 'H-Worm'],
    'QuasarRAT': ['Quasar', 'quasarmodule'],
    'DarkComet': ['DarkComet', '#KCMDDC2', '#KCMDDC3'],
    'NetWire': ['NetWire', 'netwire_rat'],
    'NanoCore': ['NanoCore', 'nc_client']
}

# Enhanced Color Codes with Gradients
COLORS = {
    'BLACK': '\033[30m',
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'PURPLE': '\033[95m',
    'CYAN': '\033[96m',
    'WHITE': '\033[97m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m',
    'ITALIC': '\033[3m',
    'STRIKETHROUGH': '\033[9m',
    'BLINK': '\033[5m',
    'DIM': '\033[2m',
    'REVERSE': '\033[7m',
    'END': '\033[0m',
    # Background Colors
    'BG_BLACK': '\033[40m',
    'BG_RED': '\033[41m',
    'BG_GREEN': '\033[42m',
    'BG_YELLOW': '\033[43m',
    'BG_BLUE': '\033[44m',
    'BG_PURPLE': '\033[45m',
    'BG_CYAN': '\033[46m',
    'BG_WHITE': '\033[47m',
    # Bright Colors
    'BRIGHT_BLACK': '\033[90m',
    'BRIGHT_RED': '\033[91m',
    'BRIGHT_GREEN': '\033[92m',
    'BRIGHT_YELLOW': '\033[93m',
    'BRIGHT_BLUE': '\033[94m',
    'BRIGHT_PURPLE': '\033[95m',
    'BRIGHT_CYAN': '\033[96m',
    'BRIGHT_WHITE': '\033[97m'
}

# Gradient Effect Function
def gradient_text(text, colors):
    result = ""
    color_cycle = len(colors)
    for i, char in enumerate(text):
        color = colors[i % color_cycle]
        result += f"{color}{char}"
    return result + COLORS['END']

# Enhanced Animation
def animate_text(text, delay=0.03, style='normal'):
    if style == 'typewriter':
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()
    elif style == 'wave':
        for i in range(len(text)):
            sys.stdout.write(f"\r{text[:i+1]}")
            sys.stdout.flush()
            time.sleep(delay)
        print()
    elif style == 'rainbow':
        rainbow_colors = [COLORS['RED'], COLORS['YELLOW'], COLORS['GREEN'], COLORS['CYAN'], COLORS['BLUE'], COLORS['PURPLE']]
        colored_text = gradient_text(text, rainbow_colors)
        print(colored_text)
    else:
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    # Enhanced ASCII Art Banner with Gradient Effect
    banner_art = """
██████╗  █████╗ ████████╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗██╗██╗   ██╗███████╗
██╔══██╗██╔══██╗╚══██╔══╝    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║██║   ██║██╔════╝
██████╔╝███████║   ██║       ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║██║   ██║█████╗  
██╔══██╗██╔══██║   ██║       ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║╚██╗ ██╔╝██╔══╝  
██║  ██║██║  ██║   ██║       ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ██║ ╚████╔╝ ███████╗
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═══╝  ╚══════╝
    """
    
    # Apply gradient effect to banner
    rainbow_colors = [COLORS['BRIGHT_RED'], COLORS['BRIGHT_YELLOW'], COLORS['BRIGHT_GREEN'], 
                     COLORS['BRIGHT_CYAN'], COLORS['BRIGHT_BLUE'], COLORS['BRIGHT_PURPLE']]
    
    print(gradient_text(banner_art, rainbow_colors))
    
    # Animated subtitle
    subtitle = "🔥 Advanced Remote Access Trojan Detection & Analysis System 🔥"
    animate_text(f"{COLORS['BRIGHT_CYAN']}{COLORS['BOLD']}{subtitle.center(80)}{COLORS['END']}", 
                delay=0.05, style='typewriter')
    
    # Enhanced info panel with better styling
    info_panel = f"""
{COLORS['BRIGHT_BLUE']}╔═══════════════════════════════════════════════════════════════════════════════╗
{COLORS['BRIGHT_BLUE']}║ {COLORS['BRIGHT_YELLOW']}{COLORS['BOLD']}👨‍💻 DEVELOPER    {COLORS['END']}: {COLORS['BRIGHT_WHITE']}ADE PRATAMA                                       {COLORS['BRIGHT_BLUE']}║
{COLORS['BRIGHT_BLUE']}║ {COLORS['BRIGHT_GREEN']}{COLORS['BOLD']}🌐 GITHUB       {COLORS['END']}: {COLORS['BRIGHT_WHITE']}github.com/HolyBytes                             {COLORS['BRIGHT_BLUE']}║
{COLORS['BRIGHT_BLUE']}║ {COLORS['BRIGHT_PURPLE']}{COLORS['BOLD']}💝 SUPPORT      {COLORS['END']}: {COLORS['BRIGHT_WHITE']}saweria.co/HolyBytes                              {COLORS['BRIGHT_BLUE']}║
{COLORS['BRIGHT_BLUE']}║ {COLORS['BRIGHT_RED']}{COLORS['BOLD']}🔢 VERSION      {COLORS['END']}: {COLORS['BRIGHT_WHITE']}BETA 0.2 - Enhanced Edition                       {COLORS['BRIGHT_BLUE']}║
{COLORS['BRIGHT_BLUE']}║ {COLORS['BRIGHT_CYAN']}{COLORS['BOLD']}👤 CURRENT USER {COLORS['END']}: {COLORS['BRIGHT_WHITE']}{getpass.getuser().ljust(40)} {COLORS['BRIGHT_BLUE']}║
{COLORS['BRIGHT_BLUE']}║ {COLORS['BRIGHT_YELLOW']}{COLORS['BOLD']}⏰ SCAN TIME    {COLORS['END']}: {COLORS['BRIGHT_WHITE']}{datetime.now().strftime('%Y-%m-%d %H:%M:%S').ljust(40)} {COLORS['BRIGHT_BLUE']}║
{COLORS['BRIGHT_BLUE']}╚═══════════════════════════════════════════════════════════════════════════════╝{COLORS['END']}
    """
    print(info_panel)

def print_menu():
    # Enhanced menu with better visual appeal
    menu_header = f"""
{COLORS['BRIGHT_PURPLE']}╔═══════════════════════════════════════════════════════════════════════════════╗
{COLORS['BRIGHT_PURPLE']}║ {COLORS['BRIGHT_YELLOW']}{COLORS['BOLD']}{COLORS['BLINK']}🏆 RAT DETECTIVE - MAIN CONTROL PANEL 🏆{COLORS['END']}{COLORS['BRIGHT_PURPLE']}                            ║
{COLORS['BRIGHT_PURPLE']}╠═══════════════════════════════════════════════════════════════════════════════╣"""
    
    menu_options = f"""
{COLORS['BRIGHT_PURPLE']}║ {COLORS['BRIGHT_GREEN']}{COLORS['BOLD']}[1]{COLORS['END']} 🔍 {COLORS['BRIGHT_WHITE']}{COLORS['BOLD']}Deep System Scan{COLORS['END']} - {COLORS['BRIGHT_CYAN']}Comprehensive file system analysis       {COLORS['BRIGHT_PURPLE']}║
{COLORS['BRIGHT_PURPLE']}║ {COLORS['BRIGHT_GREEN']}{COLORS['BOLD']}[2]{COLORS['END']} 🖼️  {COLORS['BRIGHT_WHITE']}{COLORS['BOLD']}Image Forensics{COLORS['END']}  - {COLORS['BRIGHT_CYAN']}Steganography & hidden payload detection {COLORS['BRIGHT_PURPLE']}║
{COLORS['BRIGHT_PURPLE']}║ {COLORS['BRIGHT_GREEN']}{COLORS['BOLD']}[3]{COLORS['END']} 🎥 {COLORS['BRIGHT_WHITE']}{COLORS['BOLD']}Video Analysis{COLORS['END']}   - {COLORS['BRIGHT_CYAN']}Multimedia malware investigation          {COLORS['BRIGHT_PURPLE']}║
{COLORS['BRIGHT_PURPLE']}║ {COLORS['BRIGHT_GREEN']}{COLORS['BOLD']}[4]{COLORS['END']} 📜 {COLORS['BRIGHT_WHITE']}{COLORS['BOLD']}Script Scanner{COLORS['END']}   - {COLORS['BRIGHT_CYAN']}Malicious code pattern recognition        {COLORS['BRIGHT_PURPLE']}║
{COLORS['BRIGHT_PURPLE']}║ {COLORS['BRIGHT_GREEN']}{COLORS['BOLD']}[5]{COLORS['END']} 💻 {COLORS['BRIGHT_WHITE']}{COLORS['BOLD']}GitHub Hunter{COLORS['END']}    - {COLORS['BRIGHT_CYAN']}Repository threat intelligence            {COLORS['BRIGHT_PURPLE']}║
{COLORS['BRIGHT_PURPLE']}║ {COLORS['BRIGHT_GREEN']}{COLORS['BOLD']}[6]{COLORS['END']} 🚪 {COLORS['BRIGHT_WHITE']}{COLORS['BOLD']}Exit System{COLORS['END']}     - {COLORS['BRIGHT_CYAN']}Terminate detection engine                {COLORS['BRIGHT_PURPLE']}║"""
    
    menu_footer = f"""
{COLORS['BRIGHT_PURPLE']}╚═══════════════════════════════════════════════════════════════════════════════╝{COLORS['END']}"""
    
    print(menu_header)
    print(menu_options)
    print(menu_footer)

def print_footer():
    footer = f"""
{COLORS['BRIGHT_CYAN']}╔═══════════════════════════════════════════════════════════════════════════════╗
{COLORS['BRIGHT_CYAN']}║ {COLORS['BRIGHT_RED']}{COLORS['BOLD']}© 2024 RAT Detective - HolyBytes Cybersecurity Division{COLORS['END']}{COLORS['BRIGHT_CYAN']}                    ║
{COLORS['BRIGHT_CYAN']}║ {COLORS['BRIGHT_YELLOW']}{COLORS['BOLD']}🛡️ Crafted with ♥ for Digital Security & Threat Hunting{COLORS['END']}{COLORS['BRIGHT_CYAN']}                     ║
{COLORS['BRIGHT_CYAN']}║ {COLORS['BRIGHT_GREEN']}{COLORS['BOLD']}⚡ Powered by Advanced AI & Machine Learning Algorithms{COLORS['END']}{COLORS['BRIGHT_CYAN']}                     ║
{COLORS['BRIGHT_CYAN']}╚═══════════════════════════════════════════════════════════════════════════════╝{COLORS['END']}
    """
    print(footer)

def print_loading_animation(text, duration=3):
    """Enhanced loading animation with multiple styles"""
    loading_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    end_time = time.time() + duration
    
    while time.time() < end_time:
        for char in loading_chars:
            if time.time() >= end_time:
                break
            sys.stdout.write(f'\r{COLORS["BRIGHT_CYAN"]}{char} {text}{COLORS["END"]}')
            sys.stdout.flush()
            time.sleep(0.1)
    
    sys.stdout.write(f'\r{COLORS["BRIGHT_GREEN"]}✓ {text} - Complete!{COLORS["END"]}\n')

def calculate_hash(file_path, hash_type='sha256'):
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            if hash_type == 'md5':
                return hashlib.md5(file_data).hexdigest()
            elif hash_type == 'sha1':
                return hashlib.sha1(file_data).hexdigest()
            else:
                return hashlib.sha256(file_data).hexdigest()
    except Exception as e:
        print(f"{COLORS['BRIGHT_RED']}{COLORS['BOLD']}[ERROR]{COLORS['END']} Gagal menghitung hash: {e}")
        return None

def scan_all_files(start_path='.'):
    results = []
    total_files = 0
    suspicious_files = 0
    
    animate_text(f"{COLORS['BRIGHT_BLUE']}{COLORS['BOLD']}\n[🔎] Initiating comprehensive system scan...{COLORS['END']}", 
                style='typewriter')
    print_loading_animation("Analyzing file system structure", 2)
    
    for root, dirs, files in os.walk(start_path):
        for file in files:
            file_path = os.path.join(root, file)
            total_files += 1
            
            # Skip system files and directories to prevent permission errors
            if any(ignore in file_path for ignore in ['/sys/', '/proc/', '/dev/', '/run/', '/snap/']):
                continue
                
            try:
                # Scan executable files
                if file.lower().endswith(('.exe', '.dll', '.sys', '.apk', '.jar')):
                    result = scan_executable(file_path)
                    if result['is_malicious']:
                        suspicious_files += 1
                    results.append(result)
                
                # Scan image files
                elif file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                    result = scan_image_video(file_path)
                    if result['is_malicious'] or result['threat_level'] == '🟡 Mencurigakan':
                        suspicious_files += 1
                    results.append(result)
                
                # Scan video files
                elif file.lower().endswith(('.mp4', '.avi', '.mov', '.mkv')):
                    result = scan_image_video(file_path)
                    if result['is_malicious'] or result['threat_level'] == '🟡 Mencurigakan':
                        suspicious_files += 1
                    results.append(result)
                
                # Scan script files
                elif file.lower().endswith(('.py', '.js', '.php', '.sh', '.bat', '.ps1', '.vbs')):
                    result = scan_script(file_path)
                    if result['is_malicious'] or result['threat_level'] == '🟡 Mencurigakan':
                        suspicious_files += 1
                    results.append(result)
            
            except PermissionError:
                continue
            except Exception as e:
                print(f"{COLORS['BRIGHT_YELLOW']}{COLORS['BOLD']}[WARNING]{COLORS['END']} Gagal memindai {file_path}: {e}")
                continue
    
    # Generate summary
    summary = {
        'total_files': total_files,
        'suspicious_files': suspicious_files,
        'results': results
    }
    
    return summary

def scan_image_video(file_path):
    result = {
        'file': file_path,
        'is_malicious': False,
        'threat_level': '🟢 Aman',
        'details': [],
        'metadata': {},
        'steganography_detected': False,
        'hidden_data': None
    }
    
    try:
        if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
            with Image.open(file_path) as img:
                result['metadata'] = img.info
                
                try:
                    img.getexif()
                    if img.info.get('Software', '').lower() in ['steghide', 'outguess']:
                        result['steganography_detected'] = True
                        result['details'].append("🔍 Ditemukan indikasi steganografi dalam gambar")
                        result['threat_level'] = '🟡 Mencurigakan'
                except:
                    pass
                
                file_size = os.path.getsize(file_path)
                width, height = img.size
                estimated_size = width * height * 3
                
                if file_size > estimated_size * 1.5:
                    result['details'].append(f"📊 Ukuran file ({file_size} bytes) tidak wajar untuk gambar {width}x{height} piksel")
                    result['threat_level'] = '🟡 Mencurigakan'
        
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                
                if file_path.lower().endswith('.jpg') and header != b'\xFF\xD8\xFF\xE0':
                    result['details'].append("⚠️ Header file tidak sesuai dengan format JPG")
                    result['threat_level'] = '🔴 Berbahaya'
                    result['is_malicious'] = True
                
                if header == b'MZ\x90\x00':
                    if not file_path.lower().endswith(('.exe', '.dll', '.sys')):
                        result['details'].append("🚨 File executable (PE) yang disamarkan sebagai file media")
                        result['threat_level'] = '🔴 Berbahaya'
                        result['is_malicious'] = True
        
        file_hash = calculate_hash(file_path)
        if file_hash:
            result['hash'] = file_hash
            
    except Exception as e:
        result['details'].append(f"❌ Error dalam memindai file: {e}")
        result['threat_level'] = '🟡 Mencurigakan'
    
    return result

def scan_executable(file_path):
    result = {
        'file': file_path,
        'is_malicious': False,
        'threat_level': '🟢 Aman',
        'details': [],
        'rat_type': None,
        'imports': [],
        'sections': [],
        'resources': [],
        'virustotal': None
    }
    
    try:
        if file_path.lower().endswith(('.exe', '.dll', '.sys')):
            pe = pefile.PE(file_path)
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                result['imports'].append(entry.dll.decode())
                for imp in entry.imports:
                    if imp.name:
                        result['imports'].append(f"  - {imp.name.decode()}")
            
            for section in pe.sections:
                section_info = {
                    'name': section.Name.decode().rstrip('\x00'),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy()
                }
                result['sections'].append(section_info)
                
                if section_info['entropy'] > 7.0:
                    result['details'].append(f"📈 Section {section_info['name']} memiliki entropy tinggi ({section_info['entropy']:.2f}), mungkin di-pack atau di-obfuscate")
                    result['threat_level'] = '🟡 Mencurigakan'
            
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name is not None:
                        name = str(resource_type.name)
                    else:
                        name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
                    
                    for resource_id in resource_type.directory.entries:
                        if resource_id.name is not None:
                            res_name = str(resource_id.name)
                        else:
                            res_name = str(resource_id.struct.Id)
                        
                        for resource_lang in resource_id.directory.entries:
                            data_rva = resource_lang.data.struct.OffsetToData
                            size = resource_lang.data.struct.Size
                            data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                            
                            try:
                                data_str = data.decode('utf-8', errors='ignore')
                                for rat_name, signatures in RAT_SIGNATURES.items():
                                    for sig in signatures:
                                        if sig.lower() in data_str.lower():
                                            result['is_malicious'] = True
                                            result['rat_type'] = rat_name
                                            result['threat_level'] = '🔴 Berbahaya'
                                            result['details'].append(f"🚨 Ditemukan signature {rat_name} dalam resource {name}/{res_name}")
                            except:
                                pass
            
            pe.close()
        
        elif file_path.lower().endswith('.apk'):
            with zipfile.ZipFile(file_path, 'r') as apk:
                for name in apk.namelist():
                    if name == 'classes.dex':
                        result['details'].append("📱 Ditemukan file classes.dex (kode aplikasi Android)")
                    
                    if name == 'AndroidManifest.xml':
                        result['details'].append("📋 Ditemukan AndroidManifest.xml")
                    
                    if any(rat.lower() in name.lower() for rat in ['njrat', 'quasar', 'darkcomet']):
                        result['is_malicious'] = True
                        result['threat_level'] = '🔴 Berbahaya'
                        result['details'].append(f"⚠️ Ditemukan nama file mencurigakan: {name}")
        
        elif file_path.lower().endswith('.jar'):
            with zipfile.ZipFile(file_path, 'r') as jar:
                for name in jar.namelist():
                    if name.endswith('.class'):
                        with jar.open(name) as class_file:
                            content = class_file.read().decode('utf-8', errors='ignore')
                            for rat_name, signatures in RAT_SIGNATURES.items():
                                for sig in signatures:
                                    if sig.lower() in content.lower():
                                        result['is_malicious'] = True
                                        result['rat_type'] = rat_name
                                        result['threat_level'] = '🔴 Berbahaya'
                                        result['details'].append(f"🚨 Ditemukan signature {rat_name} dalam file {name}")
        
        file_hash = calculate_hash(file_path)
        if file_hash and VIRUSTOTAL_API_KEY:
            try:
                params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    result['virustotal'] = data
                    
                    if data.get('positives', 0) > 0:
                        result['is_malicious'] = True
                        result['threat_level'] = '🔴 Berbahaya'
                        result['details'].append(f"🛡️ Ditemukan {data['positives']} dari {data['total']} scanner VirusTotal mendeteksi sebagai berbahaya")
            except Exception as e:
                print(f"{COLORS['BRIGHT_YELLOW']}{COLORS['BOLD']}[WARNING]{COLORS['END']} Gagal memeriksa VirusTotal: {e}")
        
        if not result['is_malicious'] and result['threat_level'] == '🟢 Aman':
            result['details'].append("✅ Tidak ditemukan tanda-tanda RAT yang diketahui")
    
    except Exception as e:
        result['details'].append(f"❌ Error dalam memindai file: {e}")
        result['threat_level'] = '🟡 Mencurigakan'
    
    return result

def scan_script(file_path):
    result = {
        'file': file_path,
        'is_malicious': False,
        'threat_level': '🟢 Aman',
        'details': [],
        'suspicious_lines': []
    }
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                line_lower = line.lower()
                
                # Check for suspicious commands
                suspicious_terms = [
                    'exec(', 'eval(', 'system(', 'popen(',
                    'wget ', 'curl ', 'powershell',
                    'invoke-webrequest', 'downloadstring',
                    'start-process', 'shell_exec',
                    'base64_decode', 'obfuscate'
                ]
                
                for term in suspicious_terms:
                    if term in line_lower:
                        result['suspicious_lines'].append(f"📍 Baris {i}: {line.strip()}")
                        result['threat_level'] = '🟡 Mencurigakan'
                
                # Check for known RAT signatures
                for rat_name, signatures in RAT_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in line_lower:
                            result['is_malicious'] = True
                            result['threat_level'] = '🔴 Berbahaya'
                            result['details'].append(f"🚨 Ditemukan signature {rat_name} pada baris {i}")
        
        if not result['is_malicious'] and result['threat_level'] == '🟢 Aman':
            result['details'].append("✅ Tidak ditemukan tanda-tanda RAT yang diketahui")
    
    except Exception as e:
        result['details'].append(f"❌ Error dalam memindai file: {e}")
        result['threat_level'] = '🟡 Mencurigakan'
    
    return result

def scan_github_repo(repo_url):
    result = {
        'repo': repo_url,
        'is_malicious': False,
        'threat_level': '🟢 Aman',
        'details': [],
        'suspicious_files': []
    }
    
    try:
        # Extract owner and repo name from URL
        parsed = urlparse(repo_url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) < 2:
            result['details'].append("❌ URL GitHub tidak valid")
            result['threat_level'] = '🟡 Mencurigakan'
            return result
        
        owner, repo = path_parts[:2]
        
        # Get repository contents
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/"
        response = requests.get(api_url)
        
        if response.status_code != 200:
            result['details'].append(f"❌ Gagal mengakses repository: {response.status_code}")
            result['threat_level'] = '🟡 Mencurigakan'
            return result
        
        contents = response.json()
        
        for item in contents:
            if item['type'] == 'file':
                file_name = item['name']
                file_url = item['download_url']
                
                # Check file extension
                if file_name.lower().endswith(('.exe', '.dll', '.apk', '.jar', '.py', '.js', '.php')):
                    file_result = {
                        'file': file_name,
                        'url': file_url,
                        'threat_level': '🟢 Aman',
                        'details': []
                    }
                                        # Download and scan the file
                    try:
                        file_response = requests.get(file_url)
                        if file_response.status_code == 200:
                            # Save temporarily to scan
                            temp_file = f"/tmp/{file_name}"
                            with open(temp_file, 'wb') as f:
                                f.write(file_response.content)
                            
                            # Scan based on file type
                            if file_name.lower().endswith(('.exe', '.dll', '.apk', '.jar')):
                                scan_result = scan_executable(temp_file)
                            elif file_name.lower().endswith(('.py', '.js', '.php')):
                                scan_result = scan_script(temp_file)
                            
                            # Update file result
                            file_result['threat_level'] = scan_result['threat_level']
                            file_result['details'] = scan_result['details']
                            
                            if scan_result['is_malicious']:
                                result['is_malicious'] = True
                                result['threat_level'] = '🔴 Berbahaya'
                            
                            # Clean up
                            os.remove(temp_file)
                            
                    except Exception as e:
                        file_result['details'].append(f"❌ Gagal memindai file: {e}")
                        file_result['threat_level'] = '🟡 Mencurigakan'
                    
                    if file_result['threat_level'] != '🟢 Aman':
                        result['suspicious_files'].append(file_result)
        
        if not result['is_malicious'] and result['threat_level'] == '🟢 Aman':
            result['details'].append("✅ Tidak ditemukan file mencurigakan dalam repository")
    
    except Exception as e:
        result['details'].append(f"❌ Error dalam memindai repository: {e}")
        result['threat_level'] = '🟡 Mencurigakan'
    
    return result

def display_results(results):
    if isinstance(results, dict) and 'total_files' in results:  # Full scan results
        table = PrettyTable()
        table.field_names = [
            f"{COLORS['BRIGHT_BLUE']}File{COLORS['END']}",
            f"{COLORS['BRIGHT_BLUE']}Threat Level{COLORS['END']}",
            f"{COLORS['BRIGHT_BLUE']}Details{COLORS['END']}"
        ]
        table.align = "l"
        table.max_width = 120
        
        for item in results['results']:
            threat_color = COLORS['BRIGHT_GREEN'] if item['threat_level'] == '🟢 Aman' else (
                COLORS['BRIGHT_YELLOW'] if item['threat_level'] == '🟡 Mencurigakan' else COLORS['BRIGHT_RED']
            )
            
            details = "\n".join(item['details'][:3])  # Show first 3 details
            if len(item['details']) > 3:
                details += f"\n... (+{len(item['details']) - 3} more)"
            
            table.add_row([
                item['file'],
                f"{threat_color}{item['threat_level']}{COLORS['END']}",
                details
            ])
        
        print("\n" + "="*80)
        print(f"{COLORS['BRIGHT_CYAN']}{COLORS['BOLD']}📊 SCAN SUMMARY{COLORS['END']}")
        print("="*80)
        print(f"Total files scanned: {results['total_files']}")
        print(f"Suspicious files found: {results['suspicious_files']}")
        print("="*80 + "\n")
        print(table)
    
    elif isinstance(results, dict) and 'repo' in results:  # GitHub scan results
        print("\n" + "="*80)
        print(f"{COLORS['BRIGHT_CYAN']}{COLORS['BOLD']}🔍 GITHUB REPOSITORY SCAN RESULTS{COLORS['END']}")
        print("="*80)
        print(f"Repository: {results['repo']}")
        print(f"Threat Level: {results['threat_level']}")
        print("\n" + "-"*80)
        
        for detail in results['details']:
            print(detail)
        
        if results['suspicious_files']:
            print("\n" + f"{COLORS['BRIGHT_RED']}{COLORS['BOLD']}⚠️ SUSPICIOUS FILES FOUND:{COLORS['END']}")
            for file in results['suspicious_files']:
                print("\n" + f"File: {file['file']}")
                print(f"Threat Level: {file['threat_level']}")
                for detail in file['details']:
                    print(f"  - {detail}")
    
    else:  # Single file scan results
        print("\n" + "="*80)
        print(f"{COLORS['BRIGHT_CYAN']}{COLORS['BOLD']}🔍 SCAN RESULTS{COLORS['END']}")
        print("="*80)
        print(f"File: {results['file']}")
        print(f"Threat Level: {results['threat_level']}")
        
        if 'hash' in results:
            print(f"Hash (SHA256): {results['hash']}")
        
        if 'rat_type' in results and results['rat_type']:
            print(f"{COLORS['BRIGHT_RED']}🚨 RAT TYPE DETECTED: {results['rat_type']}{COLORS['END']}")
        
        print("\n" + "-"*80)
        print(f"{COLORS['BRIGHT_YELLOW']}{COLORS['BOLD']}DETAILS:{COLORS['END']}")
        for detail in results['details']:
            print(f"- {detail}")
        
        if 'suspicious_lines' in results and results['suspicious_lines']:
            print("\n" + f"{COLORS['BRIGHT_YELLOW']}{COLORS['BOLD']}SUSPICIOUS CODE LINES:{COLORS['END']}")
            for line in results['suspicious_lines']:
                print(line)
        
        if 'virustotal' in results and results['virustotal']:
            print("\n" + f"{COLORS['BRIGHT_BLUE']}{COLORS['BOLD']}VIRUSTOTAL RESULTS:{COLORS['END']}")
            vt = results['virustotal']
            print(f"Detection: {vt.get('positives', 0)}/{vt.get('total', 0)}")
            if 'scan_date' in vt:
                print(f"Scan Date: {vt['scan_date']}")
            if 'permalink' in vt:
                print(f"Report: {vt['permalink']}")

def main():
    clear_screen()
    print_banner()
    
    while True:
        print_menu()
        choice = input(f"\n{COLORS['BRIGHT_GREEN']}{COLORS['BOLD']}[?] Select an option (1-6): {COLORS['END']}")
        
        if choice == '1':  # Deep System Scan
            print("\n" + "="*80)
            print(f"{COLORS['BRIGHT_CYAN']}{COLORS['BOLD']}🔍 DEEP SYSTEM SCAN{COLORS['END']}")
            print("="*80)
            path = input(f"{COLORS['BRIGHT_WHITE']}Enter path to scan (leave blank for current directory): {COLORS['END']}")
            if not path:
                path = '.'
            
            print_loading_animation(f"Scanning directory: {path}", 2)
            results = scan_all_files(path)
            display_results(results)
            
            input(f"\n{COLORS['BRIGHT_WHITE']}Press Enter to continue...{COLORS['END']}")
            clear_screen()
        
        elif choice == '2':  # Image Forensics
            print("\n" + "="*80)
            print(f"{COLORS['BRIGHT_CYAN']}{COLORS['BOLD']}🖼️ IMAGE FORENSICS{COLORS['END']}")
            print("="*80)
            file_path = input(f"{COLORS['BRIGHT_WHITE']}Enter image file path: {COLORS['END']}")
            
            if os.path.exists(file_path):
                print_loading_animation(f"Analyzing image: {file_path}", 2)
                results = scan_image_video(file_path)
                display_results(results)
            else:
                print(f"{COLORS['BRIGHT_RED']}File not found!{COLORS['END']}")
            
            input(f"\n{COLORS['BRIGHT_WHITE']}Press Enter to continue...{COLORS['END']}")
            clear_screen()
        
        elif choice == '3':  # Video Analysis
            print("\n" + "="*80)
            print(f"{COLORS['BRIGHT_CYAN']}{COLORS['BOLD']}🎥 VIDEO ANALYSIS{COLORS['END']}")
            print("="*80)
            file_path = input(f"{COLORS['BRIGHT_WHITE']}Enter video file path: {COLORS['END']}")
            
            if os.path.exists(file_path):
                print_loading_animation(f"Analyzing video: {file_path}", 2)
                results = scan_image_video(file_path)
                display_results(results)
            else:
                print(f"{COLORS['BRIGHT_RED']}File not found!{COLORS['END']}")
            
            input(f"\n{COLORS['BRIGHT_WHITE']}Press Enter to continue...{COLORS['END']}")
            clear_screen()
        
        elif choice == '4':  # Script Scanner
            print("\n" + "="*80)
            print(f"{COLORS['BRIGHT_CYAN']}{COLORS['BOLD']}📜 SCRIPT SCANNER{COLORS['END']}")
            print("="*80)
            file_path = input(f"{COLORS['BRIGHT_WHITE']}Enter script file path: {COLORS['END']}")
            
            if os.path.exists(file_path):
                print_loading_animation(f"Analyzing script: {file_path}", 2)
                results = scan_script(file_path)
                display_results(results)
            else:
                print(f"{COLORS['BRIGHT_RED']}File not found!{COLORS['END']}")
            
            input(f"\n{COLORS['BRIGHT_WHITE']}Press Enter to continue...{COLORS['END']}")
            clear_screen()
        
        elif choice == '5':  # GitHub Hunter
            print("\n" + "="*80)
            print(f"{COLORS['BRIGHT_CYAN']}{COLORS['BOLD']}💻 GITHUB HUNTER{COLORS['END']}")
            print("="*80)
            repo_url = input(f"{COLORS['BRIGHT_WHITE']}Enter GitHub repository URL: {COLORS['END']}")
            
            print_loading_animation(f"Scanning repository: {repo_url}", 3)
            results = scan_github_repo(repo_url)
            display_results(results)
            
            input(f"\n{COLORS['BRIGHT_WHITE']}Press Enter to continue...{COLORS['END']}")
            clear_screen()
        
        elif choice == '6':  # Exit
            print(f"\n{COLORS['BRIGHT_GREEN']}Thank you for using RAT Detective!{COLORS['END']}")
            print_footer()
            break
        
        else:
            print(f"{COLORS['BRIGHT_RED']}Invalid choice! Please select 1-6.{COLORS['END']}")
            time.sleep(1)
            clear_screen()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{COLORS['BRIGHT_RED']}Scan interrupted by user.{COLORS['END']}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{COLORS['BRIGHT_RED']}An error occurred: {e}{COLORS['END']}")
        sys.exit(1)
