#!/usr/bin/env python3
"""
VirusChecker - Высокопроизводительный автономный анализатор URL
Оптимизирован для скорости и минимального использования ресурсов
"""

import json
import time
import re
import socket
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, request, jsonify

# ============================================
# КОНФИГУРАЦИЯ И КОНСТАНТЫ
# ============================================

app = Flask(__name__)
SCANS_FILE = Path("scans.json")
CACHE_SIZE = 128
TIMEOUT = 2

# Оптимизированные наборы данных (set для O(1) доступа)
PHISHING_KEYWORDS = {
    'login', 'signin', 'account', 'verify', 'secure', 'webscr',
    'update', 'confirm', 'reset', 'password', 'credential', 'banking',
    'paypal', 'appleid', 'icloud', 'amazon', 'facebook', 'instagram',
    'office365', 'outlook', 'microsoft', 'steam', 'battlenet', 'ebay',
    'alipay', 'wechat', 'wallet', 'credit', 'authorize', 'authentication',
    'verification', 'security', 'support', 'invoice', 'receipt', 'refund',
    'bonus', 'prize', 'winner', 'gift', 'free', 'urgent', 'alert'
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review',
    '.work', '.date', '.men', '.loan', '.win', '.bid', '.trade',
    '.webcam', '.science', '.party', '.racing', '.accountant', '.top',
    '.xyz', '.club', '.online', '.site', '.live', '.shop'
}

URL_SHORTENERS = {
    'bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'cutt.ly', 'tiny.cc', 'tr.im', 'shorte.st', 't.co',
    'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv'
}

MALICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
    '.apk', '.msi', '.docm', '.xlsm', '.pptm'
}

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
    'wikipedia.org', 'yahoo.com', 'reddit.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',
    'github.com', 'stackoverflow.com', 'medium.com', 'zoom.us'
}

# Компилируем регулярные выражения заранее
IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
PUNYCODE_PATTERN = re.compile(r'xn--')
MIXED_CHARS_PATTERN = re.compile(r'[a-z]+\d+[a-z]+')
PRIVATE_IP_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                       '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                       '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                       '172.30.', '172.31.', '192.168.', '127.')

# ============================================
# ОПТИМИЗИРОВАННЫЙ АНАЛИЗАТОР
# ============================================

@lru_cache(maxsize=CACHE_SIZE)
def analyze_url_locally(url):
    """
    Кэшируемый анализатор URL с линейной сложностью O(n)
    """
    score = 0
    flags = []
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain_clean = domain.split(':')[0]
        full_url = url.lower()
        path = parsed.path.lower()
    except Exception:
        return 10, ["Некорректный URL"], 10
    
    # 1. Быстрые проверки протокола (O(1))
    if parsed.scheme == 'http':
        score += 2
        flags.append("⚠️  HTTP (не HTTPS)")
    elif parsed.scheme != 'https':
        score += 1
    
    # 2. Оптимизированная проверка домена
    is_ip = bool(IP_PATTERN.match(domain_clean))
    if is_ip:
        score += 4
        flags.append("🚨 IP-адрес вместо домена")
    
    domain_len = len(domain)
    if domain_len > 30:
        score += 2
        flags.append(f"⚠️  Длинный домен ({domain_len})")
    
    # 3. Быстрые счетчики (один проход)
    dots = domain.count('.')
    hyphens = domain.count('-')
    digits = sum(c.isdigit() for c in domain)
    
    if dots > 3:
        score += 2
        flags.append(f"⚠️  Поддомены: {dots}")
    if hyphens > 2:
        score += 2
        flags.append(f"⚠️  Дефисы: {hyphens}")
    if digits > 5:
        score += 2
        flags.append(f"⚠️  Цифры: {digits}")
    elif digits > 3:
        score += 1
    
    # 4. Проверка наборов (set lookup - O(1))
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 4
            flags.append(f"🚨 TLD: {tld}")
            break
    
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            score += 3
            flags.append(f"⚠️  Сокращатель: {shortener}")
            break
    
    # 5. Оптимизированный поиск ключевых слов
    found_keywords = []
    words_in_url = set(re.findall(r'\b[a-z]+\b', full_url))
    for keyword in PHISHING_KEYWORDS:
        if keyword in words_in_url or keyword in full_url:
            found_keywords.append(keyword)
            score += 1
            if len(found_keywords) >= 3:
                break
    
    if found_keywords:
        flags.append(f"⚠️  Ключевые слова: {len(found_keywords)}")
    
    # 6. Проверка расширений
    if any(path.endswith(ext) for ext in MALICIOUS_EXTENSIONS):
        score += 3
        flags.append("🚨 Вредоносное расширение")
    
    # 7. Белый список
    for trusted in TRUSTED_DOMAINS:
        if trusted in domain:
            score = max(0, score - 3)
            flags.append(f"✅ Доверенный: {trusted}")
            break
    
    # 8. Дополнительные проверки
    if PUNYCODE_PATTERN.search(domain):
        score += 2
        flags.append("⚠️  Punycode домен")
    
    if '@' in url:
        score += 3
        flags.append("🚨 @ в URL")
    
    if MIXED_CHARS_PATTERN.search(domain):
        score += 1
        flags.append("⚠️  Смешанные буквы/цифры")
    
    if len(url) > 500:
        score += 2
    elif len(url) > 200:
        score += 1
    
    # Финальный score
    final_score = min(10, max(0, score))
    
    return final_score, flags[:8], final_score  # Лимитируем флаги

# ============================================
# ОПТИМИЗИРОВАННЫЕ СЕТЕВЫЕ ПРОВЕРКИ
# ============================================

@lru_cache(maxsize=CACHE_SIZE)
def check_dns(domain):
    """Кэшируемая DNS проверка"""
    try:
        ip = socket.gethostbyname(domain)
        is_private = ip.startswith(PRIVATE_IP_PREFIXES)
        return {'ip': ip, 'private': is_private, 'error': None}
    except Exception:
        return {'ip': None, 'private': False, 'error': 'DNS failed'}

# ============================================
# ОПТИМИЗИРОВАННОЕ ХРАНЕНИЕ
# ============================================

def save_scan_result(scan_data):
    """Атомарное сохранение с лимитом записей"""
    try:
        scans = []
        if SCANS_FILE.exists() and SCANS_FILE.stat().st_size > 0:
            with open(SCANS_FILE, 'r', encoding='utf-8') as f:
                scans = json.load(f)
        
        scans.append(scan_data)
        
        # Быстрая обрезка
        if len(scans) > 100:
            scans = scans[-100:]
        
        # Атомарная запись
        temp_file = SCANS_FILE.with_suffix('.tmp')
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(scans, f, separators=(',', ':'))
        temp_file.replace(SCANS_FILE)
        
    except Exception:
        pass

# ============================================
# API ENDPOINTS (ОПТИМИЗИРОВАННЫЕ)
# ============================================

@app.route('/health', methods=['GET'])
def health():
    """Минимальный ответ для проверки"""
    return {'status': 'ok', 'mode': 'local'}

@app.route('/scan', methods=['POST'])
def scan_url():
    """Оптимизированный эндпоинт сканирования"""
    try:
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()
        
        if not url:
            return {'error': 'URL required'}, 400
        
        # Нормализация URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Анализ
        score, flags, _ = analyze_url_locally(url)
        
        # DNS проверка
        domain = urlparse(url).netloc.split(':')[0]
        dns = check_dns(domain) if '.' in domain else None
        
        # Вердикт
        if score >= 8:
            status = "Вредоносный"
        elif score >= 6:
            status = "Высокий риск"
        elif score >= 4:
            status = "Подозрительный"
        elif score >= 2:
            status = "Низкий риск"
        else:
            status = "Безопасный"
        
        # Результат
        scan_id = f"vc_{int(time.time()*1000)}"
        result = {
            'id': scan_id,
            'url': url,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'status': status,
            'detection': f"{score}/10",
            'risk_score': score,
            'flags': flags,
            'flags_count': len(flags),
            'dns': dns
        }
        
        # Фоновое сохранение
        save_scan_result(result)
        
        return {'success': True, 'scan_id': scan_id, 'data': result}
        
    except Exception as e:
        return {'success': False, 'error': str(e)}, 500

@app.route('/scans', methods=['GET'])
def get_scans():
    """Быстрое чтение сканов"""
    try:
        if SCANS_FILE.exists() and SCANS_FILE.stat().st_size > 0:
            with open(SCANS_FILE, 'r', encoding='utf-8') as f:
                scans = json.load(f)
            return {'success': True, 'count': len(scans), 'scans': scans[-50:]}
        return {'success': True, 'count': 0, 'scans': []}
    except Exception:
        return {'success': False, 'error': 'Read failed'}, 500

@app.route('/check', methods=['GET'])
def quick_check():
    """Быстрая проверка через GET"""
    url = request.args.get('url', '').strip()
    if not url:
        return {'error': 'URL required'}, 400
    
    score, flags, _ = analyze_url_locally(url)
    return {
        'url': url,
        'score': score,
        'warnings': flags[:3],
        'total': len(flags)
    }

# ============================================
# ЗАПУСК
# ============================================

if __name__ == '__main__':
    print(f"\n{'='*50}")
    print(f"🔐 VirusChecker Scanner v2.0")
    print(f"{'='*50}")
    print(f"✅ Режим: Автономный / Высокая производительность")
    print(f"⚡ Кэш: {CACHE_SIZE} записей")
    print(f"📦 Базы: {len(PHISHING_KEYWORDS)} ключевых слов")
    print(f"{'='*50}\n")
    
    app.run(host='0.0.0.0', port=5000, threaded=True)
