#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VirusChecker - Автономный анализатор URL
Полностью локальная проверка без использования внешних API
"""

import json
import time
import re
import os
import sys
import socket
import ssl
import urllib.parse
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

try:
    from flask import Flask, request, jsonify
    import requests
except ImportError:
    print("❌ Ошибка: Установите зависимости:")
    print("   pip install flask requests")
    sys.exit(1)

# ============================================
# КОНФИГУРАЦИЯ
# ============================================

app = Flask(__name__)
SCANS_FILE = Path("scans.json")

# ============================================
# РАСШИРЕННЫЕ БАЗЫ ДАННЫХ ДЛЯ ЛОКАЛЬНОГО АНАЛИЗА
# ============================================

# 1. ФИШИНГОВЫЕ КЛЮЧЕВЫЕ СЛОВА
PHISHING_KEYWORDS = [
    # Банковские и финансовые
    'login', 'signin', 'account', 'verify', 'secure', 'webscr',
    'update', 'confirm', 'reset', 'password', 'credential', 'banking',
    'paypal', 'appleid', 'icloud', 'amazon', 'facebook', 'instagram',
    'office365', 'outlook', 'microsoft', 'steam', 'battlenet',
    'ebay', 'alipay', 'wechat', 'pay', 'wallet', 'credit', 'card',
    'authorize', 'authentication', 'verification', 'security',
    # Дополнительные
    'support', 'service', 'customer', 'help', 'bill', 'invoice',
    'receipt', 'statement', 'transaction', 'refund', 'bonus',
    'prize', 'winner', 'gift', 'free', 'offer', 'promotion',
    'discount', 'coupon', 'voucher', 'limited', 'urgent', 'alert'
]

# 2. ПОДОЗРИТЕЛЬНЫЕ TLD (ДОМЕННЫЕ ЗОНЫ)
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review',
    '.work', '.date', '.men', '.loan', '.win', '.bid', '.trade',
    '.webcam', '.science', '.party', '.racing', '.accountant',
    '.top', '.xyz', '.club', '.online', '.site', '.live', '.shop'
]

# 3. СЕРВИСЫ СОКРАЩЕНИЯ URL
URL_SHORTENERS = [
    'bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'short.link', 'cutt.ly', 'tiny.cc', 'tr.im', 'shorte.st',
    'bc.vc', 'u.to', 'v.gd', 'cli.gs', 'qr.net', '1url.com',
    't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv'
]

# 4. ПОДОЗРИТЕЛЬНЫЕ IP-ДИАПАЗОНЫ (известные хостеры)
SUSPICIOUS_ASN = [
    'AS13335', 'AS15169', 'AS16509',  # CloudFlare, Google, AWS
    # Добавьте свои
]

# 5. ВРЕДОНОСНЫЕ ПАТТЕРНЫ В URL
MALICIOUS_PATTERNS = [
    r'\.exe$', r'\.scr$', r'\.bat$', r'\.cmd$', r'\.ps1$',
    r'\.vbs$', r'\.js$', r'\.jar$', r'\.apk$', r'\.msi$',
    r'\.docm$', r'\.xlsm$', r'\.pptm$',
    r'/eval\(', r'/base64', r'/decode', r'/exec',
    r'%00', r'../', r'..\\', r'\\\\'
]

# 6. БЕЛЫЙ СПИСОК (доверенные домены)
TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
    'wikipedia.org', 'yahoo.com', 'reddit.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',
    'github.com', 'stackoverflow.com', 'medium.com', 'zoom.us',
    'whatsapp.com', 'telegram.org', 'spotify.com', 'netflix.com'
]

# 7. БЛОКИРОВКА ПО СТРАНАМ (необязательно)
HIGH_RISK_COUNTRIES = ['RU', 'CN', 'KP', 'IR', 'SY', 'UA']  # Пример

# ============================================
# ОСНОВНОЙ АНАЛИЗАТОР (100% ЛОКАЛЬНЫЙ)
# ============================================

def analyze_url_locally(url):
    """
    ПОЛНОСТЬЮ АВТОНОМНЫЙ АНАЛИЗ URL
    Без вызовов каких-либо внешних API
    Возвращает: (оценка_риска, список_флагов, детальный_отчет)
    """
    score = 0
    flags = []
    details = {
        'domain_info': {},
        'url_analysis': {},
        'risk_factors': []
    }
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        full_url = url.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
    except Exception:
        return 10, ["❌ Некорректный формат URL"], details
    
    # -------------------------------------------------
    # 1. АНАЛИЗ ПРОТОКОЛА
    # -------------------------------------------------
    if parsed.scheme == 'http':
        score += 2
        flags.append("⚠️  Используется незащищенный протокол HTTP")
        details['risk_factors'].append("HTTP (не HTTPS)")
    elif parsed.scheme == 'https':
        details['domain_info']['secure'] = True
    else:
        score += 1
        flags.append(f"⚠️  Нестандартный протокол: {parsed.scheme}")
    
    # -------------------------------------------------
    # 2. АНАЛИЗ ДОМЕНА
    # -------------------------------------------------
    
    # Проверка на IP-адрес
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, domain.split(':')[0]):
        score += 4
        flags.append("🚨 URL использует IP-адрес вместо доменного имени")
    
    # Длина домена
    domain_without_sub = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
    if len(domain) > 30:
        score += 2
        flags.append(f"⚠️  Необычно длинное доменное имя ({len(domain)} символов)")
    if len(domain_without_sub) > 20:
        score += 1
        flags.append(f"⚠️  Длинное основное доменное имя")
    
    # Количество поддоменов
    subdomain_count = domain.count('.')
    if subdomain_count > 3:
        score += 2
        flags.append(f"⚠️  Много поддоменов ({subdomain_count})")
    
    # Дефисы в домене
    if domain.count('-') > 2:
        score += 2
        flags.append(f"⚠️  Подозрительное количество дефисов ({domain.count('-')})")
    elif domain.count('-') > 0:
        score += 1
    
    # Цифры в домене
    digit_count = sum(c.isdigit() for c in domain)
    if digit_count > 5:
        score += 2
        flags.append(f"⚠️  Много цифр в домене ({digit_count})")
    elif digit_count > 3:
        score += 1
    
    # Смешанные символы
    if re.search(r'[a-z]+\d+[a-z]+', domain):
        score += 1
        flags.append("⚠️  Подозрительная комбинация букв и цифр")
    
    # -------------------------------------------------
    # 3. ПРОВЕРКА TLD (ДОМЕННОЙ ЗОНЫ)
    # -------------------------------------------------
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 4
            flags.append(f"🚨 Подозрительная доменная зона: {tld}")
            break
    
    # -------------------------------------------------
    # 4. ПРОВЕРКА НА СЕРВИСЫ СОКРАЩЕНИЯ
    # -------------------------------------------------
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            score += 3
            flags.append(f"⚠️  Сервис сокращения URL: {shortener}")
            break
    
    # -------------------------------------------------
    # 5. ПОИСК ФИШИНГОВЫХ КЛЮЧЕВЫХ СЛОВ
    # -------------------------------------------------
    found_keywords = []
    for keyword in PHISHING_KEYWORDS:
        if keyword in full_url:
            found_keywords.append(keyword)
            score += 1
    
    if found_keywords:
        unique_keywords = list(set(found_keywords))[:5]
        flags.append(f"⚠️  Фишинговые ключевые слова: {', '.join(unique_keywords)}")
        details['risk_factors'].append(f"Keywords: {unique_keywords}")
    
    # -------------------------------------------------
    # 6. ПРОВЕРКА ПУТИ И ПАРАМЕТРОВ
    # -------------------------------------------------
    
    # Вредоносные расширения файлов
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            score += 3
            flags.append(f"🚨 Потенциально вредоносный файл: {pattern}")
            break
    
    # Много параметров в URL
    param_count = query.count('&') + query.count('=') // 2
    if param_count > 5:
        score += 1
        flags.append(f"⚠️  Много параметров в URL ({param_count})")
    
    # Длина URL
    if len(url) > 500:
        score += 2
        flags.append(f"⚠️  Чрезмерно длинный URL ({len(url)} символов)")
    elif len(url) > 200:
        score += 1
    
    # -------------------------------------------------
    # 7. ПРОВЕРКА ПО БЕЛОМУ СПИСКУ
    # -------------------------------------------------
    for trusted in TRUSTED_DOMAINS:
        if trusted in domain:
            score = max(0, score - 3)
            flags.append(f"✅ Домен в белом списке: {trusted}")
            break
    
    # -------------------------------------------------
    # 8. ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ
    # -------------------------------------------------
    
    # Проверка на Punycode (международные домены)
    if 'xn--' in domain:
        score += 2
        flags.append("⚠️  Международный домен (Punycode)")
    
    # Порты
    if ':' in domain and not domain.endswith(':80') and not domain.endswith(':443'):
        port = domain.split(':')[-1]
        if port.isdigit():
            score += 2
            flags.append(f"⚠️  Нестандартный порт: {port}")
    
    # @ в URL (редирект)
    if '@' in url:
        score += 3
        flags.append("🚨 URL содержит символ @ (подозрительный редирект)")
    
    # -------------------------------------------------
    # 9. ФИНАЛЬНЫЙ РАСЧЕТ
    # -------------------------------------------------
    final_score = min(10, max(0, score))
    
    # Определение уровня риска
    if final_score >= 8:
        risk_level = "КРИТИЧЕСКИЙ"
    elif final_score >= 6:
        risk_level = "ВЫСОКИЙ"
    elif final_score >= 4:
        risk_level = "СРЕДНИЙ"
    elif final_score >= 2:
        risk_level = "НИЗКИЙ"
    else:
        risk_level = "МИНИМАЛЬНЫЙ"
    
    details['risk_level'] = risk_level
    details['final_score'] = final_score
    details['total_flags'] = len(flags)
    
    return final_score, flags, details

# ============================================
# ОПЦИОНАЛЬНАЯ DNS-ПРОВЕРКА (НЕ ТРЕБУЕТ API)
# ============================================

def check_dns(url):
    """
    Проверка DNS записи домена
    Полностью локальная, не требует API
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = domain.split(':')[0]  # удаляем порт
        
        # Проверяем A запись
        ip = socket.gethostbyname(domain)
        
        # Проверяем, является ли IP частным
        private_ips = ['10.', '172.16.', '172.17.', '172.18.', '172.19.',
                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                      '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                      '172.30.', '172.31.', '192.168.', '127.']
        
        is_private = any(ip.startswith(priv) for priv in private_ips)
        
        return {
            'domain': domain,
            'ip': ip,
            'is_private': is_private,
            'error': None
        }
    except socket.gaierror:
        return {
            'domain': domain,
            'ip': None,
            'is_private': False,
            'error': 'DNS resolution failed'
        }
    except Exception as e:
        return {
            'domain': domain,
            'ip': None,
            'is_private': False,
            'error': str(e)
        }

# ============================================
# ОПЦИОНАЛЬНАЯ SSL-ПРОВЕРКА (НЕ ТРЕБУЕТ API)
# ============================================

def check_ssl(url):
    """
    Проверка SSL сертификата
    Только для HTTPS URL
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            return {
                'has_ssl': False,
                'error': 'Not HTTPS'
            }
        
        domain = parsed.netloc.split(':')[0]
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Проверяем срок действия
                from datetime import datetime
                not_after = cert.get('notAfter', '')
                if not_after:
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - datetime.now()).days
                    
                    return {
                        'has_ssl': True,
                        'issuer': dict(cert.get('issuer', [])),
                        'subject': dict(cert.get('subject', [])),
                        'expiry': expiry.isoformat(),
                        'days_left': days_left,
                        'error': None
                    }
    except Exception as e:
        return {
            'has_ssl': False,
            'error': str(e)
        }
    
    return {
        'has_ssl': False,
        'error': 'SSL check failed'
    }

# ============================================
# СОХРАНЕНИЕ РЕЗУЛЬТАТОВ
# ============================================

def save_scan_result(scan_data):
    """Сохраняет результат сканирования в JSON файл"""
    scans = []
    
    if SCANS_FILE.exists():
        try:
            with open(SCANS_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
                if content.strip():
                    scans = json.loads(content)
        except json.JSONDecodeError:
            scans = []
    
    scans.append(scan_data)
    
    # Храним последние 100 сканов
    if len(scans) > 100:
        scans = scans[-100:]
    
    with open(SCANS_FILE, 'w', encoding='utf-8') as f:
        json.dump(scans, f, ensure_ascii=False, indent=2)
    
    return scan_data

# ============================================
# API ENDPOINTS
# ============================================

@app.route('/health', methods=['GET'])
def health():
    """Проверка работоспособности"""
    return jsonify({
        'status': 'ok',
        'service': 'viruschecker-scanner',
        'mode': 'fully_autonomous',
        'no_external_apis': True,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/scan', methods=['POST'])
def scan_url():
    """Основной эндпоинт для сканирования URL"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL не предоставлен'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL пустой'}), 400
        
        # Нормализуем URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 1. ЛОКАЛЬНЫЙ АНАЛИЗ (основной)
        local_score, local_flags, local_details = analyze_url_locally(url)
        
        # 2. ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ (опционально)
        dns_info = check_dns(url)
        ssl_info = check_ssl(url) if url.startswith('https') else None
        
        # 3. ФОРМИРУЕМ ВЕРДИКТ
        if local_score >= 8:
            status = "Вредоносный"
            color = "#dc3545"
        elif local_score >= 6:
            status = "Высокий риск"
            color = "#ff6b6b"
        elif local_score >= 4:
            status = "Подозрительный"
            color = "#ff9900"
        elif local_score >= 2:
            status = "Низкий риск"
            color = "#ffc107"
        else:
            status = "Безопасный"
            color = "#28a745"
        
        # 4. ПОДГОТАВЛИВАЕМ РЕЗУЛЬТАТ
        scan_id = f"vc_{int(time.time() * 1000)}_{os.urandom(2).hex()}"
        
        result = {
            'id': scan_id,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'status': status,
            'detection': f"{local_score}/10",
            'risk_score': local_score,
            'risk_level': local_details.get('risk_level', 'UNKNOWN'),
            'flags': local_flags,
            'flags_count': len(local_flags),
            'dns_check': dns_info,
            'ssl_check': ssl_info,
            'details': local_details,
            'user_agent': request.headers.get('User-Agent', 'unknown'),
            'ip_address': request.remote_addr
        }
        
        # 5. СОХРАНЯЕМ
        save_scan_result(result)
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'data': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/scans', methods=['GET'])
def get_scans():
    """Получение всех сохраненных сканов"""
    if SCANS_FILE.exists():
        try:
            with open(SCANS_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
                scans = json.loads(content) if content.strip() else []
            return jsonify({
                'success': True,
                'count': len(scans),
                'scans': scans
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({'success': True, 'count': 0, 'scans': []})

@app.route('/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Получение конкретного скана по ID"""
    if SCANS_FILE.exists():
        try:
            with open(SCANS_FILE, 'r', encoding='utf-8') as f:
                scans = json.load(f)
            
            for scan in scans:
                if scan['id'] == scan_id:
                    return jsonify({'success': True, 'scan': scan})
            
            return jsonify({'success': False, 'error': 'Скан не найден'}), 404
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify({'success': False, 'error': 'Нет данных'}), 404

@app.route('/check', methods=['GET'])
def quick_check():
    """Быстрая проверка URL через GET параметр"""
    url = request.args.get('url', '')
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400
    
    # Имитация POST запроса
    score, flags, _ = analyze_url_locally(url)
    
    return jsonify({
        'url': url,
        'risk_score': score,
        'risk_level': 'HIGH' if score >= 7 else 'MEDIUM' if score >= 4 else 'LOW',
        'warnings': flags[:5],
        'total_warnings': len(flags)
    })

# ============================================
# ЗАПУСК
# ============================================

if __name__ == '__main__':
    print("=" * 60)
    print("🔐 VirusChecker - АВТОНОМНЫЙ АНАЛИЗАТОР URL")
    print("=" * 60)
    print("✅ Режим: ПОЛНОСТЬЮ ЛОКАЛЬНЫЙ")
    print("❌ Внешние API: НЕ ИСПОЛЬЗУЮТСЯ")
    print("📊 Методы анализа:")
    print("   • Протоколы и порты")
    print("   • Структура домена")
    print("   • Фишинговые ключевые слова")
    print("   • Вредоносные расширения")
    print("   • DNS проверка (опционально)")
    print("   • SSL сертификаты (опционально)")
    print("=" * 60)
    print("🚀 Запуск Flask сервера на http://localhost:5000")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
