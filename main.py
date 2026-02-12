import re
from urllib.parse import urlparse

# Список фишинговых ключевых слов [citation:5]
PHISHING_KEYWORDS = [
    'login', 'signin', 'account', 'verify', 'secure', 'webscr',
    'update', 'confirm', 'reset', 'password', 'credential', 'banking'
]


def analyze_url(url):
    """
    Анализирует URL на предмет подозрительных признаков.
    Возвращает оценку риска (0-10) и список срабатываний.
    """
    score = 0
    flags = []

    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
    except Exception:
        return 10, ["Некорректный URL"]

    # 1. Проверка на IP-адрес вместо домена
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, domain.split(':')[0]):
        score += 3
        flags.append("IP-адрес вместо доменного имени")

    # 2. Длинный домен (> 30 символов)
    if len(domain) > 30:
        score += 2
        flags.append("Необычно длинное доменное имя")

    # 3. Много дефисов в домене
    if domain.count('-') > 2:
        score += 2
        flags.append("Подозрительное количество дефисов")

    # 4. Много цифр
    digit_count = sum(c.isdigit() for c in domain)
    if digit_count > 5:
        score += 1
        flags.append("Много цифр в домене")

    # 5. Ключевые слова в пути
    for keyword in PHISHING_KEYWORDS:
        if keyword in url.lower():
            score += 1
            flags.append(f"Обнаружено ключевое слово: '{keyword}'")
            break  # одно срабатывание за наличие ключевых слов

    # 6. Использование HTTP (не HTTPS)
    if parsed.scheme == 'http':
        score += 1
        flags.append("Используется незащищенный протокол HTTP")

    # Нормализация счёта
    final_score = min(10, score)

    # Вердикт
    if final_score >= 7:
        verdict = "ВЫСОКИЙ РИСК"
    elif final_score >= 4:
        verdict = "СРЕДНИЙ РИСК"
    else:
        verdict = "НИЗКИЙ РИСК"

    return final_score, flags, verdict


def main():
    url = None

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    score, flags, verdict = analyze_url(url)

    print("\n" + "=" * 50)
    print(f"URL: {url}")
    print(f"Оценка риска: {score}/10")
    print(f"Вердикт: {verdict}")
    if flags:
        print("\nСработавшие индикаторы:")
        for flag in flags:
            print(f"  • {flag}")
    else:
        print("\nПодозрительных паттернов не обнаружено.")
    print("=" * 50)


if __name__ == "__main__":
    main()
