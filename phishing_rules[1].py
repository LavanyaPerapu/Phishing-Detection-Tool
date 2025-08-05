import re
from urllib.parse import urlparse

def is_suspicious_url(url):
    reasons = []
    score = 0

    parsed = urlparse(url)
    domain = parsed.netloc

    # 1️⃣ IP Address based URL
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', domain):
        reasons.append("URL uses IP Address")
        score += 3

    # 2️⃣ Hyphens in domain (common in phishing)
    if '-' in domain:
        reasons.append("Hyphen in domain name")
        score += 1

    # 3️⃣ @ symbol in URL (phishing trick)
    if '@' in url:
        reasons.append("Uses '@' symbol in URL")
        score += 3

    # 4️⃣ Suspicious Top Level Domains (newly abused TLDs)
    suspicious_tlds = ['.zip', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        reasons.append("Suspicious TLD detected")
        score += 2

    # 5️⃣ URL Length Check
    if len(url) > 75:
        reasons.append("Unusually long URL")
        score += 1

    # 6️⃣ Presence of suspicious words in URL path
    phishing_words = ['secure', 'account', 'update', 'login', 'verify', 'bank', 'confirm']
    if any(word in url.lower() for word in phishing_words):
        reasons.append("Phishing-related words in URL")
        score += 2

    # 7️⃣ URL Shorteners detection
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'rebrand.ly', 'cutt.ly']
    if any(short in domain for short in shorteners):
        reasons.append("URL shortener service detected")
        score += 2

    return reasons, score

def extract_urls(text):
    return re.findall(r'(https?://[^\s]+)', text)

def detect_phishing(text):
    signals = []
    urls = extract_urls(text)
    url_score = 0

    for url in urls:
        reasons, score = is_suspicious_url(url)
        url_score += score
        for reason in reasons:
            signals.append(f"URL Flagged: {url} — {reason}")

    # 8️⃣ Keyword Detection in Message Text
    text_score = 0
    text_keywords = ['urgent', 'verify', 'account', 'password', 'security', 'click here', 'confirm', 'update', 'limited time']
    for word in text_keywords:
        if word in text.lower():
            signals.append(f"Suspicious keyword in text: {word}")
            text_score += 1

    total_score = url_score + text_score

    if total_score >= 5:
        status = "Phishing Detected"
    elif 1 <= total_score < 5:
        status = "Suspicious — Check Carefully"
    else:
        status = "Safe"

    attack_type = "URL Phishing" if urls else ("Text-based Phishing" if text_score else "None")
    tip = "Be cautious! Avoid clicking on suspicious links." if total_score else "No phishing indicators found."

    return {
        "status": status,
        "type": attack_type,
        "signals": signals,
        "tip": tip
    }
