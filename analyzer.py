import re

URGENT_WORDS = [
    "act now",
    "urgent",
    "immediately",
    "verify your account",
    "click here",
    "confirm your",
    "update your",
    "unauthorized",
    "limited time",
    "suspended",
    "winner",
    "free gift"
]

SUSPICIOUS_DOMAINS = [
    "paypal-secure",
    "amazon-verify",
    "apple-id",
    "microsoft-account"
]

def extract_urls(text):
    pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(pattern, text)

def check_urgent_words(text):
    text = text.lower()
    found = []

    for word in URGENT_WORDS:
        if word in text:
            found.append(word)

    return found

def check_links(urls):
    flags = []

    for url in urls:
        if "bit.ly" in url or "tinyurl" in url:
            flags.append(f"Shortened suspicious link: {url}")

        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            flags.append(f"IP address used in URL: {url}")

    return flags

def check_sender(sender):
    flags = []

    sender = sender.lower()

    for domain in SUSPICIOUS_DOMAINS:
        if domain in sender:
            flags.append(f"Suspicious sender detected: {sender}")

    return flags

def calculate_score(urgent_flags, link_flags, sender_flags):
    score = 0

    score += len(urgent_flags) * 10
    score += len(link_flags) * 25
    score += len(sender_flags) * 20

    if score > 100:
        score = 100

    return score

def get_risk_level(score):
    if score >= 60:
        return "HIGH", "#ff4d4d"

    elif score >= 30:
        return "MEDIUM", "#ffaa00"

    else:
        return "LOW", "#00cc66"

def analyze_email(sender, subject, body):
    full_text = subject + " " + body

    urls = extract_urls(full_text)

    urgent_flags = check_urgent_words(full_text)
    link_flags = check_links(urls)
    sender_flags = check_sender(sender)

    score = calculate_score(
        urgent_flags,
        link_flags,
        sender_flags
    )

    risk_level, color = get_risk_level(score)

    return {
        "score": score,
        "risk_level": risk_level,
        "color": color,
        "urgent_flags": urgent_flags,
        "link_flags": link_flags,
        "sender_flags": sender_flags,
        "urls": urls
    }