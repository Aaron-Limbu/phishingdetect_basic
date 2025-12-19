import re
from urllib.parse import urlparse

class PhishingDetector:

    def __init__(self):
        self.keyword_list = [
            "verify your account",
            "urgent",
            "reset password",
            "confirm your details",
            "security alert",
            "click link",
            "update billing information",
            "your account will be closed",
            "unexpected login attempt",
            "unauthorized access",
            "account suspension",
            "confirm your identity",
            "payment required",
            "unusual activity",
            "limited time",
            "act now",
            "final notice",
            "secure your account",
            "reactivate",
            "login immediately",
            "invoicing issue",
            "refund available",
            "document shared with you",
        ]


        self.suspicious_domains = [
            ".xyz",
            ".top",
            ".ru",
            ".cn",
            ".club",
            ".click",
            ".bid",
            ".info",
            ".shop",
            ".live",
            ".gq",
            ".ml",
            ".tk",
            ".work",
            ".download",
            ".loan",
            ".stream",
            ".support",
            ".services",
            ".email"   \
        ]


    def detect_keywords(self, text):
        score = 0
        for keyword in self.keyword_list:
            if keyword.lower() in text.lower():
                print(f"[!] Found keyword: {keyword}")
                score += 1
        return score

    def detect_suspicious_links(self, text):
        score = 0
        urls = re.findall(r'https?://\S+', text)

        for url in urls:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            for suspicious in self.suspicious_domains:
                if domain.endswith(suspicious):
                    print(f"[!] Suspicious domain: {domain}")
                    score += 2

            if len(url) > 60:
                print("[!] Long/obfuscated link found")
                score += 1

        return score

    def detect_mismatch(self, display_text, url):
        parsed = urlparse(url)
        domain = parsed.hostname or ""

        if display_text.lower() not in domain.lower():
            print("[!] Link mismatch detected")
            return 2
        
        return 0

    def analyze_email(self, email_text):
        score = 0

        print("\n--- Analyzing Email for Phishing ---")

        score += self.detect_keywords(email_text)
        score += self.detect_suspicious_links(email_text)

        if score >= 5:
            verdict = "VERY LIKELY PHISHING"
        elif score >= 3:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LIKELY SAFE"

        print("\nDetection Score:", score)
        print("Verdict:", verdict)

        return score, verdict

if __name__ == "__main__":
    detector = PhishingDetector()
    test_email = """
    Dear user, security alert!
    Your account has been locked. Click link below:
    https://login-verify.example.xyz/reset
    """
    detector.analyze_email(test_email)
