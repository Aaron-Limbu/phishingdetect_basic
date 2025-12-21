import re
import json
from urllib.parse import urlparse
from datetime import datetime
import os

LOG_FILE = r"C:\Wazuh\logs\phishing.log"   

class PhishingDetector:

    def __init__(self):
        self.keyword_list = [
            "verify your account", "urgent", "reset password",
            "confirm your details", "security alert", "click link",
            "update billing information", "your account will be closed",
            "unexpected login attempt", "unauthorized access",
            "account suspension", "confirm your identity",
            "payment required", "unusual activity", "limited time",
            "act now", "final notice", "secure your account",
            "reactivate", "login immediately", "invoicing issue",
            "refund available", "document shared with you",
        ]

        self.suspicious_domains = [
            ".xyz", ".top", ".ru", ".cn", ".club", ".click", ".bid",
            ".info", ".shop", ".live", ".gq", ".ml", ".tk", ".work",
            ".download", ".loan", ".stream", ".support", ".services",
            ".email"
        ]

    # ---- log helper ----
    def log_event(self, message, score, verdict, matches):
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "PHISHING_DETECTION",
            "message": message,
            "score": score,
            "verdict": verdict,
            "matches": matches
        }

        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")


    def detect_keywords(self, text, matches):
        score = 0
        for keyword in self.keyword_list:
            if keyword.lower() in text.lower():
                matches.append(f"keyword:{keyword}")
                score += 1
        return score

    def detect_suspicious_links(self, text, matches):
        score = 0
        urls = re.findall(r'https?://\S+', text)

        for url in urls:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            for suspicious in self.suspicious_domains:
                if domain.endswith(suspicious):
                    matches.append(f"suspicious_domain:{domain}")
                    score += 2

            if len(url) > 60:
                matches.append("long_url")
                score += 1

        return score


    def analyze_email(self, email_text):
        matches = []
        score = 0
        score += self.detect_keywords(email_text, matches)
        score += self.detect_suspicious_links(email_text, matches)

        if score >= 5:
            verdict = "VERY LIKELY PHISHING"
        elif score >= 3:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LIKELY SAFE"
        self.log_event(
            message="email scanned",
            score=score,
            verdict=verdict,
            matches=matches
        )

        return score, verdict, matches


if __name__ == "__main__":
    detector = PhishingDetector()
    
    test_email = """
    Dear user, security alert!
    Your account has been locked. Click link below:
    https://login-verify.example.xyz/reset
    """

    score, verdict, matches = detector.analyze_email(test_email)
    print("Score:", score)
    print("Verdict:", verdict)
    print("Matches:", matches)
