import argparse
import json
from urllib.parse import urlparse


TRUSTED_DOMAINS = {
    "polito.it",
    "students.polito.it",
    "microsoft.com",
    "google.com"
}

LOOKALIKE_DOMAINS = {
    "rnicrosoft.com": "microsoft.com",
    "paypa1.com": "paypal.com",
    "g00gle.com": "google.com"
}

URGENCY_WORDS = {
    "urgent",
    "immediately",
    "today",
    "right now",
    "account suspended",
    "account disabled",
    "final warning"
}

CREDENTIAL_WORDS = {
    "password",
    "login",
    "credentials",
    "verify your account",
    "confirm your account",
    "security code"
}

PAYMENT_WORDS = {
    "payment",
    "invoice",
    "bank transfer",
    "wire transfer",
    "gift card",
    "refund"
}

DANGEROUS_ATTACHMENT_TYPES = {
    "executable",
    "script",
    "macro",
    "archive"
}

WEIGHTS = {
    "unknown_sender": 15,
    "lookalike_domain": 25,
    "urgent_language": 15,
    "credential_request": 25,
    "payment_request": 20,
    "non_https_link": 15,
    "suspicious_link": 20,
    "dangerous_attachment": 25
}

def load_messege():
    contents = {}
    with open('input.json','r') as input:
        data = json.load(input)

        for item in data:
            key = item["id"]
            value = {
                "channel": item["channel"],
                "sender": item["sender_name"],
                "text": item["body"],
                "links": item["links"],
                "attachments": item["attachments"]
                }
            contents[key] = value
            print(contents)
    return contents




load_messege()
