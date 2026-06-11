import argparse
import json


TRUSTED_DOMAINS = ["polito.it", "students.polito.it", "microsoft.com", "google.com"]

LOOKALIKE_DOMAINS = {
    "rnicrosoft.com": "microsoft.com",
    "paypa1.com": "paypal.com",
    "g00gle.com": "google.com"
}

URGENCY_WORDS = ["urgent", "immediately", "today", "right now", "final warning"]
CREDENTIAL_WORDS = ["password", "login", "credentials", "verify your account"]
PAYMENT_WORDS = ["payment", "invoice", "bank transfer", "gift card", "refund"]
DANGEROUS_TYPES = ["executable", "script", "macro", "archive"]


def load_messages(input_file):
    file = open(input_file, "r")
    data = json.load(file)
    file.close()

    contents = {}

    for item in data["messages"]:
        message_id = item["id"]
        contents[message_id] = item

    return contents


def save_output(output, output_file):
    file = open(output_file, "w")
    json.dump(output, file, indent=4)
    file.close()


def get_sender_domain(sender_address):
    if "@" in sender_address:
        parts = sender_address.split("@")
        return parts[1].lower()
    else:
        return ""


def get_link_domain(link):
    # Very simple URL domain extraction.
    # Example: http://fake.com/login -> fake.com
    link = link.replace("https://", "")
    link = link.replace("http://", "")

    parts = link.split("/")
    return parts[0].lower()


def check_unknown_sender(message):
    sender = message["sender_address"]
    domain = get_sender_domain(sender)

    if domain == "":
        return {
            "name": "unknown_sender",
            "weight": 15,
            "evidence": "Sender is not a normal email address"
        }

    trusted = False

    for trusted_domain in TRUSTED_DOMAINS:
        if domain == trusted_domain:
            trusted = True

    if trusted == False:
        return {
            "name": "unknown_sender",
            "weight": 15,
            "evidence": "Sender domain is not trusted: " + domain
        }

    return None


def check_lookalike_domain(message):
    sender = message["sender_address"]
    domain = get_sender_domain(sender)

    if domain in LOOKALIKE_DOMAINS:
        return {
            "name": "lookalike_domain",
            "weight": 25,
            "evidence": domain + " looks like " + LOOKALIKE_DOMAINS[domain]
        }

    return None


def check_urgent_words(message):
    text = message["subject"] + " " + message["body"]
    text = text.lower()

    found = []

    for word in URGENCY_WORDS:
        if word in text:
            found.append(word)

    if len(found) > 0:
        return {
            "name": "urgent_language",
            "weight": 15,
            "evidence": "Urgent words found: " + str(found)
        }

    return None


def check_credentials(message):
    text = message["subject"] + " " + message["body"]
    text = text.lower()

    found = []

    for word in CREDENTIAL_WORDS:
        if word in text:
            found.append(word)

    if len(found) > 0:
        return {
            "name": "credential_request",
            "weight": 25,
            "evidence": "Credential words found: " + str(found)
        }

    return None


def check_payment(message):
    text = message["subject"] + " " + message["body"]
    text = text.lower()

    found = []

    for word in PAYMENT_WORDS:
        if word in text:
            found.append(word)

    if len(found) > 0:
        return {
            "name": "payment_request",
            "weight": 20,
            "evidence": "Payment words found: " + str(found)
        }

    return None


def check_http_links(message):
    bad_links = []

    for link in message["links"]:
        url = link["actual_url"]

        if url.startswith("http://"):
            bad_links.append(url)

    if len(bad_links) > 0:
        return {
            "name": "non_https_link",
            "weight": 15,
            "evidence": "HTTP links found: " + str(bad_links)
        }

    return None


def check_suspicious_links(message):
    bad_links = []

    for link in message["links"]:
        url = link["actual_url"]
        domain = get_link_domain(url)

        trusted = False

        for trusted_domain in TRUSTED_DOMAINS:
            if domain == trusted_domain:
                trusted = True

        if trusted == False:
            bad_links.append(url)

    if len(bad_links) > 0:
        return {
            "name": "suspicious_link",
            "weight": 20,
            "evidence": "Untrusted links found: " + str(bad_links)
        }

    return None


def check_attachments(message):
    bad_files = []

    for attachment in message["attachments"]:
        file_type = attachment["type"].lower()

        if file_type in DANGEROUS_TYPES:
            bad_files.append(attachment["filename"])

    if len(bad_files) > 0:
        return {
            "name": "dangerous_attachment",
            "weight": 25,
            "evidence": "Dangerous attachments found: " + str(bad_files)
        }

    return None


def classify(score):
    if score >= 50:
        return "phishing"
    elif score >= 20:
        return "suspicious"
    else:
        return "legitimate"


def analyze_message(message_id, contents):
    message = contents[message_id]
    indicators = []

    result = check_unknown_sender(message)
    if result != None:
        indicators.append(result)

    result = check_lookalike_domain(message)
    if result != None:
        indicators.append(result)

    result = check_urgent_words(message)
    if result != None:
        indicators.append(result)

    result = check_credentials(message)
    if result != None:
        indicators.append(result)

    result = check_payment(message)
    if result != None:
        indicators.append(result)

    result = check_http_links(message)
    if result != None:
        indicators.append(result)

    result = check_suspicious_links(message)
    if result != None:
        indicators.append(result)

    result = check_attachments(message)
    if result != None:
        indicators.append(result)

    score = 0

    for indicator in indicators:
        score = score + indicator["weight"]

    output = {
        "id": message_id,
        "channel": message["channel"],
        "risk_score": score,
        "classification": classify(score),
        "triggered_indicators": indicators
    }

    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input")
    parser.add_argument("--output")
    args = parser.parse_args()

    contents = load_messages(args.input)

    results = []

    legitimate = 0
    suspicious = 0
    phishing = 0

    for message_id in contents:
        result = analyze_message(message_id, contents)
        results.append(result)

        if result["classification"] == "legitimate":
            legitimate = legitimate + 1
        elif result["classification"] == "suspicious":
            suspicious = suspicious + 1
        elif result["classification"] == "phishing":
            phishing = phishing + 1

    final_output = {
        "summary": {
            "total_messages": len(results),
            "legitimate": legitimate,
            "suspicious": suspicious,
            "phishing": phishing
        },
        "results": results
    }

    save_output(final_output, args.output)


main()