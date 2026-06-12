import argparse
import json


TRUSTED_DOMAINS = ["polito.it", "students.polito.it", "microsoft.com", "google.com"]

LOOKALIKE_DOMAINS = {
    "rnicrosoft.com": "microsoft.com",
    "paypa1.com": "paypal.com",
    "g00gle.com": "google.com"
} #domains that try to impersonate real ones by looking similar, of course thease dictionaries can be expanded to include much more domains and words to improve accuracy

URGENCY_WORDS = ["urgent", "immediately", "today", "right now", "final warning"]
CREDENTIAL_WORDS = ["password", "login", "credentials", "verify your account"]
PAYMENT_WORDS = ["payment", "invoice", "bank transfer", "gift card", "refund"]
DANGEROUS_TYPES = ["executable", "script", "macro", "archive"]
#phising messeges will often use urgent keywords to stress out the reciever hoping that they will make a mistake under time pressure


def load_messages(input_file): #loading the input file and turning it into a dictonary
    file = open(input_file, "r")
    data = json.load(file)
    file.close()

    contents = {}

    for item in data["messages"]:
        message_id = item["id"]
        contents[message_id] = item

    return contents


def save_output(output, output_file): #saving the output file
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
    #very simple URL domain extraction.
    #example: http://fake.com/login -> fake.com
    link = link.replace("https://", "")
    link = link.replace("http://", "")

    parts = link.split("/")
    return parts[0].lower()


def check_unknown_sender(message):     #this function checks if the sender used a real email address, and if that email address domain is trusted (for example @polito.it)
    sender = message["sender_address"]
    domain = get_sender_domain(sender)

    if domain == "":
        return {
            "name": "unknown_sender",
            "weight": 15,           #each "red flag" has a weight assigned based on how likely it is to be phising, thease later on get added
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


def check_lookalike_domain(message):  #here we compare to the lookalike domain list to make sure that the messege is not trying to impersonate a real company (eg: microsoft.com vs rnicrosoft.com)
    sender = message["sender_address"]
    domain = get_sender_domain(sender)

    if domain in LOOKALIKE_DOMAINS:
        return {
            "name": "lookalike_domain",
            "weight": 25,
            "evidence": domain + " looks like " + LOOKALIKE_DOMAINS[domain]
        }

    return None


def check_urgent_words(message):   #checking for urgent keywords - thease scare people and make them more likely to take action (eg: Please take action immedietly or your account will be deleted today)
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


def check_credentials(message):      #here we check whether the messege is asking for user credentials such as a log in or password
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


def check_payment(message):       #checking wether the messege is asking the user to pay, for example requesting a gift card
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


def check_http_links(message):       #check if link is HTTP vs. HTTPS (more secure)
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


def check_suspicious_links(message):      #checking if the links is in the list of trusted domains
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


def check_attachments(message):           #finally we check for potentially dangerous attachments like executables etc
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


def classify(score):    #using the weights from each rule function we check if a messege is legitimate, suspecious or phising based on the sum of the total weights
    if score >= 50:
        return "phishing"
    elif score >= 20:
        return "suspicious"
    else:
        return "legitimate"


def analyze_message(message_id, contents):  #here we combine the results of all the previous functions
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

    for message_id in contents: #analyze each messege
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