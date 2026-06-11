# Rule-Based Phishing Detection Engine

## Description
This project is a simple Python phishing detector. It reads messages from a JSON file, checks them with fixed rules, gives each message a risk score, and classifies it as legitimate, suspicious, or phishing. It does not use machine learning.

## Python Version
Python 3

## Libraries
Only standard Python libraries are used:
- argparse
- json

`requirements.txt` is empty.

## How to Run
python3 main.py --input examples/messages.json --output examples/output.json

## Input
The input file is `examples/messages.json`. It contains a list of messages with fields such as id, channel, sender, subject, body, links, and attachments.

## Output
The output file contains a summary and one result for each message, including risk score, classification, triggered indicators, and evidence.

## Scores
0-19 = legitimate  
20-49 = suspicious  
50+ = phishing

## Data Structures
The main data structure is a dictionary called `contents`, where each message is stored using its message ID.

## Edge Case
If a sender is a phone number instead of an email address, it is treated as an unknown sender.

## Limitation
The detector is rule-based, so it can miss phishing messages that do not match the written rules.