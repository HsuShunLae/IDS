# Intrusion Detection System (IDS)

## Overview

This project implements a Network Intrusion Detection System (IDS) which is a hybrid of Signature and Anomaly to monitor and analyze network traffic for detecting potential attacks. It involves setting up attacker and victim environments, deploying IDS rules, integrating with Machine Learning and evaluating the system's performance.

## Environment Setup

### Attacker's Environment

A Kali Linux virtual machine is configured with various attack tools, including:

DoS Hulk

DoS GoldenEye

DoS Ripper

DoS Slowloris

hping3

bettercap

Built-in attack tools

### Victim's Environment

The victim machine hosts the IDS and monitors network traffic to detect potential threats. It integrates real-time monitoring and alerting capabilities to detect and mitigate attacks.

### IDS Environment Setup

Development Tools: Visual Studio Code installed on a machine for code deployment.

Python Environment: Python 3.8 configured for running the IDS.

Required Packages: Installed necessary Python libraries for the IDS implementation.

`pip install -r requirements.txt`

## Proposed Intercepted Attacks

✓ DoS/DDoS attacks 

✓ MITM (Man-in-the-Middle) attacks 

✓ SQL injection 

✓ XSS (Cross-Site Scripting) 

✓ Brute Force attacks 

✓ Anomalous Traffic Patterns 

✓ Zero-day attacks (which is expected) 

## Usage

```
usage: IDS.py [-h] -f FILENAME [-c PCAP]

Hybrid NIDS

optional arguments:
  -h, --help            show this help message and exit
  -f FILENAME, --filename FILENAME
                        Path to the rule file
  -c PCAP, --pcap PCAP  Path to the offline pcap file
```

## Conclusion

This IDS effectively detects and alerts on various network attacks using signature-based rules. Future improvements may include integrating anomaly-based detection for enhanced security.

