"""SYN-flood detector: threshold baseline.
Uses synthetic data only. No real network traffic is captured or published.
"""
import random
from collections import defaultdict

random.seed(42)

def make_traffic(seconds=60, attack_start=40, attack_end=50):
    """Return a list of (second, src_ip, flag) tuples."""
    events = []
    for t in range(seconds):
        # Normal: ~20 clients each completing a handshake (SYN then ACK)
        for _ in range(random.randint(15, 25)):
            src = f"10.0.0.{random.randint(1, 50)}"
            events.append((t, src, "SYN"))
            events.append((t, src, "ACK"))
        # Attack: many SYNs from random spoofed sources, no final ACK
        if attack_start <= t < attack_end:
            for _ in range(random.randint(300, 500)):
                src = f"203.0.113.{random.randint(1, 254)}"
                events.append((t, src, "SYN"))
    return events

def half_open_per_second(events):
    syn = defaultdict(int)
    ack = defaultdict(int)
    for t, _, flag in events:
        if flag == "SYN":
            syn[t] += 1
        elif flag == "ACK":
            ack[t] += 1
    return {t: syn[t] - ack[t] for t in syn}

def detect(half_open, threshold=100):
    return [t for t, v in sorted(half_open.items()) if v > threshold]

if __name__ == "__main__":
    events = make_traffic()
    ho = half_open_per_second(events)
    alerts = detect(ho)
    print(f"Alert seconds: {alerts}")