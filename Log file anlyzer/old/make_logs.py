import random
import datetime

def generate_test_logs(filename="sample_access.log"):
    # Attack patterns to trigger your specific regex rules
    attacks = [
        ("1.1.1.1", "/login", "401", "Mozilla/5.0"),          # Brute Force (will repeat 5x)
        ("2.2.2.2", "/api?id=1' OR 1=1--", "200", "Mozilla/5.0"), # SQL Injection
        ("3.3.3.3", "/../../etc/passwd", "403", "Mozilla/5.0"),   # Path Traversal
        ("4.4.4.4", "/index.html", "200", "sqlmap/1.4.11"),       # Malicious Scanner UA
    ]

    with open(filename, "w") as f:
        # 1. Generate 50 lines of normal traffic
        for _ in range(50):
            dt = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
            f.write(f'192.168.1.{random.randint(1,254)} - - [{dt}] "GET /home HTTP/1.1" 200 1500 "-" "Mozilla/5.0"\n')
        
        # 2. Inject the attacks
        for ip, path, status, ua in attacks:
            dt = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
            count = 5 if ip == "1.1.1.1" else 1
            for _ in range(count):
                f.write(f'{ip} - - [{dt}] "GET {path} HTTP/1.1" {status} 0 "-" "{ua}"\n')

    print(f"Created {filename} with normal traffic and 4 hidden security threats.")

generate_test_logs()
