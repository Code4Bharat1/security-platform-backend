#!/usr/bin/env python3
import socket, ssl, sys, re, json, time, argparse, ipaddress
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_ip_address(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def has_suspicious_keywords(url: str) -> bool:
    keywords = ['login', 'secure', 'verify', 'update', 'bonus', 'win', 'bank', 'signin', 'paypal']
    low = url.lower()
    return any(k in low for k in keywords)

def is_valid_https_cert(domain: str):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            if not cert:
                return False, {"message": "No SSL certificate found"}
            return True, {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "notAfter": cert.get("notAfter")
            }
    except Exception as e:
        return False, {"message": f"SSL check failed: {e}"}

def is_url_safe(url: str, allow_insecure: bool):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path  # allow plain domains
    if not parsed.scheme:
        # default to https if not provided
        parsed = urlparse("https://" + url)
        domain = parsed.netloc

    if parsed.scheme != 'https' and not allow_insecure:
        return False, {"message": "URL does not use HTTPS"}

    if is_ip_address(domain):
        return False, {"message": "IP-based URL — not recommended"}

    if has_suspicious_keywords(url):
        return False, {"message": "Suspicious keywords found in URL"}

    ok, info = is_valid_https_cert(domain)
    if not ok and not allow_insecure:
        return False, info

    return True, {"message": "URL passed basic safety checks", "ssl": info if ok else None}

def scan_one(target_ip: str, port: int, conn_timeout: float = 0.25) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(conn_timeout)
            return sock.connect_ex((target_ip, port)) == 0
    except Exception:
        return False

def scan_ports(target: str, start_port: int, end_port: int, workers: int = 400):
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"error": f"Could not resolve target: {target}"}

    t0 = time.time()
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_one, target_ip, p): p for p in range(start_port, end_port + 1)}
        for fut in as_completed(futures):
            p = futures[fut]
            if fut.result():
                open_ports.append(p)
    open_ports.sort()

    duration_ms = int((time.time() - t0) * 1000)
    return {
        "target": target,
        "targetIp": target_ip,
        "range": [start_port, end_port],
        "durationMs": duration_ms,
        "openPorts": open_ports
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="https://example.com or domain")
    ap.add_argument("--start-port", type=int, default=1)
    ap.add_argument("--end-port", type=int, default=1024)
    ap.add_argument("--allow-insecure", action="store_true", help="skip HTTPS requirement/SSL checks")
    args = ap.parse_args()

    url = args.url
    parsed = urlparse(url)
    target = parsed.netloc or parsed.path

    safe, safety_info = is_url_safe(url, allow_insecure=args.allow_insecure)
    result = {
        "url": url,
        "target": target,
        "safety": {"ok": bool(safe), **safety_info},
    }

    if not safe:
        print(json.dumps(result), flush=True)
        return

    scan = scan_ports(target, args.start_port, args.end_port)
    result.update(scan)

    # simple suspicious-port heuristic
    risky = {21,22,23,25,110,139,143,445,465,587,993,995,1433,1521,2049,2375,3306,3389,5432,5900,5985,5986,6379,9200}
    result["suspicious"] = [p for p in result.get("openPorts", []) if p in risky]

    # quick risk tier
    total = max(1, args.end_port - args.start_port + 1)
    open_count = len(result.get("openPorts", []))
    if open_count > total * 0.3:
        tier = "High"
    elif open_count > total * 0.1:
        tier = "Medium"
    else:
        tier = "Low"
    result["riskAssessment"] = tier

    print(json.dumps(result), flush=True)

if __name__ == "__main__":
    main()
