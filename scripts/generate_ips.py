import asyncio
import socket
import sys
from datetime import datetime

import requests

# ---------- تنظیمات ----------
CHECK_ALIVE = True           # آیا تست زنده بودن انجام شود؟
TIMEOUT = 1.5                # ثانیه برای تست TCP
CONCURRENCY = 50             # تعداد تست هم‌زمان
PORT = 443
FASTLY_URL = "https://api.fastly.com/public-ip-list"
AKAMAI_URL = "https://raw.githubusercontent.com/platformbuilds/Akamai-ASN-and-IPs-List/master/akamai_ipv4.txt"

# ---------- دریافت IP ها ----------
def fetch_fastly_ips():
    resp = requests.get(FASTLY_URL, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    # فقط IPv4 (بدون IPv6)
    ips = [addr for addr in data.get("addresses", []) if ":" not in addr]
    return ips

def fetch_akamai_ips():
    resp = requests.get(AKAMAI_URL, timeout=30)
    resp.raise_for_status()
    lines = resp.text.strip().split('\n')
    ips = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
    return ips

# ---------- تبدیل CIDR به اولین IP قابل تست ----------
def first_ip_in_cidr(cidr: str):
    """اولین IP میزبان (بعد از آدرس شبکه) را از یک CIDR برمی‌گرداند."""
    try:
        ip_str, bits = cidr.split('/')
        bits = int(bits)
        ip_parts = list(map(int, ip_str.split('.')))
        ip_int = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3]
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        network = ip_int & mask
        # اولین IP بعد از آدرس شبکه (یا در صورت /31 و /32 خودش)
        if bits >= 31:
            host_ip = network
        else:
            host_ip = network + 1
        # تبدیل به رشته
        return f"{(host_ip >> 24) & 0xFF}.{(host_ip >> 16) & 0xFF}.{(host_ip >> 8) & 0xFF}.{host_ip & 0xFF}"
    except Exception:
        return None

# ---------- تست زنده بودن ----------
async def check_ip(ip: str, semaphore):
    """بررسی TCP handshake روی پورت و IP داده‌شده."""
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, PORT),
                timeout=TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

async def filter_alive_cidrs(cidr_list: list) -> list:
    """برای هر CIDR اولین IP را تست می‌کند و فقط CIDRهای زنده را برمی‌گرداند."""
    semaphore = asyncio.Semaphore(CONCURRENCY)
    results = []
    tasks = []
    mapping = {}  # ip -> cidr

    for cidr in cidr_list:
        ip = first_ip_in_cidr(cidr)
        if ip is None:
            continue
        mapping[ip] = cidr
        tasks.append(check_ip(ip, semaphore))

    print(f"Testing {len(tasks)} IPs for liveness...")
    statuses = await asyncio.gather(*tasks)

    alive = set()
    for ip, alive_flag in zip(mapping.keys(), statuses):
        if alive_flag:
            alive.add(mapping[ip])

    # CIDRهایی که حداقل یک IP زنده داشتند
    filtered = [cidr for cidr in cidr_list if cidr in alive]
    return filtered

# ---------- ذخیره‌سازی ----------
def save_list(filename, ip_list):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"# Updated: {datetime.utcnow().isoformat()} UTC\n")
        for ip in sorted(ip_list):
            f.write(ip + '\n')

# ---------- main ----------
async def main():
    print("Fetching Fastly...")
    fastly_raw = fetch_fastly_ips()
    print(f"Fastly raw: {len(fastly_raw)}")

    print("Fetching Akamai...")
    akamai_raw = fetch_akamai_ips()
    print(f"Akamai raw: {len(akamai_raw)}")

    # یکتاسازی
    fastly_set = sorted(set(fastly_raw))
    akamai_set = sorted(set(akamai_raw))
    combined = sorted(set(fastly_set + akamai_set))

    if CHECK_ALIVE:
        print("Filtering alive CIDRs...")
        fastly_alive = await filter_alive_cidrs(fastly_set)
        akamai_alive = await filter_alive_cidrs(akamai_set)
        combined_alive = sorted(set(fastly_alive + akamai_alive))

        print(f"Alive: Fastly {len(fastly_alive)}/{len(fastly_set)}, "
              f"Akamai {len(akamai_alive)}/{len(akamai_set)}, "
              f"Combined {len(combined_alive)}/{len(combined)}")

        save_list("fastly_ips.txt", fastly_alive)
        save_list("akamai_ips.txt", akamai_alive)
        save_list("combined_ips.txt", combined_alive)
    else:
        save_list("fastly_ips.txt", fastly_set)
        save_list("akamai_ips.txt", akamai_set)
        save_list("combined_ips.txt", combined)

    print("Done.")

if __name__ == "__main__":
    asyncio.run(main())
