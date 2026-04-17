import requests
import urllib3
import argparse
import sys
import os
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

checked_count = 0
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
}

def check_lfm(domain, total):
    global checked_count
    domain = domain.strip()
    if not domain: return

    # Coba https dulu, baru http
    protocols = [f"https://{domain}", f"http://{domain}"] if not domain.startswith('http') else [domain]
    paths = ["/laravel-filemanager", "/filemanager", "/file-manager"]
    found_anything = False
    
    for base in protocols:
        if found_anything: break
        for path in paths:
            target = base.rstrip('/') + path
            try:
                # 1. Cek rute utama (allow_redirects=False agar tidak tertipu redirect dashboard lain)
                r = requests.get(target, headers=HEADERS, verify=False, timeout=10, allow_redirects=False)
                
                # Deteksi VULN (Hanya jika benar-benar minta login)
                if r.status_code in [301, 302]:
                    loc = r.headers.get('Location', '').lower()
                    if 'login' in loc:
                        print(f"\n{Fore.GREEN}[+] VULN (Auth): {target}")
                        with open("lfm_detected.txt", "a") as f: f.write(target + "\n")
                        found_anything = True; break
                
                # Deteksi OPEN (Validasi Strict)
                elif r.status_code == 200:
                    content = r.text
                    # Keyword ini HARUS ada di LFM asli (Unisharp). 
                    # Halaman "Page Not Found" atau "Website Disabled" kaga mungkin punya ID ini.
                    strict_signatures = [
                        'id="working_dir"', 
                        'id="nav-buttons"', 
                        'loadItems()', 
                        'refreshContents()',
                        'vendor/laravel-filemanager'
                    ]
                    
                    # Minimal harus nemu 2 signature biar valid
                    hits = sum(1 for sig in strict_signatures if sig in content)
                    if hits >= 2:
                        print(f"\n{Fore.CYAN}[!] OPEN (CONFIRMED): {target}")
                        with open("lfm_open.txt", "a") as f: f.write(target + "\n")
                        found_anything = True; break
                
                # 2. Opsional: Cek API initialize kalau rute utama ga nampilin HTML (beberapa versi LFM cuma API)
                if not found_anything:
                    r_api = requests.get(target + "/initialize", headers=HEADERS, verify=False, timeout=7)
                    if r_api.status_code == 200 and '"disks"' in r_api.text:
                        print(f"\n{Fore.CYAN}[!] OPEN (API Valid): {target}")
                        with open("lfm_open.txt", "a") as f: f.write(target + "\n")
                        found_anything = True; break

            except:
                break

    # Update progres bar
    checked_count += 1
    percent = (checked_count / total) * 100
    sys.stdout.write(f"\r{Style.DIM}[{checked_count}/{total}] [{percent:.2f}%] Sniper Scanning...{Style.RESET_ALL}")
    sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--list", required=True)
    parser.add_argument("-t", "--threads", type=int, default=30)
    args = parser.parse_args()

    try:
        with open(args.list, 'r') as f: domains = [l.strip() for l in f if l.strip()]
    except: print(f"{Fore.RED}File list tidak ada!"); sys.exit()

    total = len(domains)
    os.system('clear')
    print(f"{Fore.YELLOW}{'='*60}")
    print(f"{Style.BRIGHT}{Fore.YELLOW}      LFM SNIPER")
    print(f"{Fore.YELLOW}{'='*60}")
    print(f"[*] Target : {total} domain | Threads: {args.threads}\n")
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for dom in domains: executor.submit(check_lfm, dom, total)
    print(f"\n\n{Fore.YELLOW}[*] Selesai! Hasil beneran tembus di lfm_open.txt")

if __name__ == "__main__":
    main()
