import time
import os
from google import genai
import requests
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

client = genai.Client(api_key=GEMINI_API_KEY)

def add_to_blacklist(ip,reason):
    with open("blacklisted_ips.txt","a") as f:
        f.write(f"{ip}-{reason}\n")
    print(f"    [SOAR Action] Added IP {ip} to blacklist (blacklisted_ips.txt)")

def send_telegram_alert(ip,threat_level,reason):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Not Telegram Token or Chat ID, skip send warning")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    message = (
        f"🚨 *AI SOC AGENT ALERT* 🚨\n\n"
        f"📌 *Suspicious IP :* `{ip}`\n"
        f"⚠️ *Threat levl:* {threat_level}\n"
        f"📝 *Analyze AI:* {reason}\n\n"
        f"✅ *Action:* Automatic added `blacklisted_ips.txt`"
    )

    payload={
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload, timeout =5)
        if response.status_code == 200:
            print(f"[+] Sent warning Telegram message for IP {ip} success")
        else:
            print(f"[-] Error send Telegram message: {response.text}")
    except Exception as e:
        print(f"[!] Error connect Telegram API: {e}")

def analyze_with_ai(ip,port,failed_logins,reason):
    prompt= f"""
    You is a professional network analyzer SOC (Security Operations Center).
    Detect system just discovered an unusual log entry:
    - IP: {ip}
    - Port access: {port}
    - Failed logins: {failed_logins}
    - Reason from system: {reason}

    Provide a brief analysis covering three key points:
    1. [Threat]: What type of attack is this?
    2. [Risk Level]: What is the level of danger (Low/Medium/High/Critical)?
    3. [Recommended Action]: What should administrators do immediately?
    """
    try:
        response=client.models.generate_content(
            model="gemini-3.5-flash",
            contents=prompt,
        )
        return response.text
    except Exception as e:
        return f"[Error connect AI API]: {e}"

def process_single_log_entry(ip,port,failed_logins,reason):
    print(f"[!] [Thread Worker] Processing threat for IP: {ip} ({reason})")

    add_to_blacklist(ip,reason)

    ai_analysis= analyze_with_ai(ip,port,failed_logins,reason)

    print("\n" + "="*50)
    print(f"    Result analysis from IP: {ip}")
    print("=" * 50)
    print(ai_analysis)
    print("="*50 + "\n")

    send_telegram_alert(
        ip=ip,
        threat_level="High / Critical",
        reason=reason
    )
    return ip

def scan_logs_from_file(file_path,max_workers=5):
    start_time=time.time()
    suspicious_tasks=[]
    print("---- Scan log from file (Multi-threaded) ----\n")
    with open(file_path,"r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            data=line.split(",")
            ip=data[0]
            port=int(data[1])
            failed_logins=int(data[2])
            is_suspicious = False
            reason = ""
            if failed_logins > 3 :
                is_suspicious= True
                reason = f"Failed logins than 3 access attempts({failed_logins} attempts)"
            elif port==22:
                is_suspicious= True
                reason = f"Scan SSH port (port {port})"

            if not is_suspicious:
                print(f"[+] IP {ip}: Safe")
            else:
                suspicious_tasks.append((ip,port,failed_logins,reason))
    if suspicious_tasks:
        print(f"\n[!] Found {len(suspicious_tasks)} suspicious IPs. Starting {max_workers} worker threads... ")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(process_single_log_entry,task[0],task[1],task[2],task[3])
                for task in suspicious_tasks
            ]
            for future in as_completed(futures):
                completed_ip=future.result()
    execution_time=time.time()-start_time
    print(f"\n [COMPLETED] Finished scanning logs in {execution_time:.2f} seconds!")
scan_logs_from_file("server_logs.txt")