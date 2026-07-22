import os
from google import genai

client = genai.Client()

def add_to_blacklist(ip,reason):
    with open("blacklisted_ips.txt","a") as f:
        f.write(f"{ip}-{reason}\n")
    print(f"    [SOAR Action] Added IP {ip} to blacklist (blacklisted_ips.txt)")

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

def scan_logs_from_file(file_path):
    print("---- Scan log from file ----")
     
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
                reason = f"Failed logins than 3 access attempts({failed_logins} lan)"
            elif port==22:
                is_suspicious= True
                reason = f"Scan SSH port (port {port})"

            if not is_suspicious:
                print(f"[+] IP {ip}: Safe")
            else:
                add_to_blacklist(ip,reason)
                print(f"[!] WARNING IP {ip}: {reason}")
                print("    ---> [AI Agent] Analyzing threats...")

                ai_analysis=analyze_with_ai(ip,port,failed_logins,reason)

                print("\n" + "="*50)
                print(f"    Result analysis from IP: {ip}")
                print("=" * 50)
                print(ai_analysis)
                print("="*50 + "\n")
scan_logs_from_file("server_logs.txt")