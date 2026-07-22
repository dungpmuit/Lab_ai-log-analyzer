import os
from google import genai

client = genai.Client()

def add_to_blacklist(ip,reason):
    with open("blacklisted_ips.txt","a") as f:
        f.write(f"{ip}-{reason}\n")
    print(f"    [SOAR Action] Da them IP {ip} vao danh sach den (blacklisted_ips.txt)")

def analyze_with_ai(ip,port,failed_logins,reason):
    prompt= f"""
    Bạn là một chuyển gia phân tích an ninh mạng SOC (Security Operations Center).
    Hệ thống giám sát vừa phát hiện một dòng log bất thường:
    - Địa chỉ IP: {ip}
    - Port truy cập: {port}
    - Số lần đăng nhập thất bại: {failed_logins}
    - Lý do cảnh báo từ hệ thống: {reason}

    Hãy đưa ra phân tích ngắn gọn theo 3 ý chính:
    1. [Mối đe dọa]: Đây là kiểu tấn công gì?
    2. [Mức độ rủi ro]: Ngay hiểm ở mức nào (Thấp/Trung bình/Cao/Nghiêm trọng)?
    3. [Hành động khuyến nghị]: Quản trị viên nên làm gì ngay lập tức?
    """
    try:
        response=client.models.generate_content(
            model="gemini-3.5-flash",
            contents=prompt,
        )
        return response.text
    except Exception as e:
        return f"[Lỗi kết nối AI API]: {e}"

def scan_logs_from_file(file_path):
    print("---- BAT DAU QUET LOG TU FILE ----")
     
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
                reason = f"Dang nhap sai qua 3 lan ({failed_logins} lan)"
            elif port==22:
                is_suspicious= True
                reason = f"Do quet cong SSH (port {port})"

            if not is_suspicious:
                print(f"[+] IP {ip}: An toan")
            else:
                add_to_blacklist(ip,reason)
                print(f"[!] CANH BAO IP {ip}: {reason}")
                print("    ---> [AI Agent] Dang phan tich moi de doa...")

                ai_analysis=analyze_with_ai(ip,port,failed_logins,reason)

                print("\n" + "="*50)
                print(f"    KET QUA PHAN TICH TU AI DANH CHO IP {ip}")
                print("=" * 50)
                print(ai_analysis)
                print("="*50 + "\n")
scan_logs_from_file("server_logs.txt")i