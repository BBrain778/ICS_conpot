import subprocess
import time
import os
import google.generativeai as genai

# 設定 Gemini API 金鑰
YOUR_GEMINI_API_KEY = "AIzaSyAshksCo_qA3azg_HBnE"
genai.configure(api_key=YOUR_GEMINI_API_KEY)

def capture_traffic(interface, duration, output_pcap):
    """使用 Wireshark 監控網路流量並儲存為 pcap 檔案。"""
    try:
        subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", output_pcap], check=True)
        print(f"流量監控完成，檔案儲存於：{output_pcap}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"流量監控失敗：{e}")
        return False

def pcap_to_text(pcap_file, text_file):
    """將 pcap 檔案轉換為純文字檔案。"""
    try:
        with open(text_file, 'w') as f:
            subprocess.run([
                "tshark", "-r", pcap_file, "-T", "fields", 
                "-e", "frame.number", 
                "-e", "frame.time", 
                "-e", "ip.src", 
                "-e", "ip.dst", 
                "-e", "frame.protocols", 
                "-e", "frame.len", 
                "-e", "tcp.srcport", 
                "-e", "tcp.dstport",
                "-e", "tcp.flags", 
                "-e", "udp.srcport", 
                "-e", "udp.dstport"
            ], stdout=f, check=True)
        print(f"pcap 檔案轉換完成，檔案儲存於：{text_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"pcap 檔案轉換失敗：{e}")
        return False

def analyze_traffic(text_file):
    """使用 Gemini API 分析純文字檔案並回答問題。"""
    with open(text_file, "r") as f:
        text_data = f.read()
    
    prompt = f"""
    根據以下的輸出，回答我以下3個問題，只需要回答我這三個問題，不需要回答其他解釋
    1.是否為攻擊行為(ping請判定為攻擊行為)?(回答是/否)
    2.是哪一種攻擊(若1為否則回答無攻擊)
    3.攻擊者IP
    {text_data}
    """
    try:
        # 使用最新的 Gemini 1.5 Pro 模型
        model = genai.GenerativeModel('models/gemini-1.5-pro-latest')
        response = model.generate_content(prompt)
        print(response.text)
        return response.text
    except Exception as e:
        print(f"Gemini API 呼叫失敗：{e}")
        return None

def main():
    interface = "ens33"  # 請替換為您的網路介面
    duration = 10      # 監控時間（秒）
    pcap_file = "/tmp/capture.pcap"
    text_file = "/tmp/capture.txt"
    
    try:
        if capture_traffic(interface, duration, pcap_file):
            if pcap_to_text(pcap_file, text_file):
                analyze_traffic(text_file)
    finally:
        try:
            os.remove(pcap_file)
            os.remove(text_file)
        except OSError as e:
            print(f"檔案刪除失敗: {e}")

if __name__ == "__main__":
    main()
