import subprocess
import os

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
                "-e", "udp.dstport",
                "-e", "ip.proto",   
                "-e", "tcp.stream",     
                "-e", "udp.stream",     
                "-e", "icmp.type",   
                "-e", "icmp.code",     
                "-e", "tls.handshake.type", 
                "-e", "tls.handshake.certificate", 
                "-e", "frame.comment", 
                "-e", "tcp.options.timestamp.tsval", 
                "-e", "tcp.options.timestamp.tsecr"
            ], stdout=f, check=True)
        print(f"pcap 檔案轉換完成，檔案儲存於：{text_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"pcap 檔案轉換失敗：{e}")
        return False

def main():
    interface = "ens33"  # 請替換為您的網路介面
    duration = 10        # 監控時間（秒）

    # 取得使用者目錄
    output_dir = "/home/bbrain/analyst"
    pcap_file = os.path.join(user_dir, "capture.pcap")
    text_file = os.path.join(user_dir, "capture.txt")

    if capture_traffic(interface, duration, pcap_file):
        pcap_to_text(pcap_file, text_file)

if __name__ == "__main__":
    main()
