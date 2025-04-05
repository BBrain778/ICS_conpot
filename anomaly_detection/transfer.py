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
        # 取得 pcap 檔案中的協定
        protocols = subprocess.run(["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.protocols"], capture_output=True, text=True, check=True).stdout.strip().split("\n")
        unique_protocols = set(proto.split(":")[-1] for proto in protocols) #將協定去重複
        print(f"pcap檔案協定: {unique_protocols}")

        # 根據協定選擇 tshark 欄位
        tshark_fields = ["frame.number", "frame.time", "ip.src", "ip.dst", "frame.protocols", "frame.len", "tcp.srcport", "tcp.dstport", "tcp.flags", "udp.srcport", "udp.dstport", "frame.time_relative", "ip.proto"]
        if "HTTP" in unique_protocols:
            tshark_fields.extend(["http.request.method", "http.response.code"])
        if "DNS" in unique_protocols:
            tshark_fields.extend(["dns.qry.name", "dns.rsp.type"])
        if "ICMP" in unique_protocols:
            tshark_fields.extend(["icmp.type", "icmp.code"])
        if "TLS" in unique_protocols:
            tshark_fields.extend(["tls.handshake.type", "tls.handshake.certificate"])
        tshark_fields.extend(["frame.cap_len" , "frame.interface_id", "frame.coloring_rule.name", "frame.comment", "tcp.options.timestamp.tsval", "tcp.options.timestamp.tsecr"])

        # 執行 tshark 命令
        with open(text_file, 'w') as f:
            tshark_command = ["tshark", "-r", pcap_file, "-T", "fields"] + ["-e", field for field in tshark_fields]
            subprocess.run(tshark_command, stdout=f, check=True, stderr=subprocess.PIPE, text=True)

        print(f"pcap 檔案轉換完成，檔案儲存於：{text_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"pcap 檔案轉換失敗：{e}")
        print(f"tshark stderr: {e.stderr}")
        return False

def main():
    interface = "ens33"  # 請替換為您的網路介面
    duration = 10      # 監控時間（秒）
    pcap_file = "/tmp/capture.pcap"
    text_file = "/tmp/capture.txt"

    try:
        if capture_traffic(interface, duration, pcap_file):
            pcap_to_text(pcap_file, text_file)
    except Exception as e:
        print(f"發生錯誤: {e}")

if __name__ == "__main__":
    main()
