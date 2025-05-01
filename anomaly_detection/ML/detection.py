import threading
import time
from datetime import datetime, timedelta
from collections import deque, Counter

import pyshark
import numpy as np
from gensim.models import Word2Vec
from sklearn.metrics.pairwise import cosine_similarity

# ———— 參數區 ————
INTERFACE = "ens33"            # 網卡介面
WINDOW_SIZE = 30               # 窗口長度（秒），只保留最近 50 秒的封包
SLIDE_INTERVAL = 10            # 滑動間隔（秒），每 20 秒偵測一次
SIMILARITY_THRESH = 0.93       # 相似度閾值
MODEL_PATH = "benign_w2v.model"
VECS_PATH = "benign_vectors.npy"
MALICIOUS_LOG = "malicious.txt"

# ———— 載入模型與正常向量 ————
model = Word2Vec.load(MODEL_PATH)
benign_vectors = np.load(VECS_PATH)    # shape=(n_sentences, vector_size)

# ———— 輔助函式 ————
def row_to_token(pkt):
    """將封包轉為 <Protocol>_F<func> token，並自定義 Modbus/TCP 輸出"""
    proto = getattr(pkt, "highest_layer", "UNKNOWN")
    
    # 自定義 Modbus/TCP 協議輸出
    if proto == "MODBUS":
        proto = "Modbus/TCP"
    
    func = getattr(pkt, "modbus", None) and getattr(pkt.modbus, "func_code", None)
    if func is None:
        return f"{proto}_UNK"  # 無功能碼時返回 UNK
    return f"{proto}_F{func}"  # 保留功能碼部分（fun 不變）

def sentence_to_vector(tokens):
    vecs = [model.wv[t] for t in tokens if t in model.wv]
    if not vecs:
        return np.zeros(model.vector_size)
    return np.mean(vecs, axis=0)

def avg_similarity(vec, normal_vecs):
    return float(cosine_similarity([vec], normal_vecs).mean())

# ———— 全域佇列 & 執行緒停止旗標 ————
packet_deque = deque()   # 儲存 (timestamp:datetime, token:str, src_ip:str)
stop_event = threading.Event()

# ———— 封包擷取執行緒 ————
def capture_packets():
    capture = pyshark.LiveCapture(interface=INTERFACE)
    for pkt in capture.sniff_continuously():
        if stop_event.is_set():
            break
        # 時間、token、來源 IP
        t = pkt.sniff_time                             # datetime
        token = row_to_token(pkt)
        ip_src = getattr(pkt, "ip", None) and pkt.ip.src or "0.0.0.0"
        packet_deque.append((t, token, ip_src))

# ———— 偵測執行緒 ————
def sliding_window_detect():
    while not stop_event.is_set():
        time.sleep(SLIDE_INTERVAL)
        now = datetime.now()
        cutoff = now - timedelta(seconds=WINDOW_SIZE)
        
        # 1. 清除過舊資料
        while packet_deque and packet_deque[0][0] < cutoff:
            packet_deque.popleft()
        
        if not packet_deque:
            print(f"[{now.isoformat()}] 窗口內無流量，跳過偵測")
            continue
        
        # 2. 收集 tokens 與來源 IP
        tokens = [tok for (_, tok, _) in packet_deque]
        src_ips = [ip for (_, _, ip) in packet_deque]
        
        # 3. 計算句子向量與相似度
        vec = sentence_to_vector(tokens)
        sim = avg_similarity(vec, benign_vectors)
        print(f"[{now.isoformat()}] 相似度={sim:.3f}", end=" ")
        
        # 4. 如果低於閾值，記錄最常出現的 IP
        if sim < SIMILARITY_THRESH:
            suspect_ip = Counter(src_ips).most_common(1)[0][0]
            with open(MALICIOUS_LOG, "a") as f:
                f.write(f"{now.isoformat()} {suspect_ip} sim={sim:.3f}\n")
            print(f"→ 偵測到惡意行為：{suspect_ip}")
        else:
            print("→ 判定為正常")

# ———— 主程式 ————
if __name__ == "__main__":
    print("啟動滑動窗口偵測...")
    # 啟動執行緒
    t1 = threading.Thread(target=capture_packets, daemon=True)
    t2 = threading.Thread(target=sliding_window_detect, daemon=True)
    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n收到終止訊號，正在結束...")
        stop_event.set()
        t1.join()
        t2.join()
        print("偵測已停止。")
