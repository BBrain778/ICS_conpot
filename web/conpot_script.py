from flask import Flask, render_template, request, redirect, url_for, session
import threading
import subprocess

app = Flask(__name__, template_folder="/app/templates")
app.secret_key = "your_secret_key"  # 替換為安全的隨機字串，用於 session 加密

# 簡單的帳號密碼字典（可改進為檔案或資料庫）
USERS = {"admin": "password123"}

# 首頁路由
@app.route("/")
def index():
    return render_template("index.html")

# 登入頁面路由
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username in USERS and USERS[username] == password:
            session["logged_in"] = True
            return redirect(url_for("control_panel"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html", error=None)

# 控制平台路由
@app.route("/control", methods=["GET", "POST"])
def control_panel():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # 初始化狀態
    signal_state = session.get("signal_state", "off")
    speed = session.get("speed", 50)
    track = session.get("track", "left")

    if request.method == "POST":
        # 更新信號燈
        if "state" in request.form:
            signal_state = request.form["state"]
            session["signal_state"] = signal_state
        # 更新速度
        elif "speed" in request.form:
            speed = request.form["speed"]
            session["speed"] = speed
        # 更新軌道
        elif "track" in request.form:
            track = request.form["track"]
            session["track"] = track
    
    return render_template("control.html", signal_state=signal_state, speed=speed, track=track)

# 啟動 Conpot 的函數
def run_conpot():
    cmd = [
        "/home/conpot/.local/bin/conpot",
        "--template", "/home/conpot/.local/lib/python3.6/site-packages/conpot-0.6.0-py3.6.egg/conpot/templates/default/",
        "--config", "/home/conpot/.local/lib/python3.6/site-packages/conpot-0.6.0-py3.6.egg/conpot/conpot.cfg"
    ]
    subprocess.run(cmd)

# 啟動 Flask 的函數
def run_flask():
    app.run(host="0.0.0.0", port=5000, debug=False)

if __name__ == "__main__":
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.start()
    run_conpot()
    flask_thread.join()
