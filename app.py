import os
import sys
import time
import json
import base64
import hashlib
import threading
from datetime import datetime

# API Dependencies
import requests
import urllib3
import urllib.parse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Protobuf imports fallback logic as per your script
try:
    import MajoRLogin_pb2 as mLpB
    import MajorLoginRes_pb2 as mLrPb
except ImportError:
    print("\n[!] Error: Protobuf files (MajoRLogin_pb2.py, MajorLoginRes_pb2.py) not found!")
    sys.exit()

urllib3.disable_warnings()

# Initialize FastAPI instance
app = FastAPI(
    title="FF Login History Web API",
    description="Full feature extraction backend parsed directly through HTTP requests.",
    version="1.0.0"
)

# --- GLOBAL LOGIC & CONFIGURATION (Exactly from your script) ---

AeSkEy = b'Yg&tc%DEuh6%Zc^8'
AeSiV  = b'6oyZDr22E3ychjM%'
MAJOR_LOGIN_URL = "https://loginbp.ggpolarbear.com/MajorLogin"

MAJOR_LOGIN_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-S908E Build/TP1A.220624.014)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "Expect": "100-continue",
    "X-GA": "v1 1",
    "X-Unity-Version": "2018.4.11f1",
    "ReleaseVersion": "OB54"
}

PLATFORM_MAP = {
    3: "Facebook",
    4: "Guest",
    5: "VK",
    6: "Huawei",
    8: "Google",
    11: "X (Twitter)",
    13: "AppleId",
}

# --- CRYPTO & CORE ENGINE UTILITIES ---

def enc(d):
    return AES.new(AeSkEy, AES.MODE_CBC, AeSiV).encrypt(pad(d, 16))

def dec(d):
    try:
        return unpad(AES.new(AeSkEy, AES.MODE_CBC, AeSiV).decrypt(d), 16)
    except:
        return d

def get_base_url(lock_region):
    lock_region = lock_region.upper()
    ind_regions = ["IND"]
    us_regions = ["BR", "US", "NA", "SAC"]
    if lock_region in ind_regions:
        return "https://client.ind.freefiremobile.com"
    elif lock_region in us_regions:
        return "https://client.us.freefiremobile.com"
    else:
        return "https://clientbp.ggpolarbear.com"

def build_majorlogin(tok, open_id, p_type):
    m = mLpB.MajorLogin()
    m.event_time = str(datetime.now())[:-7]
    m.game_name = "free fire"
    m.platform_id = p_type
    m.client_version = "1.120.1"
    m.system_software = "Android OS 9 / API-28"
    m.system_hardware = "Handheld"
    m.telecom_operator = "Verizon"
    m.network_type = "WIFI"
    m.screen_width = 1920
    m.screen_height = 1080
    m.screen_dpi = "280"
    m.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    m.memory = 3003
    m.gpu_renderer = "Adreno (TM) 640"
    m.gpu_version = "OpenGL ES 3.1 v1.46"
    m.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    m.client_ip = "223.191.51.89"
    m.language = "en"
    m.open_id = open_id
    m.open_id_type = str(p_type)
    m.device_type = "Handheld"
    m.access_token = tok
    m.platform_sdk_id = 1
    m.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    m.login_by = 3
    m.channel_type = 3
    m.cpu_type = 2
    m.cpu_architecture = "64"
    m.client_version_code = "2019118695"
    m.login_open_id_type = p_type
    m.origin_platform_type = str(p_type)
    m.primary_platform_type = str(p_type)
    return enc(m.SerializeToString())

def read_varint(data, offset):
    res = 0
    shift = 0
    while True:
        if offset >= len(data):
            break
        b = data[offset]
        offset += 1
        res |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, offset

def parse_record(data):
    rec = {}
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        wt, f = tag & 7, tag >> 3
        if wt == 0:
            val, offset = read_varint(data, offset)
            if f == 1:
                rec['ts'] = val
            elif f == 2:
                rec['ram'] = val
        elif wt == 2:
            length, offset = read_varint(data, offset)
            val = data[offset:offset+length]
            offset += length
            if f == 3:
                rec['dev'] = val.decode(errors='ignore')
            elif f == 4:
                rec['arch'] = val.decode(errors='ignore')
        else:
            break
    return rec

def parse_history_protobuf(data):
    records = []
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        wt, f = tag & 7, tag >> 3
        if wt == 0:
            val, offset = read_varint(data, offset)
        elif wt == 2:
            length, offset = read_varint(data, offset)
            val = data[offset:offset+length]
            offset += length
            if f == 1:
                records.append(parse_record(val))
        else:
            break
    return records

def get_jwt_from_access(tok):
    oId = None
    try:
        r = requests.get(f"https://100067.connect.garena.com/oauth/token/inspect?token={tok}", headers={"User-Agent": "Mozilla/5.0"}, timeout=5).json()
        oId = r.get("open_id")
    except:
        pass

    if not oId:
        try:
            uid_headers = {"access-token": tok, "user-agent": "Mozilla/5.0 (Linux; Android 10; K) Chrome/124.0.0.0"}
            uid_res = requests.get("https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/", headers=uid_headers, verify=False, timeout=5).json()
            uid = uid_res.get("uid")
            if uid:
                openid_res = requests.post("https://topup.pk/api/auth/player_id_login", headers={"Content-Type": "application/json"}, json={"app_id": 100067, "login_id": str(uid)}, verify=False, timeout=5).json()
                oId = openid_res.get("open_id")
        except:
            pass

    if not oId:
        return None

    platforms = [8, 3, 4, 6]
    for p_type in platforms:
        pl = build_majorlogin(tok, oId, p_type)
        try:
            x = requests.post(MAJOR_LOGIN_URL, headers=MAJOR_LOGIN_HEADERS, data=pl, timeout=10, verify=False)
            if x.status_code == 200:
                res = mLrPb.MajorLoginRes()
                try:
                    res.ParseFromString(dec(x.content))
                except:
                    res.ParseFromString(x.content)
                if res.token:
                    return res.token
        except:
            continue
    return None

def decode_ff_name(b64_str):
    try:
        key = b"1e5898ccb8dfdd921f9bdea848768b64a201"
        b64_str = b64_str.strip()
        b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
        encrypted_bytes = base64.b64decode(b64_str)
        decrypted_bytes = bytearray()
        for i, byte in enumerate(encrypted_bytes):
            key_byte = key[i % len(key)]
            decrypted_bytes.append(byte ^ key_byte)
        name = decrypted_bytes.decode('utf-8', errors='ignore')
        return name
    except Exception as e:
        return f"Error decoding: {str(e)}"

# --- FASTAPI UTILITY PIPELINE (Adapted cleanly without CLI Prints) ---

def api_get_player_info(jwt):
    try:
        payload_b64 = jwt.split('.')[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
        raw_nickname = decoded.get("nickname", "Unknown")
        name = decode_ff_name(raw_nickname)
        uid = decoded.get("account_id", "Unknown")
        region = decoded.get("lock_region", "Unknown")
        p_id = decoded.get("external_type", 0)
        platform = PLATFORM_MAP.get(p_id, f"Unknown ({p_id})")
        base_url = get_base_url(region)
        
        return {
            "account_name": name,
            "account_id": uid,
            "platform": platform,
            "region": region,
            "base_url": base_url,
            "error": None
        }
    except Exception as e:
        return None, None, f"Could not parse Player Info: {str(e)}"

def api_get_history(jwt, base_url):
    history_url = f"{base_url}/GetLoginHistory"
    history_headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB54",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
        "Host": base_url.replace("https://", ""),
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br"
    }
    try:
        r = requests.post(history_url, headers=history_headers, data=enc(b""), timeout=15, verify=False)
        if r.status_code != 200:
            return None, f"History Request Failed: HTTP {r.status_code}"
        try:
            d = dec(r.content)
        except:
            d = r.content
        records = parse_history_protobuf(d)
        
        parsed_records = []
        for rec in records:
            ts_raw = rec.get('ts', 0)
            try:
                date_str = datetime.fromtimestamp(ts_raw).strftime('%Y-%m-%d %H:%M:%S')
            except:
                date_str = "Invalid Timestamp"
            
            parsed_records.append({
                "time": date_str,
                "timestamp_raw": ts_raw,
                "device": rec.get('dev', 'Unknown Device'),
                "architecture": rec.get('arch', 'Unknown Architecture'),
                "ram_mb": rec.get('ram', 0)
            })
        return parsed_records, None
    except Exception as e:
        return None, f"Connection or Decoding Error: {str(e)}"

# --- FastAPI Schemas ---

class ExtractorRequest(BaseModel):
    token: str

# --- Endpoints ---

@app.post("/api/v1/extract")
async def extract_ff_data(payload: ExtractorRequest):
    raw_token = payload.token.strip()
    
    if not raw_token:
        raise HTTPException(status_code=400, detail="Empty input! Token cannot be blank.")
    
    # Identify Token Type (JWT or raw string access token)
    if raw_token.startswith("ey") and "." in raw_token:
        jwt = raw_token
    else:
        jwt = get_jwt_from_access(raw_token)
        
    if not jwt:
        raise HTTPException(status_code=401, detail="Failed to obtain JWT. Token invalid or expired.")
        
    # Run Account Info Extractor 
    player_data = api_get_player_info(jwt)
    if isinstance(player_data, tuple) and player_data[2]: # check for errors
        raise HTTPException(status_code=422, detail=player_data[2])
        
    base_url = player_data.pop("base_url") # Internal configuration context, pop out from user visibility
    
    # Fetch login logs array
    history_records, history_error = api_get_history(jwt, base_url)
    if history_error:
        raise HTTPException(status_code=502, detail=history_error)
        
    return {
        "status": "success",
        "developer_credit": ["@spideyabd", "@ROX_T10"],
        "data": {
            "player_info": player_data,
            "login_history": history_records
        }
    }

if __name__ == "__main__":
    import uvicorn
    # Local live test runtime server endpoint definition
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
