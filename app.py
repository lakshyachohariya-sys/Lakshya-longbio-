#!

import sys
import json
import time
import base64
import hashlib
import requests
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONSTANTS ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
APP_ID = "100067"
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
FREEFIRE_VERSION = "OB54"

# Garena OAuth endpoints
OAUTH_REGISTER_URL = f"https://{APP_ID}.connect.garena.com/api/v2/oauth/guest:register"
OAUTH_TOKEN_URL    = f"https://{APP_ID}.connect.garena.com/oauth/guest/token/grant"
INSPECT_URL        = f"https://{APP_ID}.connect.garena.com/oauth/token/inspect"
MAJOR_LOGIN_URL    = "https://loginbp.ggpolarbear.com/MajorLogin"

# Bio update endpoints
UPDATE_URLS = [
    "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
    "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo",
    "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "https://clientbp.common.ggbluefox.com/UpdateSocialBasicInfo",
]

HEADERS_TEMPLATE = {
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

# ==================== PROTOBUF WRITER ====================
class ProtoWriter:
    @staticmethod
    def varint(value):
        result = []
        while value > 127:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value)
        return bytes(result)

    @staticmethod
    def tag(field_num, wire_type):
        return ProtoWriter.varint((field_num << 3) | wire_type)

    @staticmethod
    def write_varint(field_num, value):
        return ProtoWriter.tag(field_num, 0) + ProtoWriter.varint(value)

    @staticmethod
    def write_string(field_num, value):
        if isinstance(value, str):
            value = value.encode('utf-8')
        return ProtoWriter.tag(field_num, 2) + ProtoWriter.varint(len(value)) + value

    @staticmethod
    def create_message(fields):
        result = bytearray()
        for field_num, value in sorted(fields.items()):
            if isinstance(value, int):
                result.extend(ProtoWriter.write_varint(field_num, value))
            elif isinstance(value, str):
                result.extend(ProtoWriter.write_string(field_num, value))
        return bytes(result)

# ==================== CRYPTO HELPERS ====================
def encrypt(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def decrypt(data: bytes) -> bytes:
    if len(data) % 16 != 0:
        return data
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    dec = cipher.decrypt(data)
    try:
        return unpad(dec, AES.block_size)
    except ValueError:
        return dec

def parse_protobuf(data):
    result = {}
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        field = tag >> 3
        wire = tag & 0x7
        if wire == 0:
            value, offset = read_varint(data, offset)
            result[field] = value
        elif wire == 2:
            length, offset = read_varint(data, offset)
            value = data[offset:offset+length]
            offset += length
            try:
                result[field] = value.decode('utf-8')
            except:
                result[field] = value.hex()
        else:
            break
    return result

def read_varint(data, offset):
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80):
            break
        shift += 7
    return result, offset


def get_access_token_from_uid(uid: str, password: str):
  
    payload = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": CLIENT_SECRET,
        "client_id": APP_ID
    }
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive"
    }
    resp = requests.post(OAUTH_TOKEN_URL, data=payload, headers=headers, timeout=30, verify=False)
    if resp.status_code != 200:
        raise Exception(f"Token grant failed: HTTP {resp.status_code}, {resp.text}")
    data = resp.json()
    access_token = data.get('access_token')
    open_id = data.get('open_id')
    if not access_token or not open_id:
        raise Exception(f"Token grant error: {data}")
    return access_token, open_id

def inspect_token(access_token):

    params = {"token": access_token}
    headers = {"User-Agent": "GarenaMSDK/4.0.19P9", "Accept": "application/json"}
    resp = requests.get(INSPECT_URL, params=params, headers=headers, timeout=15, verify=False)
    if resp.status_code != 200:
        raise Exception(f"Inspect failed: {resp.text}")
    data = resp.json()
    open_id = data.get('open_id')
    if not open_id:
        raise Exception("No open_id in inspect response")
    platform = data.get('main_active_platform') or data.get('login_platform') or 8
    return open_id, platform

def build_major_login_request(access_token, open_id, platform=8):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    fields = {
        3: now,
        4: "free fire",
        5: 1,
        7: "2.131.22",
        8: "Android OS 10 / API-29 (QP1A.190711.020/1617006012)",
        9: "Handheld",
        10: "Vi India",
        11: "WIFI",
        12: 1600,
        13: 720,
        14: "320",
        15: "ARM64 FP ASIMD AES | 2301 | 8",
        16: 2799,
        17: "PowerVR Rogue GE8320",
        18: "OpenGL ES 3.2 build 1.11@5425693",
        19: "Google|9f7d6b8b-b10c-454a-852d-06332cd498eb",
        20: "106.221.227.120",
        21: "en",
        22: open_id,
        23: str(platform),
        24: "Handheld",
        25: "realme RMX2189",
        26: "IND",
        29: access_token,
        30: 1,
        41: "Vi India",
        42: "WIFI",
        57: "1ac4b80ecf0478a44203bf8fac6120f5",
        60: 19799,
        61: 201,
        62: 5056,
        64: 433,
        65: 19999,
        66: 201,
        67: 19799,
        70: 4,
        73: 2,
        74: "/data/app/com.dts.freefireth-DhhtHV35iyaox_nT1wACyw==/lib/arm64",
        76: 1,
        77: "4c322aeb56444feaa151d1ea91a8f7f2|/data/app/com.dts.freefireth-DhhtHV35iyaox_nT1wACyw==/base.apk",
        78: 6,
        79: 2,
        81: "64",
        83: "2019120816",
        85: 3,
        86: "OpenGLES2",
        87: 3071,
        88: 8,
        92: 13891,
        93: "3rd_party",
        94: "KqsHTxzwonOaDxctr7lcZMg1KjER292xcCs41IFIq3w5DlNu2vZmQLdt3EWcqNRj1EO4tC0auQM50Y5L+TU5LYVnqIY=",
        95: 111207,
        96: '{"cur_rate":null,"support_etc2":false}',
        97: 1,
        99: str(platform),
        100: str(platform),
        102: b'C\x04AD\x07\r^Uf'
    }
    return ProtoWriter.create_message(fields)

def send_major_login(access_token, open_id, platform=8):
    plain = build_major_login_request(access_token, open_id, platform)
    encrypted = encrypt(plain)
    headers = {
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "Host": "loginbp.ggpolarbear.com",
        "ReleaseVersion": FREEFIRE_VERSION,
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2022.3.47f1"
    }
    resp = requests.post(MAJOR_LOGIN_URL, data=encrypted, headers=headers, timeout=30, verify=False)
    if resp.status_code != 200:
        raise Exception(f"MajorLogin HTTP {resp.status_code}")
    raw = resp.content
    try:
        decrypted = decrypt(raw)
        return parse_protobuf(decrypted)
    except:
        return parse_protobuf(raw)

def get_jwt_from_uid(uid: str, password: str) -> str:
    access_token, open_id = get_access_token_from_uid(uid, password)
  
    try:
        _, platform = inspect_token(access_token)
    except:
        platform = 8
    resp = send_major_login(access_token, open_id, platform)
    jwt = resp.get(8)
    if isinstance(jwt, bytes):
        jwt = jwt.decode('utf-8')
    if not jwt:
        raise Exception("No JWT in MajorLogin response")
    return jwt

def get_jwt_from_access_token(access_token: str) -> str:
    open_id, platform = inspect_token(access_token)
    resp = send_major_login(access_token, open_id, platform)
    jwt = resp.get(8)
    if isinstance(jwt, bytes):
        jwt = jwt.decode('utf-8')
    if not jwt:
        raise Exception("No JWT in MajorLogin response")
    return jwt

def decode_jwt(jwt: str) -> dict:
    try:
        parts = jwt.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT")
        payload = parts[1]
        payload += '=' * (4 - len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload).decode('utf-8'))
        return data
    except Exception as e:
        raise ValueError(f"JWT decode failed: {e}")

# ==================== BIO UPDATE ====================
def build_bio_payload(bio_text: str) -> bytes:

    packet = bytearray()
    packet.extend(ProtoWriter.write_varint(2, 17))
    packet.extend(ProtoWriter.write_string(5, b''))
    packet.extend(ProtoWriter.write_string(6, b''))
    packet.extend(ProtoWriter.write_string(8, bio_text))
    packet.extend(ProtoWriter.write_varint(9, 1))
    packet.extend(ProtoWriter.write_string(11, b''))
    packet.extend(ProtoWriter.write_string(12, b''))
    return bytes(packet)

def update_bio(jwt: str, bio: str) -> dict:
    plain = build_bio_payload(bio)
    encrypted = encrypt(plain)
    headers = HEADERS_TEMPLATE.copy()
    headers["Authorization"] = f"Bearer {jwt}"
    results = []
    for url in UPDATE_URLS:
        try:
            resp = requests.post(url, headers=headers, data=encrypted, timeout=15, verify=False)
            results.append({
                "url": url,
                "status": resp.status_code,
                "success": resp.status_code == 200
            })
            if resp.status_code == 200:
                return {
                    "success": True,
                    "endpoint": url,
                    "results": results
                }
        except Exception as e:
            results.append({"url": url, "error": str(e), "success": False})
    return {
        "success": False,
        "results": results
    }

# ==================== FLASK APP ====================
app = Flask(__name__)

@app.route('/bio', methods=['GET'])
def bio_changer():
    bio = request.args.get('bio')
    if not bio:
        return jsonify({"error": "Missing 'bio' query parameter"}), 400

    jwt = None
    auth_method = None

    uid = request.args.get('uid')
    password = request.args.get('password')
    access_token = request.args.get('access_token')
    jwt_param = request.args.get('jwt')

    if uid and password:
        try:
            jwt = get_jwt_from_uid(uid, password)
            auth_method = "uid_password"
        except Exception as e:
            return jsonify({"error": f"Failed to get JWT from UID/password: {str(e)}"}), 400
    elif access_token:
        try:
            jwt = get_jwt_from_access_token(access_token)
            auth_method = "access_token"
        except Exception as e:
            return jsonify({"error": f"Failed to get JWT from access token: {str(e)}"}), 400
    elif jwt_param:
        jwt = jwt_param
        auth_method = "jwt"
    else:
        return jsonify({"error": "Provide uid+password, access_token, or jwt as query parameters"}), 400

    # Decode JWT
    try:
        player_info = decode_jwt(jwt)
    except Exception as e:
        return jsonify({"error": f"Invalid JWT: {str(e)}"}), 400

    # Update bio
    update_result = update_bio(jwt, bio)

    return jsonify({
        "success": update_result["success"],
        "auth_method": auth_method,
        "jwt": jwt,
        "player_info": player_info,
        "bio": bio,
        "update": update_result
    })

def index():
    return jsonify({
        "message": "Rishu BiO ChaNGer",
        "supported_login": [
            "UID and Password",
            "Access Token",
            "JWT"
        ]
    })
        

if __name__ == "__main__":
    app.run(debug=True)