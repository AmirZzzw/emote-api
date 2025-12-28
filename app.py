import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
import asyncio
from flask import Flask, request, jsonify
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread, Event
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import socket

#EMOTES BY YASH X CODEX

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

app = Flask(__name__)

# تنظیمات JWT Token
JWT_TOKENS_URL = "https://raw.githubusercontent.com/AmirZzzw/info-api/main/jwt.json"
_jwt_tokens_cache = None
_jwt_cache_time = 0

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB51"}

# ---- Random Colores ----
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload

# ========== توابع جدید برای JWT Token ==========
async def get_jwt_token():
    """دریافت JWT Token از گیت‌هاب"""
    global _jwt_tokens_cache, _jwt_cache_time
    
    # اگر کمتر از 5 دقیقه از cache گذشته
    if _jwt_tokens_cache and (time.time() - _jwt_cache_time) < 300:
        print("🎯 Using cached JWT token")
        return _jwt_tokens_cache
    
    try:
        print("🔄 Fetching JWT token from GitHub...")
        async with aiohttp.ClientSession() as session:
            async with session.get(
                JWT_TOKENS_URL,
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=10
            ) as response:
                if response.status == 200:
                    tokens = await response.json()
                    if tokens and len(tokens) > 0:
                        _jwt_tokens_cache = tokens[0]["token"]
                        _jwt_cache_time = time.time()
                        print(f"✅ JWT token loaded (expires in 8 hours)")
                        return _jwt_tokens_cache
    except Exception as e:
        print(f"❌ Error fetching JWT: {e}")
    
    return None

async def get_login_data_with_jwt(jwt_token):
    """دریافت Login Data مستقیماً با JWT Token"""
    print("🔄 Getting login data with JWT...")
    
    # URL های ممکن
    possible_urls = [
        "https://clientbp.ggblueshark.com",
        "https://clientbp.common.ggbluefox.com",
        "https://clientbp.common.ggbluered.com",
        "https://clientbp.common.ggblueshark.com"
    ]
    
    # Payload خالی
    empty_payload = await encrypted_proto(b"")
    
    for base_url in possible_urls:
        url = f"{base_url}/GetLoginData"
        headers = Hr.copy()
        headers['Authorization'] = f"Bearer {jwt_token}"
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    url, 
                    data=empty_payload, 
                    headers=headers, 
                    ssl=ssl_context
                ) as response:
                    
                    if response.status == 200:
                        login_data_bytes = await response.read()
                        proto = PorTs_pb2.GetLoginData()
                        proto.ParseFromString(login_data_bytes)
                        
                        print(f"✅ Login success! Region: {proto.Region}, UID: {proto.AccountUID}")
                        
                        # کلیدهای رمزنگاری از توکن JWT (یا پیش‌فرض)
                        key = b'Yg&tc%DEuh6%Zc^8'
                        iv = b'6oyZDr22E3ychjM%'
                        
                        return {
                            'url': base_url,
                            'region': proto.Region,
                            'token': jwt_token,  # از JWT استفاده می‌کنیم
                            'account_uid': proto.AccountUID,
                            'key': key,
                            'iv': iv,
                            'timestamp': int(time.time()),
                            'online_ip_port': proto.Online_IP_Port,
                            'account_name': proto.AccountName
                        }
        except Exception as e:
            print(f"⚠️ {base_url} failed: {e}")
            continue
    
    return None

# ========== توابع اصلی (قدیمی) ==========
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.118.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return  await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    headers = Hr.copy()
    headers['Authorization']= f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"

async def SEndPacKeT(writer, PacKeT):
    if writer:
        writer.write(PacKeT)
        await writer.drain()

# ========== نسخه بهینه با JWT ==========
async def quick_session_emote_fast(team_code: str, uids: list, emote_id: int):
    """نسخه سریع با JWT Token"""
    
    print(f"🚀 Starting FAST session for team: {team_code}")
    
    try:
        # 1. دریافت JWT Token
        jwt_token = await get_jwt_token()
        if not jwt_token:
            print("⚠️ JWT token failed, using fallback")
            return await quick_session_emote_old(team_code, uids, emote_id)
        
        # 2. دریافت Login Data با JWT
        login_data = await get_login_data_with_jwt(jwt_token)
        if not login_data:
            print("⚠️ JWT login failed, using fallback")
            return await quick_session_emote_old(team_code, uids, emote_id)
        
        # 3. استخراج داده‌ها
        region = login_data['region']
        TarGeT = login_data['account_uid']
        ToKen = login_data['token']
        key = login_data['key']
        iv = login_data['iv']
        timestamp = login_data['timestamp']
        online_ip_port = login_data['online_ip_port']
        
        print(f"✅ JWT Login successful - Region: {region}, UID: {TarGeT}")
        
        # 4. اتصال به سرور
        if ":" not in online_ip_port:
            raise Exception(f"Invalid port format: {online_ip_port}")
        
        OnLineiP, OnLineporT = online_ip_port.split(":")
        print(f"📍 Parsed - IP: {OnLineiP}, Port: {OnLineporT}")
        
        # 5. Auth Token
        AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), key, iv)
        
        # 6. اتصال TCP
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(OnLineiP, int(OnLineporT)),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            raise Exception("Connection timeout")
        
        print("✅ Connected to online server")
        
        # 7. احراز هویت
        bytes_payload = bytes.fromhex(AutHToKen)
        writer.write(bytes_payload)
        await writer.drain()
        
        # 8. جوین تیم
        print(f"👥 Joining squad: {team_code}")
        EM = await GenJoinSquadsPacket(team_code, key, iv)
        writer.write(EM)
        await writer.drain()
        await asyncio.sleep(0.5)
        
        # 9. ارسال ایموت
        print(f"🎭 Performing emote {emote_id} on {len(uids)} players")
        for uid_str in uids:
            uid = int(uid_str)
            H = await Emote_k(uid, emote_id, key, iv, region)
            writer.write(H)
            await writer.drain()
            await asyncio.sleep(0.1)
        
        # 10. خروج
        print("🚪 Leaving squad")
        LV = await ExiT(TarGeT, key, iv)
        writer.write(LV)
        await writer.drain()
        
        # 11. قطع اتصال
        writer.close()
        await writer.wait_closed()
        
        print("✅ FAST session completed successfully")
        return {"status": "success", "message": "Emote completed via JWT"}
        
    except Exception as e:
        print(f"❌ Error in FAST session: {str(e)}")
        return {"status": "error", "message": f"JWT failed: {str(e)}"}

# ========== نسخه قدیمی (فال‌بک) ==========
async def quick_session_emote_old(team_code: str, uids: list, emote_id: int):
    """نسخه قدیمی (فال‌بک)"""
    
    # BOT LOGIN UID
    BOT_UID = int('4342953910')
    Uid, Pw = '4342953910', 'sidka_FI27F_SIDKASHOP_T3AMN'
    
    print(f"🔄 Starting OLD session for team: {team_code}")
    
    try:
        # 1. LOGIN
        print("🔐 Logging in (old method)...")
        open_id, access_token = await GeNeRaTeAccEss(Uid, Pw)
        if not open_id or not access_token:
            raise Exception("Invalid account")
        
        PyL = await EncRypTMajoRLoGin(open_id, access_token)
        MajoRLoGinResPonsE = await MajorLogin(PyL)
        if not MajoRLoGinResPonsE:
            raise Exception("Account banned or not registered")
        
        MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
        UrL = MajoRLoGinauTh.url
        region = MajoRLoGinauTh.region
        ToKen = MajoRLoGinauTh.token
        TarGeT = MajoRLoGinauTh.account_uid
        key = MajoRLoGinauTh.key
        iv = MajoRLoGinauTh.iv
        timestamp = MajoRLoGinauTh.timestamp
        
        print(f"✅ Old login successful - Region: {region}, UID: {TarGeT}")
        
        # 2. GET PORTS
        print("📡 Getting login data...")
        LoGinDaTa = await GetLoginData(UrL, PyL, ToKen)
        if not LoGinDaTa:
            raise Exception("Failed to get login data")
        
        LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
        OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
        
        if ":" not in OnLinePorTs:
            raise Exception(f"Invalid port format: {OnLinePorTs}")
        
        OnLineiP, OnLineporT = OnLinePorTs.split(":")
        
        # 3. CONNECT
        AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), key, iv)
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(OnLineiP, int(OnLineporT)),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise Exception("Connection timeout")
        
        print("✅ Connected to online server")
        
        # 4. AUTHENTICATE
        bytes_payload = bytes.fromhex(AutHToKen)
        writer.write(bytes_payload)
        await writer.drain()
        
        # 5. JOIN SQUAD
        print(f"👥 Joining squad: {team_code}")
        EM = await GenJoinSquadsPacket(team_code, key, iv)
        writer.write(EM)
        await writer.drain()
        await asyncio.sleep(0.5)
        
        # 6. PERFORM EMOTE
        print(f"🎭 Performing emote {emote_id} on {len(uids)} players")
        for uid_str in uids:
            uid = int(uid_str)
            H = await Emote_k(uid, emote_id, key, iv, region)
            writer.write(H)
            await writer.drain()
            await asyncio.sleep(0.1)
        
        # 7. LEAVE SQUAD
        print("🚪 Leaving squad")
        LV = await ExiT(BOT_UID, key, iv)
        writer.write(LV)
        await writer.drain()
        
        # 8. DISCONNECT
        writer.close()
        await writer.wait_closed()
        
        print("✅ OLD session completed")
        return {"status": "success", "message": "Emote completed (old method)"}
        
    except Exception as e:
        print(f"❌ Error in OLD session: {str(e)}")
        return {"status": "error", "message": str(e)}

# ========== تابع اصلی ترکیبی ==========
async def quick_session_emote(team_code: str, uids: list, emote_id: int):
    """ترکیبی: اول JWT، اگر نشد فال‌بک"""
    try:
        # اول نسخه سریع با JWT رو امتحان کن
        result = await quick_session_emote_fast(team_code, uids, emote_id)
        if result["status"] == "success":
            return result
        # اگر JWT نشد، نسخه قدیم
        return await quick_session_emote_old(team_code, uids, emote_id)
    except Exception as e:
        print(f"❌ All methods failed: {e}")
        return {"status": "error", "message": str(e)}

# ========== Routes ==========
@app.route('/join')
def join_team():
    team_code = request.args.get('tc')
    uid1 = request.args.get('uid1')
    uid2 = request.args.get('uid2')
    uid3 = request.args.get('uid3')
    uid4 = request.args.get('uid4')
    uid5 = request.args.get('uid5')
    uid6 = request.args.get('uid6')
    emote_id_str = request.args.get('emote_id')

    if not team_code or not emote_id_str:
        return jsonify({"status": "error", "message": "Missing tc or emote_id"})

    try:
        emote_id = int(emote_id_str)
    except:
        return jsonify({"status": "error", "message": "emote_id must be integer"})

    uids = [uid for uid in [uid1, uid2, uid3, uid4, uid5, uid6] if uid]

    if not uids:
        return jsonify({"status": "error", "message": "Provide at least one UID"})

    try:
        result = asyncio.run(quick_session_emote(team_code, uids, emote_id))
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed: {str(e)}"})

@app.route('/test')
def test():
    return jsonify({
        "status": "online",
        "message": "Emote API is running",
        "version": "2.0 (JWT + Fallback)",
        "usage": "/join?tc=TEAM_CODE&uid1=UID&emote_id=EMOTE_ID",
        "example": "/join?tc=123456&uid1=4285785816&emote_id=909000063"
    })

@app.route('/debug/jwt')
def debug_jwt():
    """Endpoint برای تست JWT"""
    try:
        token = asyncio.run(get_jwt_token())
        return jsonify({
            "status": "success" if token else "error",
            "has_jwt_token": bool(token),
            "token_preview": token[:50] + "..." if token else None
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/')
def home():
    return '''
    <html>
        <head>
            <title>Free Fire Emote Bot API</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #333; }
                .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
                code { background: #eee; padding: 2px 5px; }
                .debug { background: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>🎭 Free Fire Emote Bot API v2.0</h1>
            <p>API for sending emotes to players in Free Fire</p>
            <p><strong>New:</strong> Uses JWT tokens for faster login!</p>
            
            <div class="endpoint">
                <h3>📤 Send Emote</h3>
                <p><code>GET /join?tc=TEAM_CODE&uid1=UID&emote_id=EMOTE_ID</code></p>
                <p><strong>Example:</strong> 
                <a href="/join?tc=123456&uid1=4285785816&emote_id=909000063">
                    /join?tc=123456&uid1=4285785816&emote_id=909000063
                </a></p>
            </div>
            
            <div class="debug">
                <h3>🐛 Debug Endpoints</h3>
                <ul>
                    <li><a href="/test">/test</a> - API status</li>
                    <li><a href="/debug/jwt">/debug/jwt</a> - Check JWT token</li>
                </ul>
            </div>
        </body>
    </html>
    '''

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Starting server on port {port}")
    app.run(host='0.0.0.0', port=port)
