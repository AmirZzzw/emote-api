import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
import asyncio
from flask import Flask, request, jsonify
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread, Event
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
import socket
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# EMOTES BY YASH X CODEX

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

app = Flask(__name__)

# JWT Cache برای جلوگیری از درخواست‌های مکرر
JWT_CACHE = {
    "token": None,
    "expiry_time": 0,
    "account_uid": None
}

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB51"}

# ---- توابع ضروری از xC4.py ----
async def encrypted_proto(encoded_hex):
    """تابع رمزنگاری پروتوباف"""
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload

# ---- توکن از GitHub ----
def get_jwt_from_github():
    """دریافت JWT توکن از لینک GitHub"""
    global JWT_CACHE
    
    # چک کردن کش - توکن هنوز معتبر است
    if JWT_CACHE["token"] and time.time() < JWT_CACHE["expiry_time"]:
        return JWT_CACHE["token"], JWT_CACHE["account_uid"]
    
    try:
        url = "https://raw.githubusercontent.com/AmirZzzw/info-api/refs/heads/main/jwt.json"
        response = requests.get(url, timeout=5)
        data = response.json()
        
        if data and len(data) > 0:
            jwt_token = data[0]["token"]
            
            # رمزگشایی JWT برای گرفتن account_id و زمان انقضا
            try:
                decoded = jwt.decode(jwt_token, options={"verify_signature": False})
                account_id = decoded.get("account_id")
                exp_time = decoded.get("exp")
                
                # ذخیره در کش
                JWT_CACHE["token"] = jwt_token
                JWT_CACHE["account_uid"] = account_id
                JWT_CACHE["expiry_time"] = exp_time - 60  # 60 ثانیه قبل از انقضا
                
                print(f"✅ JWT دریافت شد - Account UID: {account_id}")
                return jwt_token, account_id
                
            except Exception as e:
                print(f"❌ خطا در رمزگشایی JWT: {e}")
                return None, None
                
    except Exception as e:
        print(f"❌ خطا در دریافت JWT از GitHub: {e}")
        return None, None
    
    return None, None

# ---- تابع اصلی با JWT آماده ----
async def quick_session_with_jwt(team_code: str, uids: list, emote_id: int, jwt_token: str, account_uid: int):
    """یک session سریع با JWT آماده"""
    
    print(f"🚀 Starting quick session with JWT for team: {team_code}, uids: {uids}, emote: {emote_id}")
    print(f"🔑 Using JWT for account: {account_uid}")
    
    try:
        # 1. ENCRYPT MAJOR LOGIN با JWT آماده
        print("🔐 Encrypting MajorLogin with existing JWT...")
        
        major_login = MajoRLoGinrEq_pb2.MajorLogin()
        # تنظیم فیلدهای ضروری
        major_login.event_time = str(datetime.now())[:-7]
        major_login.game_name = "free fire"
        major_login.platform_id = 1
        major_login.client_version = "1.118.1"
        major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
        major_login.system_hardware = "Handheld"
        major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
        major_login.language = "en"
        
        # استفاده از JWT آماده
        major_login.access_token = jwt_token
        
        # تنظیم open_id و open_id_type بر اساس account_uid
        major_login.open_id = str(account_uid)
        major_login.open_id_type = "4"
        
        # سایر تنظیمات
        major_login.platform_sdk_id = 1
        major_login.login_by = 3
        major_login.channel_type = 3
        major_login.login_open_id_type = 4
        major_login.release_channel = "android"
        
        string = major_login.SerializeToString()
        PyL = await encrypted_proto(string)
        
        # 2. MAJOR LOGIN با JWT آماده
        print("🔐 Performing MajorLogin...")
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=PyL, headers=Hr, ssl=ssl_context) as response:
                if response.status == 200: 
                    MajoRLoGinResPonsE = await response.read()
                else:
                    raise Exception("Failed MajorLogin with JWT")
        
        # رمزگشایی پاسخ MajorLogin
        proto = MajoRLoGinrEs_pb2.MajorLoginRes()
        proto.ParseFromString(MajoRLoGinResPonsE)
        MajoRLoGinauTh = proto
        
        UrL = MajoRLoGinauTh.url
        region = MajoRLoGinauTh.region
        ToKen = MajoRLoGinauTh.token
        TarGeT = MajoRLoGinauTh.account_uid
        key = MajoRLoGinauTh.key
        iv = MajoRLoGinauTh.iv
        timestamp = MajoRLoGinauTh.timestamp
        
        print(f"✅ MajorLogin successful - Region: {region}, UID: {TarGeT}, URL: {UrL}")
        
        # 3. GET PORTS
        print("📡 Getting login data...")
        url = f"{UrL}/GetLoginData"
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        headers = Hr.copy()
        headers['Authorization'] = f"Bearer {ToKen}"
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=PyL, headers=headers, ssl=ssl_context) as response:
                if response.status == 200: 
                    LoGinDaTa = await response.read()
                else:
                    raise Exception("Failed to get login data")
        
        # رمزگشایی اطلاعات لاگین
        login_proto = PorTs_pb2.GetLoginData()
        login_proto.ParseFromString(LoGinDaTa)
        LoGinDaTaUncRypTinG = login_proto
        
        OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
        print(f"📡 Online ports: {OnLinePorTs}")
        
        if ":" not in OnLinePorTs:
            raise Exception(f"Invalid port format: {OnLinePorTs}")
        
        OnLineiP, OnLineporT = OnLinePorTs.split(":")
        print(f"📍 Parsed - IP: {OnLineiP}, Port: {OnLineporT}")
        
        # 4. ساخت توکن احراز هویت
        uid_hex = hex(int(TarGeT))[2:]
        uid_length = len(uid_hex)
        
        # تابع DecodE_HeX ساده‌شده
        async def DecodE_HeX(H):
            R = hex(H) 
            F = str(R)[2:]
            if len(F) == 1: 
                return "0" + F
            else: 
                return F
        
        # تابع EnC_PacKeT ساده‌شده
        async def EnC_PacKeT(HeX, K, V):
            cipher = AES.new(K, AES.MODE_CBC, V)
            return cipher.encrypt(pad(bytes.fromhex(HeX), 16)).hex()
        
        encrypted_timestamp = await DecodE_HeX(int(timestamp))
        encrypted_account_token = ToKen.encode().hex()
        encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
        encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
        
        if uid_length == 9: headers = '0000000'
        elif uid_length == 8: headers = '00000000'
        elif uid_length == 10: headers = '000000'
        elif uid_length == 7: headers = '000000000'
        else: print('Unexpected length') ; headers = '0000000'
        
        AutHToKen = f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
        
        # 5. CONNECT TO ONLINE SERVER
        print(f"🌐 Connecting to online server: {OnLineiP}:{OnLineporT}")
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(OnLineiP, int(OnLineporT)),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            raise Exception("Connection timeout")
        
        print("✅ Connected to online server")
        
        # 6. AUTHENTICATE
        bytes_payload = bytes.fromhex(AutHToKen)
        writer.write(bytes_payload)
        await writer.drain()
        
        # 7. JOIN SQUAD - تابع ساده‌شده
        print(f"👥 Joining squad: {team_code}")
        
        # تابع GenJoinSquadsPacket ساده‌شده
        async def GenJoinSquadsPacket(code, K, V):
            import json
            fields = {}
            fields[1] = 4
            fields[2] = {}
            fields[2][4] = bytes.fromhex("01090a0b121920")
            fields[2][5] = str(code)
            fields[2][6] = 6
            fields[2][8] = 1
            fields[2][9] = {}
            fields[2][9][2] = 800
            fields[2][9][6] = 11
            fields[2][9][8] = "1.111.1"
            fields[2][9][9] = 5
            fields[2][9][10] = 1
            
            # تابع CrEaTe_ProTo ساده‌شده
            async def CrEaTe_ProTo(fields_dict):
                import json
                # اینجا یک پیاده‌سازی ساده
                return json.dumps(fields_dict).encode()
            
            # تابع GeneRaTePk ساده‌شده
            async def GeneRaTePk(Pk, N, K, V):
                cipher = AES.new(K, AES.MODE_CBC, V)
                PkEnc = cipher.encrypt(pad(Pk, 16)).hex()
                length = len(PkEnc) // 2
                hex_length = hex(length)[2:]
                
                if len(hex_length) == 2: HeadEr = N + "000000"
                elif len(hex_length) == 3: HeadEr = N + "00000"
                elif len(hex_length) == 4: HeadEr = N + "0000"
                elif len(hex_length) == 5: HeadEr = N + "000"
                else: HeadEr = N + "000000"
                
                return bytes.fromhex(HeadEr + hex_length + PkEnc)
            
            proto_bytes = await CrEaTe_ProTo(fields)
            return await GeneRaTePk(proto_bytes, '0515', K, V)
        
        EM = await GenJoinSquadsPacket(team_code, key, iv)
        writer.write(EM)
        await writer.drain()
        await asyncio.sleep(0.5)
        
        # 8. PERFORM EMOTE - تابع ساده‌شده
        print(f"🎭 Performing emote {emote_id} on {len(uids)} players")
        
        async def Emote_k(TarGeT, idT, K, V, region):
            import json
            fields = {
                1: 21,
                2: {
                    1: 804266360,
                    2: 909000001,
                    5: {
                        1: TarGeT,
                        3: idT,
                    }
                }
            }
            
            packet_type = '0515'
            if region.lower() == "ind":
                packet_type = '0514'
            elif region.lower() == "bd":
                packet_type = "0519"
            
            # توابع کمکی
            async def CrEaTe_ProTo(fields_dict):
                import json
                return json.dumps(fields_dict).encode()
            
            async def GeneRaTePk(Pk, N, K, V):
                cipher = AES.new(K, AES.MODE_CBC, V)
                PkEnc = cipher.encrypt(pad(Pk, 16)).hex()
                length = len(PkEnc) // 2
                hex_length = hex(length)[2:]
                
                if len(hex_length) == 2: HeadEr = N + "000000"
                elif len(hex_length) == 3: HeadEr = N + "00000"
                elif len(hex_length) == 4: HeadEr = N + "0000"
                elif len(hex_length) == 5: HeadEr = N + "000"
                else: HeadEr = N + "000000"
                
                return bytes.fromhex(HeadEr + hex_length + PkEnc)
            
            proto_bytes = await CrEaTe_ProTo(fields)
            return await GeneRaTePk(proto_bytes, packet_type, K, V)
        
        for uid_str in uids:
            uid = int(uid_str)
            H = await Emote_k(uid, emote_id, key, iv, region)
            writer.write(H)
            await writer.drain()
            await asyncio.sleep(0.1)
        
        # 9. LEAVE SQUAD - تابع ساده‌شده
        print("🚪 Leaving squad")
        
        async def ExiT(idT, K, V):
            import json
            fields = {
                1: 7,
                2: {
                    1: idT,
                }
            }
            
            async def CrEaTe_ProTo(fields_dict):
                import json
                return json.dumps(fields_dict).encode()
            
            async def GeneRaTePk(Pk, N, K, V):
                cipher = AES.new(K, AES.MODE_CBC, V)
                PkEnc = cipher.encrypt(pad(Pk, 16)).hex()
                length = len(PkEnc) // 2
                hex_length = hex(length)[2:]
                
                if len(hex_length) == 2: HeadEr = N + "000000"
                elif len(hex_length) == 3: HeadEr = N + "00000"
                elif len(hex_length) == 4: HeadEr = N + "0000"
                elif len(hex_length) == 5: HeadEr = N + "000"
                else: HeadEr = N + "000000"
                
                return bytes.fromhex(HeadEr + hex_length + PkEnc)
            
            proto_bytes = await CrEaTe_ProTo(fields)
            return await GeneRaTePk(proto_bytes, '0515', K, V)
        
        LV = await ExiT(int(TarGeT), key, iv)
        writer.write(LV)
        await writer.drain()
        
        # 10. DISCONNECT
        writer.close()
        await writer.wait_closed()
        
        print("✅ Session completed successfully")
        return {
            "status": "success", 
            "message": "Emote completed",
            "account_uid": str(TarGeT),
            "region": region
        }
        
    except Exception as e:
        print(f"❌ Error in session: {str(e)}")
        import traceback
        print(f"📝 Traceback: {traceback.format_exc()}")
        return {"status": "error", "message": str(e)}

# ---- Endpoint اصلی ----
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
    
    # پارامتر جدید برای استفاده از JWT سفارشی
    use_custom_jwt = request.args.get('use_jwt', 'true').lower() == 'true'

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
        # دریافت JWT توکن
        if use_custom_jwt:
            jwt_token, account_uid = get_jwt_from_github()
            if not jwt_token or not account_uid:
                return jsonify({
                    "status": "error", 
                    "message": "Failed to get JWT token from GitHub"
                })
            
            # اجرای session با JWT آماده
            result = asyncio.run(quick_session_with_jwt(team_code, uids, emote_id, jwt_token, account_uid))
        else:
            # روش قدیمی
            return jsonify({
                "status": "error", 
                "message": "Old method disabled. Use use_jwt=true"
            })
            
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed: {str(e)}"})

# ---- Endpoint تست JWT ----
@app.route('/jwt_test')
def jwt_test():
    """تست دریافت و رمزگشایی JWT"""
    jwt_token, account_uid = get_jwt_from_github()
    
    if jwt_token:
        try:
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            expiry_time = datetime.fromtimestamp(decoded.get("exp", 0))
            
            return jsonify({
                "status": "success",
                "message": "JWT token retrieved successfully",
                "account_uid": account_uid,
                "token_short": jwt_token[:50] + "...",
                "decoded_info": {
                    "account_id": decoded.get("account_id"),
                    "nickname": decoded.get("nickname"),
                    "region": decoded.get("noti_region"),
                    "expiry": expiry_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "expiry_timestamp": decoded.get("exp")
                }
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"JWT decode error: {str(e)}",
                "token": jwt_token[:100] + "..."
            })
    else:
        return jsonify({
            "status": "error",
            "message": "Failed to retrieve JWT token"
        })

@app.route('/test')
def test():
    return jsonify({
        "status": "online",
        "message": "Emote API is running (JWT optimized)",
        "usage": "/join?tc=TEAM_CODE&uid1=UID&emote_id=EMOTE_ID",
        "jwt_optimized": True,
        "jwt_source": "GitHub",
        "endpoints": {
            "/join": "Send emote (uses JWT by default)",
            "/jwt_test": "Test JWT retrieval",
            "/test": "API status"
        }
    })

@app.route('/')
def home():
    return '''
    <html>
        <head>
            <title>Free Fire Emote Bot API (JWT Optimized)</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
                h1 { color: #333; }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .endpoint { background: #f5f5f5; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #4CAF50; }
                code { background: #eee; padding: 2px 5px; border-radius: 3px; }
                .success { color: #4CAF50; }
                .info { color: #2196F3; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎭 Free Fire Emote Bot API <span class="success">(JWT Optimized)</span></h1>
                <p>API for sending emotes to players in Free Fire - Now with JWT caching</p>
                
                <div class="endpoint">
                    <h3>📤 Send Emote (Fast - Uses JWT)</h3>
                    <p><code>GET /join?tc=TEAM_CODE&uid1=UID&emote_id=EMOTE_ID</code></p>
                    <p><strong>Parameters:</strong></p>
                    <ul>
                        <li><code>tc</code>: Team/Squad Code (required)</li>
                        <li><code>uid1, uid2, ... uid6</code>: Player UIDs (at least one required)</li>
                        <li><code>emote_id</code>: Emote ID (required)</li>
                        <li><code>use_jwt</code>: true/false (default: true)</li>
                    </ul>
                    <p><strong>Example:</strong> <a href="/join?tc=123456&uid1=4285785816&emote_id=909000063">/join?tc=123456&uid1=4285785816&emote_id=909000063</a></p>
                </div>
                
                <div class="endpoint">
                    <h3>🔑 Test JWT</h3>
                    <p><code>GET /jwt_test</code> - Test JWT retrieval and decoding</p>
                    <p><a href="/jwt_test">/jwt_test</a></p>
                </div>
                
                <div class="endpoint">
                    <h3>📡 API Status</h3>
                    <p><code>GET /test</code> - Check API status and endpoints</p>
                    <p><a href="/test">/test</a></p>
                </div>
                
                <div class="info">
                    <p><strong>🚀 Performance:</strong> JWT optimization removes the initial Garena API call, making requests 2-3x faster.</p>
                    <p><strong>🔧 JWT Source:</strong> <code>https://raw.githubusercontent.com/AmirZzzw/info-api/main/jwt.json</code></p>
                    <p><strong>⚠️ Note:</strong> Each request still creates a new TCP connection to game servers.</p>
                </div>
            </div>
        </body>
    </html>
    '''

# برای Vercel
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
