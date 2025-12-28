import requests , os , sys , jwt , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
import asyncio
from flask import Flask, request, jsonify
from datetime import datetime
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import traceback

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

# ---- توابع رمزنگاری ----
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
    
    # چک کردن کش
    if JWT_CACHE["token"] and time.time() < JWT_CACHE["expiry_time"]:
        return JWT_CACHE["token"], JWT_CACHE["account_uid"]
    
    try:
        url = "https://raw.githubusercontent.com/AmirZzzw/info-api/refs/heads/main/jwt.json"
        response = requests.get(url, timeout=5)
        data = response.json()
        
        if data and len(data) > 0:
            jwt_token = data[0]["token"]
            
            try:
                decoded = jwt.decode(jwt_token, options={"verify_signature": False})
                account_id = decoded.get("account_id")
                exp_time = decoded.get("exp")
                
                JWT_CACHE["token"] = jwt_token
                JWT_CACHE["account_uid"] = account_id
                JWT_CACHE["expiry_time"] = exp_time - 60
                
                print(f"✅ JWT دریافت شد - Account UID: {account_id}")
                return jwt_token, account_id
                
            except Exception as e:
                print(f"❌ خطا در رمزگشایی JWT: {e}")
                return None, None
                
    except Exception as e:
        print(f"❌ خطا در دریافت JWT از GitHub: {e}")
        return None, None
    
    return None, None

# ---- ساختارهای ساده پروتوباف ----
class MajorLoginReq:
    """ساختار ساده برای MajorLogin Request"""
    def __init__(self):
        self.event_time = str(datetime.now())[:-7]
        self.game_name = "free fire"
        self.platform_id = 1
        self.client_version = "1.118.1"
        self.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
        self.system_hardware = "Handheld"
        self.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
        self.language = "en"
        self.access_token = ""
        self.open_id = ""
        self.open_id_type = "4"
        self.platform_sdk_id = 1
        self.login_by = 3
        self.channel_type = 3
        self.login_open_id_type = 4
        self.release_channel = "android"
    
    def set_jwt(self, jwt_token, account_uid):
        self.access_token = jwt_token
        self.open_id = str(account_uid)
    
    def serialize(self):
        """سریالایز ساده"""
        import struct
        data = f"{self.event_time}|{self.game_name}|{self.open_id}|{self.access_token}"
        return data.encode()

class MajorLoginRes:
    """ساختار ساده برای MajorLogin Response"""
    def __init__(self, data=None):
        # مقداردهی اولیه همه attributeها
        self.account_uid = 4342953910
        self.region = "ME"
        self.token = "simulated_token_" + str(int(time.time()))
        self.url = "https://clientbp.ggblueshark.com"  # اینجا اضافه شد
        self.timestamp = int(time.time())
        self.key = b'Yg&tc%DEuh6%Zc^8'
        self.iv = b'6oyZDr22E3ychjM%'
        
        if data:
            self.parse(data)
    
    def parse(self, data):
        """پارس کردن پاسخ ساده"""
        try:
            parts = data.decode('utf-8', errors='ignore').split('|')
            if len(parts) >= 7:
                self.account_uid = int(parts[0]) if parts[0].isdigit() else 4342953910
                self.region = parts[1] if len(parts) > 1 else "ME"
                self.token = parts[2] if len(parts) > 2 else f"token_{int(time.time())}"
                self.url = parts[3] if len(parts) > 3 else "https://clientbp.ggblueshark.com"  # اینجا اضافه شد
                self.timestamp = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else int(time.time())
                self.key = parts[5].encode() if len(parts) > 5 and parts[5] else b'Yg&tc%DEuh6%Zc^8'
                self.iv = parts[6].encode() if len(parts) > 6 and parts[6] else b'6oyZDr22E3ychjM%'
        except Exception as e:
            print(f"⚠️ Error parsing MajorLoginRes: {e}")
            # مقادیر پیش‌فرض نگه می‌داریم

class GetLoginDataRes:
    """ساختار ساده برای GetLoginData Response"""
    def __init__(self, data=None):
        # مقداردهی اولیه
        self.Online_IP_Port = "223.191.51.89:8001"
        self.AccountName = "Bot"
        
        if data:
            self.parse(data)
    
    def parse(self, data):
        """پارس کردن پاسخ ساده"""
        try:
            parts = data.decode('utf-8', errors='ignore').split('|')
            if len(parts) >= 2:
                self.Online_IP_Port = parts[0] if parts[0] else "223.191.51.89:8001"
                self.AccountName = parts[1] if len(parts) > 1 and parts[1] else "Bot"
        except Exception as e:
            print(f"⚠️ Error parsing GetLoginDataRes: {e}")

# ---- تابع اصلی با JWT آماده ----
async def quick_session_with_jwt(team_code: str, uids: list, emote_id: int, jwt_token: str, account_uid: int):
    """یک session سریع با JWT آماده"""
    
    print(f"🚀 Starting quick session with JWT for team: {team_code}, uids: {uids}, emote: {emote_id}")
    print(f"🔑 Using JWT for account: {account_uid}")
    
    try:
        # 1. ساخت MajorLogin Request
        print("🔐 Creating MajorLogin request...")
        
        major_login = MajorLoginReq()
        major_login.set_jwt(jwt_token, account_uid)
        
        string = major_login.serialize()
        PyL = await encrypted_proto(string)
        
        # 2. شبیه‌سازی MajorLogin
        print("🔐 Simulating MajorLogin...")
        
        MajoRLoGinauTh = MajorLoginRes()
        
        # اطمینان از وجود همه attributeها
        UrL = getattr(MajoRLoGinauTh, 'url', "https://clientbp.ggblueshark.com")
        region = getattr(MajoRLoGinauTh, 'region', "ME")
        ToKen = getattr(MajoRLoGinauTh, 'token', f"simulated_token_{int(time.time())}")
        TarGeT = getattr(MajoRLoGinauTh, 'account_uid', 4342953910)
        key = getattr(MajoRLoGinauTh, 'key', b'Yg&tc%DEuh6%Zc^8')
        iv = getattr(MajoRLoGinauTh, 'iv', b'6oyZDr22E3ychjM%')
        timestamp = getattr(MajoRLoGinauTh, 'timestamp', int(time.time()))
        
        print(f"✅ MajorLogin simulated - Region: {region}, UID: {TarGeT}, URL: {UrL}")
        
        # 3. شبیه‌سازی GetLoginData
        print("📡 Simulating GetLoginData...")
        
        LoGinDaTaUncRypTinG = GetLoginDataRes()
        OnLinePorTs = getattr(LoGinDaTaUncRypTinG, 'Online_IP_Port', "223.191.51.89:8001")
        
        print(f"📡 Online ports: {OnLinePorTs}")
        
        if ":" not in OnLinePorTs:
            # اگر فرمت درست نیست، مقدار پیش‌فرض بده
            OnLinePorTs = "223.191.51.89:8001"
            print(f"⚠️ Using default port: {OnLinePorTs}")
        
        OnLineiP, OnLineporT = OnLinePorTs.split(":")
        print(f"📍 Parsed - IP: {OnLineiP}, Port: {OnLineporT}")
        
        # 4. ساخت توکن احراز هویت
        uid_hex = hex(int(TarGeT))[2:]
        uid_length = len(uid_hex)
        
        async def DecodE_HeX(H):
            R = hex(H) 
            F = str(R)[2:]
            if len(F) == 1: 
                return "0" + F
            else: 
                return F
        
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
        else: headers = '0000000'
        
        AutHToKen = f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
        
        # 5. شبیه‌سازی اتصال به سرور
        print(f"🌐 Simulating connection to: {OnLineiP}:{OnLineporT}")
        
        await asyncio.sleep(0.5)
        print("✅ Connected to online server (simulated)")
        
        # 6. شبیه‌سازی جوین تیم
        print(f"👥 Simulating joining squad: {team_code}")
        await asyncio.sleep(0.5)
        
        # 7. شبیه‌سازی ارسال ایموت
        print(f"🎭 Simulating emote {emote_id} on {len(uids)} players")
        for uid_str in uids:
            uid = int(uid_str)
            print(f"   → Sending emote to UID: {uid}")
            await asyncio.sleep(0.1)
        
        # 8. شبیه‌سازی خروج از تیم
        print("🚪 Simulating leaving squad")
        await asyncio.sleep(0.5)
        
        print("✅ Session completed successfully (simulated)")
        return {
            "status": "success", 
            "message": "Emote completed (simulated)",
            "account_uid": str(TarGeT),
            "region": region,
            "team_code": team_code,
            "emote_id": emote_id,
            "uids": uids,
            "note": "This is a simulation. JWT was retrieved successfully."
        }
        
    except Exception as e:
        print(f"❌ Error in session: {str(e)}")
        traceback.print_exc()
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
            
            # اجرای session
            result = asyncio.run(quick_session_with_jwt(team_code, uids, emote_id, jwt_token, account_uid))
        else:
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
        "message": "Emote API is running (JWT optimized - SIMULATED)",
        "usage": "/join?tc=TEAM_CODE&uid1=UID&emote_id=EMOTE_ID",
        "jwt_optimized": True,
        "jwt_source": "GitHub",
        "note": "Currently running in simulation mode. Add real protobuf parsing for production.",
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
            <title>Free Fire Emote Bot API (Simulated)</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
                h1 { color: #333; }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .endpoint { background: #f5f5f5; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #4CAF50; }
                code { background: #eee; padding: 2px 5px; border-radius: 3px; }
                .success { color: #4CAF50; }
                .warning { color: #FF9800; }
                .info { color: #2196F3; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎭 Free Fire Emote Bot API <span class="warning">(SIMULATION MODE)</span></h1>
                <p>API for sending emotes to players in Free Fire - Currently in simulation mode</p>
                
                <div class="warning" style="background: #FFF3CD; padding: 15px; border-radius: 5px; border-left: 4px solid #FF9800; margin: 15px 0;">
                    <strong>⚠️ Note:</strong> This is running in simulation mode. It retrieves JWT tokens but doesn't connect to actual game servers. Add real protobuf parsing for production use.
                </div>
                
                <div class="endpoint">
                    <h3>📤 Send Emote (Simulated)</h3>
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
                    <p><strong>🚀 Current Status:</strong> JWT retrieval works, game server connection is simulated.</p>
                    <p><strong>🔧 JWT Source:</strong> <code>https://raw.githubusercontent.com/AmirZzzw/info-api/main/jwt.json</code></p>
                    <p><strong>🔨 Next Steps:</strong> Add real protobuf parsing by fixing the protobuf files or using a compatible version.</p>
                </div>
            </div>
        </body>
    </html>
    '''

# برای Vercel
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
