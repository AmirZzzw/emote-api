import requests, os, ssl, asyncio, json
import aiohttp
from flask import Flask, request, jsonify
import socket
from xC4 import *  # از توابع رمزنگاری موجود
from Pb2 import MajoRLoGinrEs_pb2, PorTs_pb2
import time

app = Flask(__name__)

# JWT Token های آماده
import requests
import time

JWT_TOKENS_URL = "https://github.com/AmirZzzw/info-api/raw/refs/heads/main/jwt.json"

# Headers پیشفرض
Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB51"
}

# Cache برای JWT Tokens
_jwt_tokens = None
_last_fetch_time = 0
TOKEN_CACHE_DURATION = 300  # 5 دقیقه

async def get_jwt_tokens():
    """دریافت JWT Tokens از لینک با cache"""
    global _jwt_tokens, _last_fetch_time
    
    current_time = time.time()
    if _jwt_tokens and (current_time - _last_fetch_time) < TOKEN_CACHE_DURATION:
        return _jwt_tokens
    
    try:
        # استفاده از requests به جای aiohttp برای GitHub
        response = requests.get(
            JWT_TOKENS_URL,
            headers={
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0'
            },
            timeout=10
        )
        
        if response.status_code == 200:
            _jwt_tokens = response.json()
            _last_fetch_time = current_time
            print(f"✅ Loaded {len(_jwt_tokens)} JWT tokens")
            return _jwt_tokens
        else:
            print(f"❌ GitHub API error: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error fetching JWT tokens: {e}")
    
    return _jwt_tokens or []

async def get_next_jwt_token():
    """دریافت یک JWT Token از لیست (round-robin)"""
    tokens = await get_jwt_tokens()
    if not tokens:
        raise Exception("No JWT tokens available")
    
    # Simple round-robin selection
    # می‌توانید اینجا منطق بهتری برای انتخاب توکن اضافه کنید
    return tokens[0]["token"]  # اولین توکن را برمی‌گرداند

async def get_login_data_from_jwt(jwt_token):
    """دریافت اطلاعات Login مستقیماً با JWT Token"""
    try:
        # 1. مستقیماً GetLoginData را با JWT Token فراخوانی کنیم
        # ابتدا باید URL مناسب را پیدا کنیم
        
        # URL های ممکن برای سرورها (بر اساس region)
        possible_urls = [
            "https://clientbp.ggblueshark.com",
            "https://clientbp.common.ggbluefox.com",
            "https://clientbp.common.ggbluered.com",
            "https://clientbp.common.ggblueshark.com"
        ]
        
        # Payload خالی برای GetLoginData
        empty_payload = await encrypted_proto(b"")  # از تابع موجود در xC4
        
        # امتحان هر URL تا یکی کار کند
        for base_url in possible_urls:
            url = f"{base_url}/GetLoginData"
            
            headers = Hr.copy()
            headers['Authorization'] = f"Bearer {jwt_token}"
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, data=empty_payload, headers=headers, ssl=ssl_context, timeout=10) as response:
                        if response.status == 200:
                            login_data_bytes = await response.read()
                            
                            # Decode پاسخ
                            proto = PorTs_pb2.GetLoginData()
                            proto.ParseFromString(login_data_bytes)
                            
                            print(f"✅ Found working URL: {base_url}")
                            return {
                                'url': base_url,
                                'region': proto.Region,
                                'account_uid': proto.AccountUID,
                                'account_name': proto.AccountName,
                                'online_ip_port': proto.Online_IP_Port,
                                'account_ip_port': proto.AccountIP_Port,
                                'clan_id': proto.Clan_ID if proto.Clan_ID else None,
                                'clan_compiled_data': proto.Clan_Compiled_Data if proto.Clan_Compiled_Data else None
                            }
            except Exception as e:
                print(f"⚠️ URL {base_url} failed: {e}")
                continue
        
        raise Exception("No working server URL found")
        
    except Exception as e:
        print(f"❌ Error in get_login_data_from_jwt: {e}")
        raise

async def get_cached_login_data():
    """Cache برای اطلاعات Login"""
    cache_key = "login_data_cache"
    cache_file = "login_cache.json"
    
    # چک کردن cache فایل
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # چک کردن expire (1 ساعت)
            if time.time() - cache_data.get('timestamp', 0) < 3600:
                print("🎯 Using cached login data")
                return cache_data['data']
        except:
            pass
    
    # اگر cache معتبر نبود، دریافت جدید
    print("🔄 Fetching new login data...")
    jwt_token = await get_next_jwt_token()
    login_data = await get_login_data_from_jwt(jwt_token)
    
    # اضافه کردن JWT token به داده‌ها
    login_data['jwt_token'] = jwt_token
    
    # ذخیره در cache
    cache_data = {
        'timestamp': time.time(),
        'data': login_data
    }
    
    with open(cache_file, 'w') as f:
        json.dump(cache_data, f)
    
    return login_data

async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    """همان تابع قبلی - نیاز به توابع EnC_PacKeT و DecodE_HeX از xC4 دارد"""
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    
    if uid_length == 9:
        headers = '0000000'
    elif uid_length == 8:
        headers = '00000000'
    elif uid_length == 10:
        headers = '000000'
    elif uid_length == 7:
        headers = '000000000'
    else:
        print('Unexpected length')
        headers = '0000000'
    
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"

async def quick_session_emote(team_code: str, uids: list, emote_id: int):
    """Session سریع با JWT Token آماده"""
    
    print(f"🚀 Starting quick session for team: {team_code}, uids: {uids}, emote: {emote_id}")
    
    try:
        # 1. دریافت اطلاعات Login از Cache یا JWT
        print("🔐 Getting login data...")
        login_data = await get_cached_login_data()
        
        # استخراج داده‌ها
        region = login_data['region']
        TarGeT = login_data['account_uid']
        online_ip_port = login_data['online_ip_port']
        jwt_token = login_data.get('jwt_token')
        
        # کلیدهای رمزنگاری - نیاز به استخراج از JWT یا استفاده از مقادیر ثابت
        # اگر در JWT موجود نیستند، می‌توانید از مقادیر پیش‌فرض استفاده کنید
        key = b'Yg&tc%DEuh6%Zc^8'  # از xC4.py
        iv = b'6oyZDr22E3ychjM%'   # از xC4.py
        
        # 2. اتصال به سرور Online
        print(f"🌐 Connecting to online server: {online_ip_port}")
        
        if ":" not in online_ip_port:
            raise Exception(f"Invalid port format: {online_ip_port}")
        
        OnLineiP, OnLineporT = online_ip_port.split(":")
        
        # ساخت Auth Token - نیاز به timestamp داریم
        # از زمان فعلی استفاده می‌کنیم
        timestamp = int(time.time())
        AutHToKen = await xAuThSTarTuP(TarGeT, jwt_token, timestamp, key, iv)
        
        # اتصال به سرور
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(OnLineiP, int(OnLineporT)),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            raise Exception("Connection timeout")
        
        print("✅ Connected to online server")
        
        # 3. احراز هویت
        bytes_payload = bytes.fromhex(AutHToKen)
        writer.write(bytes_payload)
        await writer.drain()
        await asyncio.sleep(0.5)  # منتظر پاسخ سرور
        
        # 4. جوین تیم
        print(f"👥 Joining squad: {team_code}")
        EM = await GenJoinSquadsPacket(team_code, key, iv)
        writer.write(EM)
        await writer.drain()
        await asyncio.sleep(1.0)  # منتظر جوین شدن
        
        # 5. انجام ایموت
        print(f"🎭 Performing emote {emote_id} on {len(uids)} players")
        for uid_str in uids:
            uid = int(uid_str)
            H = await Emote_k(uid, emote_id, key, iv, region)
            writer.write(H)
            await writer.drain()
            await asyncio.sleep(0.15)  # تأخیر کوتاه بین ایموت‌ها
        
        # 6. خروج از تیم
        print("🚪 Leaving squad")
        LV = await ExiT(TarGeT, key, iv)  # استفاده از UID خود بات
        writer.write(LV)
        await writer.drain()
        
        # 7. قطع اتصال
        writer.close()
        await writer.wait_closed()
        
        print("✅ Session completed successfully")
        return {
            "status": "success",
            "message": "Emote completed",
            "region": region,
            "uid": TarGeT,
            "time": time.time()
        }
        
    except Exception as e:
        print(f"❌ Error in session: {str(e)}")
        import traceback
        print(f"📝 Traceback: {traceback.format_exc()}")
        return {"status": "error", "message": str(e)}

# Routeها (همان قبلی)
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
        "usage": "/join?tc=TEAM_CODE&uid1=UID&emote_id=EMOTE_ID",
        "example": "/join?tc=123456&uid1=4285785816&emote_id=909000063"
    })

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
            </style>
        </head>
        <body>
            <h1>🎭 Free Fire Emote Bot API</h1>
            <p>API for sending emotes to players in Free Fire</p>
            
            <div class="endpoint">
                <h3>📤 Send Emote</h3>
                <p><code>GET /join?tc=TEAM_CODE&uid1=UID&emote_id=EMOTE_ID</code></p>
                <p><strong>Parameters:</strong></p>
                <ul>
                    <li><code>tc</code>: Team/Squad Code (required)</li>
                    <li><code>uid1, uid2, ... uid6</code>: Player UIDs (at least one required)</li>
                    <li><code>emote_id</code>: Emote ID (required)</li>
                </ul>
                <p><strong>Example:</strong> <a href="/join?tc=123456&uid1=4285785816&emote_id=909000063">/join?tc=123456&uid1=4285785816&emote_id=909000063</a></p>
            </div>
            
            <div class="endpoint">
                <h3>🩺 Test Endpoint</h3>
                <p><code>GET /test</code> - Check API status</p>
                <p><a href="/test">/test</a></p>
            </div>
            
            <p><strong>Note:</strong> Each request creates a new session (login → join → emote → disconnect).</p>
        </body>
    </html>
    '''

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
