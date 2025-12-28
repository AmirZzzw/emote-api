import requests, os, ssl, asyncio, json
import aiohttp
from flask import Flask, request, jsonify
import socket
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Pb2 import PorTs_pb2
from xC4 import *  # ✅ این خط مهمه! تمام توابع xC4 رو import کن

app = Flask(__name__)

# تنظیمات
JWT_TOKENS_URL = "https://raw.githubusercontent.com/AmirZzzw/info-api/main/jwt.json"
TOKEN_CACHE_DURATION = 300  # 5 دقیقه

# متغیرهای cache
_jwt_tokens = None
_last_fetch_time = 0
_login_data_cache = None
_login_cache_expiry = 0
LOGIN_CACHE_DURATION = 1800  # 30 دقیقه

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

async def get_jwt_tokens():
    """دریافت JWT Tokens از GitHub"""
    global _jwt_tokens, _last_fetch_time
    
    current_time = time.time()
    if _jwt_tokens and (current_time - _last_fetch_time) < TOKEN_CACHE_DURATION:
        return _jwt_tokens
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                JWT_TOKENS_URL,
                headers={
                    'Accept': 'application/json',
                    'User-Agent': 'Mozilla/5.0'
                },
                timeout=10
            ) as response:
                if response.status == 200:
                    _jwt_tokens = await response.json()
                    _last_fetch_time = current_time
                    print(f"✅ Loaded {len(_jwt_tokens)} JWT tokens")
                    return _jwt_tokens
                else:
                    print(f"❌ GitHub error: {response.status}")
                    
    except Exception as e:
        print(f"❌ Error fetching JWT tokens: {e}")
        # Fallback با requests
        try:
            response = requests.get(JWT_TOKENS_URL, timeout=10)
            if response.status_code == 200:
                _jwt_tokens = response.json()
                _last_fetch_time = current_time
                print(f"✅ Loaded tokens via requests")
                return _jwt_tokens
        except Exception as e2:
            print(f"❌ Requests also failed: {e2}")
    
    return _jwt_tokens or []

async def get_next_jwt_token():
    """دریافت یک JWT Token از لیست"""
    tokens = await get_jwt_tokens()
    if not tokens:
        raise Exception("No JWT tokens available")
    return tokens[0]["token"]

async def get_login_data_from_jwt(jwt_token):
    """دریافت اطلاعات Login با JWT Token"""
    print("🔄 Fetching login data from server...")
    
    # از تابع encrypted_proto که حالا import شده استفاده کن
    empty_payload = await encrypted_proto(b"")
    
    # URL های سرور
    possible_urls = [
        "https://clientbp.ggblueshark.com",
        "https://clientbp.common.ggbluefox.com",
        "https://clientbp.common.ggbluered.com",
        "https://clientbp.common.ggblueshark.com"
    ]
    
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
                        
                        print(f"✅ Login successful! Region: {proto.Region}, UID: {proto.AccountUID}")
                        
                        return {
                            'url': base_url,
                            'region': proto.Region,
                            'account_uid': proto.AccountUID,
                            'account_name': proto.AccountName,
                            'online_ip_port': proto.Online_IP_Port,
                            'account_ip_port': proto.AccountIP_Port,
                            'clan_id': proto.Clan_ID if proto.Clan_ID else None,
                            'clan_compiled_data': proto.Clan_Compiled_Data if proto.Clan_Compiled_Data else None,
                            'jwt_token': jwt_token
                        }
                    else:
                        print(f"⚠️ {base_url} - Status: {response.status}")
                        
        except Exception as e:
            print(f"⚠️ {base_url} error: {str(e)}")
            continue
    
    raise Exception("Failed to connect to any game server")

async def get_cached_login_data():
    """دریافت Login Data با Cache"""
    global _login_data_cache, _login_cache_expiry
    
    current_time = time.time()
    
    # اگر cache معتبر است
    if _login_data_cache and (current_time - _login_cache_expiry) < LOGIN_CACHE_DURATION:
        print("🎯 Using cached login data")
        return _login_data_cache
    
    # دریافت جدید
    print("🔄 Fetching fresh login data...")
    jwt_token = await get_next_jwt_token()
    login_data = await get_login_data_from_jwt(jwt_token)
    
    # ذخیره در cache
    _login_data_cache = login_data
    _login_cache_expiry = current_time
    
    return login_data

async def quick_session_emote(team_code: str, uids: list, emote_id: int):
    """Session سریع برای ارسال ایموت"""
    
    print(f"🚀 Starting session for team: {team_code}, emotes: {emote_id}")
    
    try:
        # 1. دریافت Login Data
        login_data = await get_cached_login_data()
        
        # 2. آماده‌سازی داده‌ها
        region = login_data['region']
        account_uid = login_data['account_uid']
        online_ip_port = login_data['online_ip_port']
        jwt_token = login_data['jwt_token']
        
        # کلیدهای رمزنگاری (همانند xC4.py)
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        
        # 3. اتصال به سرور
        print(f"🌐 Connecting to server: {online_ip_port}")
        
        if ":" not in online_ip_port:
            raise Exception("Invalid server address format")
        
        ip, port = online_ip_port.split(":")
        
        # ساخت Auth Token
        timestamp = int(time.time())
        auth_token = await xAuThSTarTuP(account_uid, jwt_token, timestamp, key, iv)
        
        # اتصال TCP
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, int(port)),
                timeout=15.0
            )
        except asyncio.TimeoutError:
            raise Exception("Connection timeout")
        
        print("✅ Connected to game server")
        
        # ارسال Auth
        writer.write(bytes.fromhex(auth_token))
        await writer.drain()
        await asyncio.sleep(1)
        
        # 4. جوین تیم
        print(f"👥 Joining team: {team_code}")
        join_packet = await GenJoinSquadsPacket(team_code, key, iv)
        writer.write(join_packet)
        await writer.drain()
        await asyncio.sleep(2)
        
        # 5. ارسال ایموت
        print(f"🎭 Sending emote {emote_id} to {len(uids)} players")
        for uid_str in uids:
            uid = int(uid_str)
            emote_packet = await Emote_k(uid, emote_id, key, iv, region)
            writer.write(emote_packet)
            await writer.drain()
            await asyncio.sleep(0.2)
        
        # 6. خروج از تیم
        print("🚪 Leaving team")
        leave_packet = await ExiT(account_uid, key, iv)
        writer.write(leave_packet)
        await writer.drain()
        
        # 7. قطع اتصال
        writer.close()
        await writer.wait_closed()
        
        print("✅ Session completed successfully!")
        return {
            "status": "success",
            "message": "Emote sent successfully",
            "region": region,
            "account_uid": str(account_uid),
            "targets": uids,
            "emote_id": emote_id
        }
        
    except Exception as e:
        print(f"❌ Error in session: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}

# Routes
@app.route('/join')
def join_team():
    team_code = request.args.get('tc')
    uids = [request.args.get(f'uid{i}') for i in range(1, 7)]
    uids = [uid for uid in uids if uid]
    emote_id = request.args.get('emote_id')
    
    if not team_code:
        return jsonify({"status": "error", "message": "Missing team code (tc)"})
    if not emote_id:
        return jsonify({"status": "error", "message": "Missing emote_id"})
    if not uids:
        return jsonify({"status": "error", "message": "Provide at least one UID"})
    
    try:
        emote_id = int(emote_id)
    except:
        return jsonify({"status": "error", "message": "emote_id must be integer"})
    
    try:
        result = asyncio.run(quick_session_emote(team_code, uids, emote_id))
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/test')
def test():
    try:
        tokens = asyncio.run(get_jwt_tokens())
        tokens_count = len(tokens) if tokens else 0
        
        return jsonify({
            "status": "online",
            "message": "API is running",
            "jwt_tokens_count": tokens_count,
            "cache_info": {
                "token_cache": "valid" if _jwt_tokens else "empty",
                "login_cache": "valid" if _login_data_cache else "empty"
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/debug/jwt')
def debug_jwt():
    """Endpoint برای دیباگ دریافت توکن"""
    try:
        tokens = asyncio.run(get_jwt_tokens())
        return jsonify({
            "status": "success",
            "tokens_count": len(tokens) if tokens else 0,
            "tokens": tokens[:1] if tokens else []  # فقط اولی رو نشون بده
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/debug/login')
def debug_login():
    """Endpoint برای دیباگ Login Data"""
    try:
        login_data = asyncio.run(get_cached_login_data())
        # حساس‌ترین داده‌ها رو پنهان کن
        safe_data = login_data.copy()
        if 'jwt_token' in safe_data:
            safe_data['jwt_token'] = safe_data['jwt_token'][:50] + "..."
        
        return jsonify({
            "status": "success",
            "login_data": safe_data
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
            <h1>🎭 Free Fire Emote Bot API</h1>
            <p>API for sending emotes to players in Free Fire</p>
            
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
                    <li><a href="/test">/test</a> - Check API status</li>
                    <li><a href="/debug/jwt">/debug/jwt</a> - Check JWT tokens</li>
                    <li><a href="/debug/login">/debug/login</a> - Check login data</li>
                </ul>
            </div>
        </body>
    </html>
    '''

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Starting server on port {port}")
    app.run(host='0.0.0.0', port=port)
