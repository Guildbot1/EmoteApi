import requests, os, sys, json, time, urllib3, base64, datetime, re, socket, threading, ssl, asyncio
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp

# IMPORTS
from xC4 import *
from xHeaders import *
from Pb2 import DEcwHisPErMsG_pb2, MajoRLoGinrEs_pb2, PorTs_pb2, MajoRLoGinrEq_pb2

urllib3.disable_warnings()
app = Flask(__name__)
CORS(app)

loop = None

# --- HELPER: LOGIN REQUESTS ---
async def GeNeRaTeAccEss(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    data = {"uid": uid, "password": password, "client_id": "100067", "response_type": "token"}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(url, data=data, headers={"User-Agent": GAME_CONFIG['user_agent']}) as r:
                if r.status != 200: return None, None
                d = await r.json()
                return d.get("open_id"), d.get("access_token")
    except: return None, None

async def EncRypTMajoRLoGin(open_id, access_token):
    proto = MajoRLoGinrEq_pb2.MajorLogin()
    proto.client_version = GAME_CONFIG['game_version']
    proto.open_id = open_id
    proto.access_token = access_token
    proto.platform_id = 1
    # Standard Fields
    proto.system_hardware = "Handheld"
    proto.network_type = "WIFI"
    proto.device_type = "Handheld"
    
    # Encryption
    cipher = AES.new(Key, AES.MODE_CBC, Iv)
    return cipher.encrypt(pad(proto.SerializeToString(), AES.block_size))

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {'ReleaseVersion': GAME_CONFIG['release_version'], 'User-Agent': GAME_CONFIG['user_agent']}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(url, data=payload, headers=headers, ssl=False) as r:
                return await r.read() if r.status == 200 else None
    except: return None

async def GetLoginData(base, pay, tok):
    url = f"{base}/GetLoginData"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(url, data=pay, headers={"Authorization": f"Bearer {tok}"}, ssl=False) as r:
                return await r.read() if r.status == 200 else None
    except: return None

# --- BOT CLASS (ON-DEMAND) ---
class FreeFireBot:
    def __init__(self, region, uid, password):
        self.region = region
        self.uid = uid
        self.password = password
        self.online_writer = None
        self.connected = False
        self.is_busy = False
        self.last_activity = 0
        self.bot_uid = None
        self.auth_token = None

    async def connect(self):
        """Wakes up the bot"""
        if self.connected: return True
        try:
            print(f"🔌 [{self.region}] Waking up Bot {self.uid}...")
            
            # Login Flow
            oid, token = await GeNeRaTeAccEss(self.uid, self.password)
            if not oid: return False
            
            pyl = await EncRypTMajoRLoGin(oid, token)
            resp = await MajorLogin(pyl)
            if not resp: return False
            
            auth_res = MajoRLoGinrEs_pb2.MajorLoginRes()
            auth_res.ParseFromString(resp)
            self.bot_uid = auth_res.account_uid
            
            # Get Ports
            log_bytes = await GetLoginData(auth_res.url, pyl, auth_res.token)
            if not log_bytes: return False
            
            login_data = PorTs_pb2.GetLoginData()
            login_data.ParseFromString(log_bytes)
            
            game_ip, game_port = login_data.Online_IP_Port.split(":")
            
            # Connect
            self.auth_token = await xAuThSTarTuP(int(self.bot_uid), auth_res.token, int(auth_res.timestamp), Key, Iv)
            
            asyncio.create_task(self.tcp_loop(game_ip, game_port))
            
            self.connected = True
            self.last_activity = time.time()
            print(f"✅ [{self.region}] Bot Online!")
            return True
        except Exception as e:
            print(f"❌ Login Error: {e}")
            return False

    async def tcp_loop(self, ip, port):
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            self.online_writer = writer
            writer.write(bytes.fromhex(self.auth_token))
            await writer.drain()
            
            while self.connected:
                # 5 Min Idle Timeout
                if time.time() - self.last_activity > 300: 
                    print(f"💤 {self.uid} Sleeping (Idle)...")
                    break
                
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=10)
                    if not data: break
                except: pass
            
            writer.close()
        except: pass
        finally:
            self.connected = False
            self.online_writer = None

    async def execute_task(self, code, target_uid):
        self.last_activity = time.time()
        
        if not self.connected:
            if not await self.connect(): return False
            
        self.is_busy = True
        try:
            # 1. Join
            pkt = await GenJoinSquadsPacket(code, Key, Iv, self.region)
            if self.online_writer:
                self.online_writer.write(pkt) 
                await self.online_writer.drain()
            print(f"🚀 [{self.region}] Joining {code}...")
            await asyncio.sleep(1.5) 
            
            # 2. Emote
            emote = await Emote_k(int(target_uid), 909038002, Key, Iv, self.region)
            if self.online_writer:
                self.online_writer.write(emote)
                await self.online_writer.drain()
            print(f"🎭 [{self.region}] Emoting...")
            
            # 3. Leave
            await asyncio.sleep(1)
            leave = await ExiT(self.bot_uid, Key, Iv)
            if self.online_writer:
                self.online_writer.write(leave)
                await self.online_writer.drain()
            print(f"🚪 [{self.region}] Left.")
            
            return True
        except Exception as e: 
            print(f"Task Failed: {e}")
            return False
        finally: self.is_busy = False

# --- MANAGER ---
class BotManager:
    def __init__(self):
        self.bots = {}

    def load_bots(self):
        accs = GAME_CONFIG.get('accounts', {})
        for reg, list_acc in accs.items():
            self.bots[reg] = [FreeFireBot(reg, a['uid'], a['pass']) for a in list_acc]
        print(f"🤖 Loaded {sum(len(v) for v in self.bots.values())} bots.")

    async def get_best_bot(self, region):
        reg = region.upper()
        if reg not in self.bots: return None
        
        # 1. Find Online & Free
        for bot in self.bots[reg]:
            if bot.connected and not bot.is_busy: return bot
            
        # 2. Find Offline & Free (Wake it up)
        for bot in self.bots[reg]:
            if not bot.connected:
                if await bot.connect(): return bot
        
        return None

MANAGER = BotManager()

# --- API ---
@app.route('/api/execute', methods=['POST'])
def handle_req():
    data = request.json
    region = data.get('server', 'IND').upper()
    
    future = asyncio.run_coroutine_threadsafe(process_request(region, data), loop)
    result = future.result()
    return jsonify(result)

async def process_request(region, data):
    bot = await MANAGER.get_best_bot(region)
    if not bot: 
        return {"status": "busy", "message": "All bots busy/offline. Try again in 5s."}
    
    asyncio.create_task(bot.execute_task(data['code'], data['uid']))
    return {"status": "success", "message": f"Task assigned to Bot {bot.uid} ({region})"}

def run_flask():
    app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)

async def StarTinG():
    global loop
    loop = asyncio.get_running_loop()
    
    print("🔄 Checking for Updates...")
    fetch_auto_update()
    MANAGER.load_bots()
    
    threading.Thread(target=run_flask, daemon=True).start()
    print("✅ System Ready. Waiting for API Requests...")
    
    while True:
        await asyncio.sleep(10)

if __name__ == '__main__':
    asyncio.run(StarTinG())

