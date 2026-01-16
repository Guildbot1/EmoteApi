import requests, json, binascii, time, urllib3, base64, datetime, re, socket, threading, random, os, asyncio
from protobuf_decoder.protobuf_decoder import Parser
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- GLOBAL CONFIG ---
GAME_CONFIG = {
    "game_version": "1.120.1", 
    "release_version": "OB52",
    "headers_map": {"DEFAULT": "0515"}
}

# Initial Keys (GitHub se update honge)
Key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
Iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# --- AUTO UPDATE ---
def fetch_auto_update():
    global GAME_CONFIG, Key, Iv
    # 👇👇 YAHAN APNA GITHUB RAW LINK DALEN 👇👇
    url = "https://raw.githubusercontent.com/Guildbot1/EmoteApi/main/config.json"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            new_config = response.json()
            GAME_CONFIG.update(new_config)
            if 'encryption' in new_config:
                Key = bytes(new_config['encryption']['key'])
                Iv = bytes(new_config['encryption']['iv'])
            print(f"✅ Config Loaded: Ver {GAME_CONFIG['game_version']}")
            return True
    except: pass
    return False

def get_header(region):
    if not region: return "0515"
    return GAME_CONFIG.get('headers_map', {}).get(region.upper(), "0515")

# --- CRYPTO & UTILS ---
async def EnC_PacKeT(HeX, K, V): 
    return AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(HeX), 16)).hex()

async def DecodE_HeX(H):
    R = hex(H); F = str(R)[2:]
    return "0" + F if len(F) == 1 else F

async def EnC_Uid(H, Tp):
    e, H = [], int(H)
    while H: e.append((H & 0x7F) | (0x80 if H > 0x7F else 0)); H >>= 7
    return bytes(e).hex() if Tp == 'Uid' else None

async def EnC_Vr(N):
    if N < 0: return b''
    H = []
    while True:
        BesTo = N & 0x7F; N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)

async def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = await CrEaTe_ProTo(value)
            encoded_len = await EnC_Vr(len(nested))
            packet.extend(await EnC_Vr((field << 3) | 2) + encoded_len + nested)
        elif isinstance(value, int):
            packet.extend(await EnC_Vr((field << 3) | 0) + await EnC_Vr(value))
        elif isinstance(value, (str, bytes)):
            encoded = value.encode() if isinstance(value, str) else value
            encoded_len = await EnC_Vr(len(encoded))
            packet.extend(await EnC_Vr((field << 3) | 2) + encoded_len + encoded)
    return packet

async def GeneRaTePk(Pk, N, K, V):
    PkEnc = await EnC_PacKeT(Pk, K, V)
    _ = await DecodE_HeX(int(len(PkEnc) // 2))
    header = N + ("0" * (6 - len(_))) + _
    return bytes.fromhex(header + PkEnc)

# --- AUTH PACKET ---
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    
    pad_len = 16 - len(uid_hex)
    headers = "0" * pad_len
    if len(uid_hex) == 10: headers = '000000'
    elif len(uid_hex) == 9: headers = '0000000'
    elif len(uid_hex) == 11: headers = '00000'
    
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"

# --- GAME PACKETS ---
async def GenJoinSquadsPacket(code, K, V, region="global"):
    fields = {1: 4, 2: {4: bytes.fromhex("01090a0b121920"), 5: str(code), 6: 6, 8: 1, 9: {2: 800, 6: 11, 8: GAME_CONFIG['game_version'], 9: 5, 10: 1}}}
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), get_header(region), K, V)

async def Emote_k(TarGeT, idT, K, V, region="global"):
    fields = {1: 21, 2: {1: 804266360, 2: idT, 5: {1: TarGeT, 3: idT}}}
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), get_header(region), K, V)

async def ExiT(idT, K, V):
    fields = {1: 7, 2: {1: idT}}
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), "0515", K, V)
