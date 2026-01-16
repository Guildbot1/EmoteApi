import requests
from xC4 import GAME_CONFIG

def equie_emote(JWT, url):
    url = f"{url}/ChooseEmote"
    headers = {
        "Authorization": f"Bearer {JWT}",
        "ReleaseVersion": GAME_CONFIG.get("release_version", "OB52"),
        "User-Agent": GAME_CONFIG.get("user_agent", "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)"),
        "X-Unity-Version": "2018.4.11f1",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = bytes.fromhex("CA F6 83 22 2A 25 C7 BE FE B5 1F 59 54 4D B3 13")
    try: requests.post(url, headers=headers, data=data)
    except: pass
