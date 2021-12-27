# CattoBot

Do you ever look at your gists and feel like there's something missing? Then CattoBot is exactly what you need!
Enjoy many innocent cat pictures and absolutely not suspicious random phrases in your lonely gists' comments!

## What really is CattoBot?
CattoBot is a Command and Control script together with its bot, it exploits GitHub Gists for communication between controller and bots. Steganography techniques are used to hide commands and replies inside images of cute cats embedded in the comments.

## How to set up CattoBot
### Step 1
Generate a GitHub developer token (api key) with Gist among the scopes. Go here: https://github.com/settings/tokens/, click "Generate new token", check Gist in the scopes and copy and paste the token value inside the bot and the controller's code, aka replace the placeholder value for API_TOKEN variable (tokens of bot and controller can be different and can be of different users).
### Step 2
Generate a 32 bytes ChaCha20 symmetric key and replace the placeholder value of the variable CHACHA20_KEY in both the bot and the controller's code (make sure it is a python bytestring, the value MUST be the same between bot and controller).
### Step 3 (Optional)
Register to https://imgbb.com/ and generate an API key from https://api.imgbb.com/ then replace the default value of IMGBB_KEY in both the bot and the controller's code (keys of bot and controller can be different).
### Step 4 (Optional)
Generate user and password hash with _gen-hash.py_ and insert the generated data inside the USERS dict in the bot code.
### Step 5 (Optional)
Set the GIST_ID variable in both the bot and the controller's code to a gist of your choiche.

## How to run CattoBot
On the target machine(s):
```
python3 bot.py
```

On the command and control system:
```
python3 controller.py
```
Make sure requirements are installed!
