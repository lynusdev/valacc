import tkinter as tk
from tkinter import ttk, messagebox
import sv_ttk
import requests
import time
import dateutil.parser as dp
from collections import OrderedDict
import ssl
from requests.adapters import HTTPAdapter
from typing import Any
from re import compile
import mysql.connector
from random import randint

db = mysql.connector.connect(host="localhost", user="root", passwd="root", database="valacc")
c = db.cursor()

root = tk.Tk()
root.title("valacc")
sv_ttk.use_dark_theme()
root.resizable(False, False)

CIPHERS = ['ECDHE-ECDSA-AES128-GCM-SHA256',
           'ECDHE-ECDSA-CHACHA20-POLY1305',
           'ECDHE-RSA-AES128-GCM-SHA256',
           'ECDHE-RSA-CHACHA20-POLY1305',
           'ECDHE+AES128',
           'RSA+AES128',
           'ECDHE+AES256',
           'RSA+AES256',
           'ECDHE+3DES',
           'RSA+3DES']

ranks = ["Unranked", "Unused1", "Unused2",
         "Iron 1", "Iron 2", "Iron 3",
         "Bronze 1", "Bronze 2", "Bronze 3",
         "Silver 1", "Silver 2", "Silver 3",
         "Gold 1", "Gold 2", "Gold 3",
         "Platinum 1", "Platinum 2", "Platinum 3",
         "Diamond 1", "Diamond 2", "Diamond 3",
         "Immortal 1", "Immortal 2", "Immortal 3",
         "Radiant"]

shards =  { "latam":"na",
            "br":"na",
            "na":"na",
            "eu":"eu",
            "ap":"ap",
            "kr":"kr"}

class SSLAdapter(HTTPAdapter):
	def init_poolmanager(self, *a: Any, **k: Any) -> None:
		c = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
		c.set_ciphers(':'.join(CIPHERS))
		k['ssl_context'] = c
		return super(SSLAdapter, self).init_poolmanager(*a, **k)
     
def get_tokens(username, password):
    session = requests.Session()
    session.headers = OrderedDict({"User-Agent": "RiotClient/79.0.1.1001.2013 %s (Windows;10;;Professional, x64)","Accept-Language": "en-US,en;q=0.9","Accept": "application/json, text/plain, */*"})
    session.mount('https://', SSLAdapter())
    nonce = str(randint(11111111, 99999999))
    json1 = {"acr_values": "urn:riot:bronze","claims": "","client_id": "riot-client","nonce": nonce,"redirect_uri": "http://localhost/redirect","response_type": "token id_token","scope": "openid link ban lol_region",}
    json2 = {"language": "en_US","password": password,"remember": "true","type": "auth","username": username,}
    response = session.post(url="https://auth.riotgames.com/api/v1/authorization", json = json1)
    response = session.put(url="https://auth.riotgames.com/api/v1/authorization", json = json2)
    if "rate limited" in response.text:
        print(f"rate limited: {username}")
        return "rate_limited"
    data = response.json()
    if "access_token" in response.text:
        pattern = compile('access_token=((?:[a-zA-Z]|\d|\.|-|_)*).*id_token=((?:[a-zA-Z]|\d|\.|-|_)*).*expires_in=(\d*)')
        data = pattern.findall(data['response']['parameters']['uri'])[0]
        token = data[0]
        id_token = data[1]

    elif "auth_failure" in response.text:
        print(f"auth failiure: {username}")
        return "auth_failure"

    elif 'rate_limited' in response.text:
        print(f"rate limited: {username}")
        return "rate_limited"
    
    headers = {'User-Agent': "RiotClient/58.0.0.4640299.4552318 %s (Windows;10;;Professional, x64)",'Authorization': f'Bearer {token}',}
    session.headers.update(headers)
    response = session.post("https://entitlements.auth.riotgames.com/api/token/v1", json={})
    entitlement = response.json()['entitlements_token']

    return [token, entitlement, id_token]

def get_info(token, entitlement, id_token):
    url = "https://auth.riotgames.com/userinfo"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.request("GET", url, headers=headers)
    data = response.json()
    sub = data["sub"]
    riot_id = data["acct"]["game_name"] + "#" + data["acct"]["tag_line"]


    url = "https://riot-geo.pas.si.riotgames.com/pas/v1/product/valorant"
    json = {"id_token": id_token}
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    response = requests.request("PUT", url, json=json, headers=headers)
    data = response.json()
    region = data["affinities"]["live"]
    shard = shards[region]

    try:
        url = f"https://pd.{shard}.a.pvp.net/account-xp/v1/players/{sub}"
        headers = {
            "X-Riot-Entitlements-JWT": entitlement,
            "Authorization": f"Bearer {token}"
        }
        response = requests.request("GET", url, headers=headers)
        data = response.json()
        level = data["Progress"]["Level"]
        next_daily_win = dp.parse(data["NextTimeFirstWinAvailable"]).timestamp()
        if time.time() - next_daily_win >= 0:
            first_win = 0
        else:
            first_win = 1
    except Exception as e:
        print(f"couldn't get level and first win")
        level = 0
        first_win = 0

    try:
        url = f"https://pd.{shard}.a.pvp.net/daily-ticket/v1/{sub}"
        headers = {
            "X-Riot-Entitlements-JWT": entitlement,
            "Authorization": f"Bearer {token}"
        }
        response = requests.request("GET", url, headers=headers)
        data = response.json()
        milestone_1 = data["DailyRewards"]["Milestones"][0]["Progress"]
        milestone_2 = data["DailyRewards"]["Milestones"][1]["Progress"]
        milestone_3 = data["DailyRewards"]["Milestones"][2]["Progress"]
        milestone_4 = data["DailyRewards"]["Milestones"][3]["Progress"]
        if milestone_1 == 4 and milestone_2 == 4 and milestone_3 == 4 and milestone_4 == 4:
            dailies_done = 1
        else:
            dailies_done = 0
    except Exception as e:
        print(f"couldn't get dailies")
        dailies_done = 0

    try:
        url = f"https://pd.{shard}.a.pvp.net/mmr/v1/players/{sub}"
        headers = {
            "X-Riot-Entitlements-JWT": entitlement,
            "X-Riot-ClientPlatform": "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9",
            "X-Riot-ClientVersion": "release-08.02-shipping-9-2265102",
            "Authorization": f"Bearer {token}"
        }
        response = requests.request("GET", url, headers=headers)
        data = response.json()
        if data["QueueSkills"]["competitive"]["TotalGamesNeededForRating"] > 0:
            tier_number = 0
        else:
            season_keys = list(data["QueueSkills"]["competitive"]["SeasonalInfoBySeasonID"])
            tier_number = data["QueueSkills"]["competitive"]["SeasonalInfoBySeasonID"][season_keys[-1]]["CompetitiveTier"]
        rank = ranks[tier_number]
    except Exception as e:
        print(f"couldn't get rank")
        rank = "?"

    try:
        url = f"https://pd.{shard}.a.pvp.net/store/v1/wallet/{sub}"
        headers = {
            "X-Riot-Entitlements-JWT": entitlement,
            "Authorization": f"Bearer {token}"
        }
        response = requests.request("GET", url, headers=headers)
        data = response.json()
        balances = list(data["Balances"])
        vp = data["Balances"][balances[0]]
        kingdom_credits = data["Balances"][balances[1]]
        radianite = data["Balances"][balances[2]]
    except Exception as e:
        print(f"couldn't get vp, kingdom credits and radianite")
        vp = -1
        kingdom_credits = -1
        radianite = -1

    try:
        url = f"https://pd.{shard}.a.pvp.net/restrictions/v3/penalties"
        headers = {
            "X-Riot-Entitlements-JWT": entitlement,
            "X-Riot-ClientPlatform": "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9",
            "Authorization": f"Bearer {token}"
        }
        response = requests.request("GET", url, headers=headers)
        data = response.json()
        if data["Penalties"] == []:
            ban = 0
        else:
            ban = 1
    except Exception as e:
        print(f"couldn't get ban")
        ban = 0

    return [riot_id, region, level, rank, vp, radianite, kingdom_credits, ban, first_win, dailies_done]

def custom_order(account):
    if "EC" in account[0] and "#1312" in account[0]:
        number = int(account[0].split("EC")[1].split("#1312")[0])
        return number
    else:
        return 9999

def update_table():
    for item in table.get_children():
        table.delete(item)
    c.execute("SELECT riotid, username, region, level, rankk, vp, rn, kc, ban, firstwin, dailies FROM accounts ORDER BY riotid")
    accounts = c.fetchall()
    accounts.sort(key = custom_order)
    for account in accounts:
        formatted_account = list(account)
        if formatted_account[-1] == 0:
            formatted_account[-1] = "✗"
        else:
            formatted_account[-1] = "✓"
        if formatted_account[-2] == 0:
            formatted_account[-2] = "✗"
        else:
            formatted_account[-2] = "✓"
        if formatted_account[-3] == 0:
            formatted_account[-3] = "✗"
        else:
            formatted_account[-3] = "✓"
        table.insert('', tk.END, values=formatted_account)
    accounts_count.set(f"{len(accounts)} accounts")

def add_account():
    frame.focus_set()
    username = username_entry.get()
    password = password_entry.get()
    username_entry.delete(0, 'end')
    password_entry.delete(0, 'end')
    if username == "" or password == "":
        return
    c.execute(f"SELECT * FROM accounts WHERE username='{username}'")
    results = c.fetchall()
    if not results == []:
        messagebox.showerror("error", f"account already added: {username}")
        return
    tokens = get_tokens(username, password)
    if tokens == "auth_failure":
        messagebox.showerror("error", f"couldn't add, auth failure: {username}")
        return
    elif tokens == "rate_limited":
        messagebox.showerror("error", f"couldn't add, rate limited: {username}")
        return
    try:
        info = get_info(tokens[0], tokens[1], tokens[2])
    except:
        messagebox.showerror("error", f"couldn't get info, login and retry: {username}")
        return
    c.execute(f"INSERT INTO accounts VALUES ('{username}', '{password}', '{tokens[0]}', '{tokens[1]}', '{tokens[2]}', '{info[0]}', '{info[1]}', {info[2]}, '{info[3]}', {info[4]}, {info[5]}, {info[6]}, {info[7]}, {info[8]}, {info[9]})")
    db.commit()
    update_table()
    print(f"successfully added account: {username}")

def delete():
    frame.focus_set()
    selected_item = table.focus()
    if selected_item == "":
        return
    username = table.item(selected_item)["values"][1]
    c.execute(f"DELETE FROM accounts WHERE username='{username}'")
    db.commit()
    update_table()

def refresh():
    frame.focus_set()
    selected_item = table.focus()
    if selected_item == "":
        return
    username = table.item(selected_item)["values"][1]
    c.execute(f"SELECT token, entitlement, idtoken FROM accounts WHERE username='{username}'")
    tokens = list(c.fetchall()[0])
    try:
        info = get_info(tokens[0], tokens[1], tokens[2])
        print(f"[{username}] saved tokens valid")
    except Exception as e:
        print(f"[{username}] saved tokens invalid")
        c.execute(f"SELECT password FROM accounts WHERE username='{username}'")
        password = list(c.fetchall()[0])[0]
        tokens = get_tokens(username, password)
        if tokens == "auth_failure":
            messagebox.showerror("error", f"couldn't refresh, auth failure: {username}")
            return
        elif tokens == "rate_limited":
            messagebox.showerror("error", f"couldn't refresh, rate limited: {username}")
            return
        c.execute(f"UPDATE accounts SET token='{tokens[0]}', entitlement='{tokens[1]}', idtoken='{tokens[2]}' WHERE username = '{username}'")
        info = get_info(tokens[0], tokens[1], tokens[2])
    c.execute(f"UPDATE accounts SET riotid='{info[0]}', region='{info[1]}', level='{info[2]}', rankk='{info[3]}', vp='{info[4]}', rn='{info[5]}', kc='{info[6]}', ban='{info[7]}', firstwin='{info[8]}', dailies='{info[9]}' WHERE username = '{username}'")
    db.commit()
    update_table()

def refresh_all():
    frame.focus_set()
    bar = ttk.Progressbar(actions_frame, orient="horizontal", variable=progress)
    bar.pack(fill="both", padx=10, pady=(0, 10))
    progress.set(0)
    root.update()
    
    c.execute("SELECT riotid, username, password, token, entitlement, idtoken FROM accounts ORDER BY riotid")
    accounts = c.fetchall()
    accounts.sort(key = custom_order)

    for account in accounts:
        username = list(account)[1]
        password = list(account)[2]
        tokens = [list(account)[3], list(account)[4], list(account)[5]]
        try:
            info = get_info(tokens[0], tokens[1], tokens[2])
            print(f"[{username}] saved tokens valid")
        except Exception as e:
            print(f"[{username}] saved tokens invalid")
            tokens = get_tokens(username, password)
            if tokens == "auth_failure":
                messagebox.showerror("error", f"couldn't refresh, auth failure: {username}")
                continue
            elif tokens == "rate_limited":
                messagebox.showerror("error", f"couldn't refresh, rate limited: {username}")
                bar.pack_forget()
                return
            c.execute(f"UPDATE accounts SET token='{tokens[0]}', entitlement='{tokens[1]}', idtoken='{tokens[2]}' WHERE username = '{username}'")
            info = get_info(tokens[0], tokens[1], tokens[2])
        c.execute(f"UPDATE accounts SET riotid='{info[0]}', region='{info[1]}', level='{info[2]}', rankk='{info[3]}', vp='{info[4]}', rn='{info[5]}', kc='{info[6]}', ban='{info[7]}', firstwin='{info[8]}', dailies='{info[9]}' WHERE username = '{username}'")
        db.commit()
        update_table()
        if account == accounts[-1]:
            progress.set(99.9)
            root.update()
            time.sleep(0.1)
            bar.pack_forget()
        else:
            progress.set(progress.get()+(100/len(accounts)))
        root.update()

def copy_username():
    frame.focus_set()
    selected_item = table.focus()
    if selected_item == "":
        return
    username = table.item(selected_item)["values"][1]
    root.clipboard_clear()
    root.clipboard_append(username)

def copy_password():
    frame.focus_set()
    selected_item = table.focus()
    if selected_item == "":
        return
    username = table.item(selected_item)["values"][1]
    c.execute(f"SELECT password FROM accounts WHERE username='{username}'")
    password = list(c.fetchall()[0])
    root.clipboard_clear()
    root.clipboard_append(password)

frame = ttk.Frame(root)
frame.pack()

widgets_frame = ttk.Frame(frame)
widgets_frame.grid(row=0, column=0, sticky="n")

accounts_count = tk.StringVar()

accounts_label = ttk.Label(widgets_frame, textvariable=accounts_count)
accounts_label.grid(row=3, column=0, padx=10, pady=10)


login_frame = ttk.Labelframe(widgets_frame, text="add account")
login_frame.grid(row=0, column=0, padx=20, pady=10, sticky="nsew")

username_entry = ttk.Entry(login_frame)
username_entry.pack(fill="both", padx=10, pady=10)

password_entry = ttk.Entry(login_frame, show="*")
password_entry.pack(fill="both", padx=10, pady=(0, 10))

add_account_button = ttk.Button(login_frame, text="add account", command=add_account)
add_account_button.pack(fill="both", padx=10, pady=(0, 10))


actions_frame = ttk.Labelframe(widgets_frame, text="actions")
actions_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")

delete_button = ttk.Button(actions_frame, text="delete", command=delete)
delete_button.pack(fill="both", padx=10, pady=10)

refresh_button = ttk.Button(actions_frame, text="refresh", command=refresh)
refresh_button.pack(fill="both", padx=10, pady=(0, 10))

separator = ttk.Separator(actions_frame)
separator.pack(fill="both", padx=10, pady=(0, 10))

refresh_all_button = ttk.Button(actions_frame, text="refresh all", command=refresh_all)
refresh_all_button.pack(fill="both", padx=10, pady=(0, 10))

progress = tk.IntVar()


copy_frame = ttk.Labelframe(widgets_frame, text="copy")
copy_frame.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")

copy_username_button = ttk.Button(copy_frame, text="username", command=copy_username)
copy_username_button.pack(fill="both", padx=10, pady=10)

copy_password_button = ttk.Button(copy_frame, text="password", command=copy_password)
copy_password_button.pack(fill="both", padx=10, pady=(0, 10))


table_frame = ttk.Frame(frame)
table_frame.grid(row=0, column=1, pady=10)

treeScroll = ttk.Scrollbar(table_frame)
treeScroll.pack(side="right", fill="y")

columns = ["riot_id", "username", "region", "level", "rank", "vp", "rn", "kc", "ban", "first_win", "dailies"]

table = ttk.Treeview(table_frame, show="headings", yscrollcommand=treeScroll.set, columns=columns, height=23, selectmode="browse")
table.pack()
table.column("riot_id", width=140)
table.heading("riot_id", text="riot id")
table.column("riot_id", anchor="center")
table.column("username", width=140)
table.heading("username", text="username")
table.column("username", anchor="center")
table.column("region", width=70)
table.heading("region", text="region")
table.column("region", anchor="center")
table.column("level", width=50)
table.heading("level", text="level")
table.column("level", anchor="center")
table.column("rank", width=80)
table.heading("rank", text="rank")
table.column("rank", anchor="center")
table.column("vp", width=80)
table.heading("vp", text="vp")
table.column("vp", anchor="center")
table.column("rn", width=80)
table.heading("rn", text="rn")
table.column("rn", anchor="center")
table.column("kc", width=80)
table.heading("kc", text="kc")
table.column("kc", anchor="center")
table.column("ban", width=28)
table.heading("ban", text="ban")
table.column("ban", anchor="center")
table.column("first_win", width=28)
table.heading("first_win", text="fw")
table.column("first_win", anchor="center")
table.column("dailies", width=28)
table.heading("dailies", text="dy")
table.column("dailies", anchor="center")
treeScroll.config(command=table.yview)

update_table()

root.mainloop()