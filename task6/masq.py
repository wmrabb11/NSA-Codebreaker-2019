#!/usr/bin/python

import requests
import json
import base64
import xmpp
import sys

leader_username = 'ryan--vhost-254@terrortime.app'
chat_url = 'https://chat.terrortime.app'
get_url = 'https://register.terrortime.app/oauth2/token'
auth_prop = "Basic bWF4aW1pbGlhbm8tLXZob3N0LTI1NEB0ZXJyb3J0aW1lLmFwcDpNYWlKaDdnZjRFcExmbA=="

def get_token():
    headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": auth_prop,
            "X-Server-Select": "oauth"
            }
    data = {
            "audience": "",
            "grant_type": "client_credentials",
            "scope": "chat"
            }
    r = requests.post(get_url, headers=headers, data=data)
    json_rep = json.loads( r.content )
    try:
        tok = json_rep["access_token"]
        print( '[+] Access token: {}'.format(tok) )
    except Exception:
        print( r.content )

if __name__=="__main__":
    get_token()
