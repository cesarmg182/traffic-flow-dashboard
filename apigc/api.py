from typing import List
import json,requests

def auth_get_token():
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/"
    creds= {"username": "admin", "password": "YTg7MDU2Nj35ZmQx"}
    headers = {'content-type': 'application/json'}
    r = requests.post(mgmt_url + "authenticate", data=json.dumps(creds), headers=headers, verify=False)
    token_tmp=r.json()['access_token']
    return token_tmp

header = {"id":"603fbc7ba3c9f9b8a0e72cc6", 'content-type': 'application/json','Accept':'application/json'}

def fetch_available_maps() -> List[str]:
    return ["INFO"]

def fetch_available_label_group() -> List[str]:
    return ["SERVERS:TRANSVERSAL"]

def fetch_available_label() -> List[str]:
    return ["APP:INFO"]
"""
def fetch_available_maps() -> List[str]:
    #return ["INFO"]
    token=auth_get_token()
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/visibility/saved-maps?limit=50"
    header = {"Authorization": "Bearer " + token}
    r = requests.get( url = mgmt_url,verify=False,headers = header)
    r = r.json()
    l=[]
    for i in range(0,len(r["objects"])):
        l.append(r["objects"][i]["name"])
    return l

def fetch_available_label_group() -> List[str]:
    #return ["SERVERS:TRANSVERSAL"]
    token=auth_get_token()
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/visibility/label-groups?assets_status=on,off"
    header = {"Authorization": "Bearer " + token}
    r = requests.get( url = mgmt_url,verify=False,headers = header)
    r = r.json()
    l=[]
    for i in range(0,len(r["objects"])):
        l.append(r["objects"][i]["key"]+":"+r["objects"][i]["value"])
    return l

def fetch_available_label() -> List[str]:
    #return ["APP:INFO"]
    token=auth_get_token()
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/visibility/labels?assets=on,off&limit=200"
    header = {"Authorization": "Bearer " + token}
    r = requests.get( url = mgmt_url,verify=False,headers = header)
    r = r.json()
    l=[]
    for i in range(0,len(r["objects"])):
        l.append(r["objects"][i]["key"]+":"+r["objects"][i]["value"])
    return l
"""