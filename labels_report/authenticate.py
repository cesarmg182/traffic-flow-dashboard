import json,requests

def auth_get_token():
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/"
    #mgmt_url = "https://78.46.28.1/api/v3.0/"
    creds= {"username": "admin", "password": "YTg7MDU2Nj35ZmQx"}
    headers = {'content-type': 'application/json'}

    r = requests.post(mgmt_url + "authenticate", data=json.dumps(creds), headers=headers, verify=False)

    print('Status HTTP Message AUTHENTICATION : '+str(r.status_code),r)
    token_tmp=r.json()['access_token']
    #print ("TOKEN:" + token_tmp)
    return token_tmp

