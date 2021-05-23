import json,requests

mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/assets"
header = {"id":"603fbc7ba3c9f9b8a0e72cc6", 'content-type': 'application/json','Accept':'application/json'}

def get_assests_status(token):
    header = {"Authorization": "Bearer " + token}
    variable_filter= "?status=on"
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)

    print('Status HTTP Message GET Assets Status : '+str(r.status_code),r)
    #print(r.headers)
    #print(r.text)
    r = r.json()
    return r

def get_assests_test(token):
    header = {"Authorization": "Bearer " + token}
    variable_filter= "?status=on"
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    r = r.json()
    #print(len(r["objects"]))
    #print(r["objects"][0]['guest_agent_details']["hostname"])
    #print(r["objects"][0]['_id'])
    #print(len(r["objects"][0]['guest_agent_details']["network"]))  # dice el # de interfaces
    #print(r["objects"][0]['guest_agent_details']["network"][0])
    #print(r["objects"][0]['guest_agent_details']["network"][1])
    print(r["objects"][0]["guest_agent_details"]["hostname"],"------------")
    print(r["objects"][0]["labels"][0]["key"],"-------------")

    for i in range(len(r["objects"])):
        hostname = r["objects"][i]['guest_agent_details']['hostname']
        v=len(r["objects"][i]['guest_agent_details']['network'])
        print("Hostname:" + hostname + " , " + str(v))
        if v ==1:  
            print (r["objects"][i]['guest_agent_details']['network'][0]['ip_addresses'])
        else:
            for n in range (0,v):
                vip=len(r["objects"][i]['guest_agent_details']['network'][n]['ip_addresses'])
                print (r["objects"][i]['guest_agent_details']['network'][n]['ip_addresses'])
#                if vip ==1:
#                    print( r["objects"][i]['guest_agent_details']['network'][n]['ip_addresses'][0]['address'])
#                else:
#                    for k in range (0,vip):
#                        print( r["objects"][i]['guest_agent_details']['network'][n]['ip_addresses'][k]['address'])
"""
    key_assets=["_id","name","ip_addresses","mac_addresses","status"]
    for k in r["objects"][0]:
        for i in key_assets:
            if i == k:
                print (k + " : " + str(r["objects"][0][k]))

    for k,v in r["objects"][0].items():
        for i in key_assets:
            if i == k:
                print (k + " : " + str(v))
"""