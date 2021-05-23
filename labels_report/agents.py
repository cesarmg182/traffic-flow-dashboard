import json,requests

mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/agents"
header = {"id":"603fbc7ba3c9f9b8a0e72cc6", 'content-type': 'application/json','Accept':'application/json'}

def get_agents_status(token):
    header = {"Authorization": "Bearer " + token}
    variable_filter= "?sort=display_name&activity=last_month&aggregator=AGR-420FBD69-9565-6BF4-0803-79E687BA02F8"
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)

    print('Status HTTP Message GET Assets Status : '+str(r.status_code),r)
    #print(r.headers)
    #print(r.text)
    r = r.json()
    return r

