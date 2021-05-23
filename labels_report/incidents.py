import json,requests,write_excel,funciones

mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/incidents"
header = {"id":"603fbc7ba3c9f9b8a0e72cc6", 'content-type': 'application/json','Accept':'application/json'}

#/overview/incidents/incidents?from_time=1617484140000&to_time=1620079200000



def get_incidents(token):
    header = {"Authorization": "Bearer " + token}
    variable_filter= "?from_time=1617491340000&to_time=1620086400000&incident_type=Network%20Scan&limit=1"
    #variable_filter="/ae9b8b1f-b30b-4cf8-b611-4d633b03d52f"
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    r = r.json()
    num_incs=len(r["objects"])
    incs=[]
    for i in range(0,num_incs):  
        incs.append(r["objects"][i]["_id"])
    return incs

def get_incident_detail(token,inc):
    header = {"Authorization": "Bearer " + token}
    variable_filter="/"+inc
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    r = r.json()
    hostname=r["affected_assets"][0]["ip"]
    print (r["affected_assets"][0]["ip"],r["affected_assets"][0]["vm"]["name"],r["incident_type"])
    print (r["start_time"],r["end_time"])
    dip,dport=[],[]
    for i in r["destinations"]:
        dip.append(i)
        dport.append(r["destinations"][i]["ports"])
    print(dip)
    print(dport)
    unique_key=["dest","ports"]   ##funcion crear un key unico, return un key para el title
   # write_excel.excel2(hostname,dip,dport,unique_key) ##funcion excel / label[0] es el key2 / label[1] es el value2


  

 
