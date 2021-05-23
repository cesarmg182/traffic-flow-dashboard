import json,requests,write_excel,funciones

mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/visibility/labels"
header = {"id":"603fbc7ba3c9f9b8a0e72cc6", 'content-type': 'application/json','Accept':'application/json'}

def get_labels_all(token):
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/agents"
    header = {"Authorization": "Bearer " + token}
    variable_filter= "?sort=display_name&offset=0&limit=800"
    #variable_filter= "?sort=display_name&offset=0&gc_filter=PAPTCLNXP01"
    #variable_filter= "?sort=display_name&activity=last_month&gc_filter=sqlp01&limit=15"
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    r = r.json()
    num_host=len(r["objects"])
    hostname,key2,value2=[],[],[]
    for i in range(0,num_host):  
        num_label=len(r["objects"][i]["labels"])
        hostname.append(r["objects"][i]["hostname"])
        key,value,tempkey,tempvalue=[],[],[],[]
        for n in range(0,num_label):
            key.append(r["objects"][i]["labels"][n]["key"])           #key original obtenido de json
            value.append(r["objects"][i]["labels"][n]["value"])       #value original obtenido de json
        if len(key)>0:                    ## unificar keys buscando los multiples key y uniendo en un solo string
            for x in range(0,len(key)):
                if key[x] not in tempkey:
                    tempkey.append(key[x])
                    tempvalue.append(value[x])
                else:
                    for y in range(0,len(tempvalue)):  # busca en los valores iguales guardados en f
                        if key[x]==tempkey[y]:
                            tempvalue[y]=tempvalue[y]+","+value[x]
        key2.append(tempkey)        # key2 final ya unificado y reducido
        value2.append(tempvalue)    # value2 final ya unificado y reducido
    unique_key=funciones.get_unique_key(key2)   ##funcion crear un key unico, return un key para el title
    label=funciones.order_key_value(key2,value2,unique_key)  # funcion ordenar key/value, return key2/value2
    write_excel.excel(hostname,label[0],label[1],unique_key) ##funcion excel / label[0] es el key2 / label[1] es el value2
###############################################################

def get_labels_status(token):
    header = {"Authorization": "Bearer " + token}
    #variable_filter= "?assets=on,off&text_search=yape"
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/visibility/label-groups?assets_status=on,off"
    variable_filter=""
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    print('Status HTTP Message GET Assets Status : '+str(r.status_code),r)
    r = r.json()
    return r

def get_labels_test(token):
    header = {"Authorization": "Bearer " + token}
    variable_filter= "?assets=on,off&text_search=db"
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    r = r.json()
    num_host=len(r["objects"])
    for i in range(0,num_host):
        print(r["objects"][i]['key'],":",r["objects"][i]['value'])   
        num_match=len(r["objects"][i]["matching_assets"])
        num_dyn=len(r["objects"][i]["dynamic_criteria"])        
        for n in range(0,num_match):
            print(r["objects"][i]["matching_assets"][n]["name"])
        for n in range(0,num_dyn):         
            print(r["objects"][i]["dynamic_criteria"][n]["field"],r["objects"][i]["dynamic_criteria"][n]["op"],r["objects"][i]["dynamic_criteria"][n]["argument"])
 
