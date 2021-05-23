import json,requests,write_excel,funciones

mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/asets"
header = {"id":"603fbc7ba3c9f9b8a0e72cc6", 'content-type': 'application/json','Accept':'application/json'}

m={}
def get_labels_all(token,offset,limit):
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/assets"
    header = {"Authorization": "Bearer " + token}
    variable_filter= "?status=on&offset="+str(offset)+"&limit="+str(limit)+"&sort=status"
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    r = r.json()
    #print (r["objects"][0]["labels"])
    #print(r["objects"][0]["guest_agent_details"]["hostname"])
    for n in range(0,len(r["objects"])):
        m[r["objects"][n]["guest_agent_details"]["hostname"]]=r["objects"][n]["labels"]
    return m

def order_labels_all(d):
    num_host=len(d)
    print(num_host)
    hostname,key2,value2=[],[],[]
    hostname=d.keys()
    for i in hostname:  
        num_label=len(d[i])
        key,value,tempkey,tempvalue=[],[],[],[]
        for n in range(0,num_label):
            key.append(d[i][n]["key"])           #key original obtenido de json
            value.append(d[i][n]["value"])       #value original obtenido de json
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
    print(key2)
    print(value2)
    unique_key=funciones.get_unique_key(key2)   ##funcion crear un key unico, return un key para el title
    label=funciones.order_key_value(key2,value2,unique_key)  # funcion ordenar key/value, return key2/value2
    write_excel.excel(hostname,label[0],label[1],unique_key) ##funcion excel / label[0] es el key2 / label[1] es el value2
    fin =[hostname,label[0],label[1],unique_key]
    return fin
############################################################

