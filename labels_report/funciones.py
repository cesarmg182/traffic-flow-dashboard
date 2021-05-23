def get_unique_key(key):
    newkey,finalkey=[],[]
    for i in key:
        if len(i)>0:
            for j in i:
                newkey.append (j)
    [finalkey.append(x) for x in newkey if x not in finalkey]                         
    print(finalkey," -> LABELS TOTALES")
    return finalkey

def order_key_value(key2,value2,unique_key):
    for k in range(0,len(key2)):
        if key2[k]==unique_key or len(key2[k])==0:
            continue
        else:
            temp=[None]*len(unique_key)
            for a in range(0,len(unique_key)):  #valor del unique_key
                for i in range(0,len(key2[k])):
                    if key2[k][i]==unique_key[a]:
                        temp[a]=value2[k][i]
                        break
            value2[k]=temp
    return key2,value2
        
