import json,datetime

def exec_my_script():
    x = datetime.datetime.now()
    fecha= ("%s-%s-%s_%sh_%sm_%ss" % (x.year, x.month, x.day, x.hour, x.minute,x.second))
    fh = open('json_file'+fecha+'.txt', 'a')
    json_var="hola"
    json_write = json.dumps(json_var)
    fh.write(json_write)
    fh.close()

