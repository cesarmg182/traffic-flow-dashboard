import json,datetime

def write_json_file(json_var):
    x = datetime.datetime.now()
    fecha= ("%s-%s-%s_%sh_%sm_%ss" % (x.year, x.month, x.day, x.hour, x.minute,x.second))
    fh = open('json_file'+fecha+'.txt', 'a')
    json_write = json.dumps(json_var)
    #json_write = str(json_var)
    fh.write(json_write)
    fh.close()

def write_assests_file(json_assets):
    fh = open('demo.txt', 'a')
    for i in range(len(json_assets["objects"])):
        print(f"Server#: {i}")
        hostname = json_assets["objects"][i]['guest_agent_details']['hostname']
        print("Hostname:" + hostname)
        ips = json_assets["objects"][i]['guest_agent_details']['network'][0]['ip_addresses']
        print("IPs: ", ips)
        distribution = json_assets["objects"][i]['guest_agent_details']['os_details']['distribution']
        print("Distribution: " + distribution)
        hwuuid = json_assets["objects"][i]['guest_agent_details']['hardware']['hw_uuid']
        print("hw_uuid: " + hwuuid)
        print("---")

        fh.write("Servidor:" + str(i+1) + "\n")
        fh.write("Hostname: " + hostname + "\n")
        fh.write("IPs: " + str(ips) + "\n")
        fh.write("Distribution: " + distribution + "\n")
        fh.write("HW UUID: " + hwuuid + "\n")
        fh.write("\n")

    fh.close()