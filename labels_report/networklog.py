import json,requests

mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/visibility/saved_maps"
header = {"id":"603fbc7ba3c9f9b8a0e72cc6", 'content-type': 'application/json','Accept':'application/json'}

def get_labels_status2(token):
    header = {"Authorization": "Bearer " + token}
    variable_filter= "?saved_map_id=fb56bdcb-04d4-40a0-88ff-3941a0ef4299&start_time=1620257680843&end_time=1620261280843&group_by=APP,ROL&layout_key=15688038-676f-487c-9816-b8d18595f885"
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/visibility/label-groups?assets_status=on,off"
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    print('Status HTTP Message GET Assets Status : '+str(r.status_code),r)
    r = r.json()
    return r


def get_labels_status(token):
    header = {"Authorization": "Bearer " + token}
    #mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/segmentation/segmentation-policy?offset=0&limit=20&from_time=0&to_time=2147483647000"
    mgmt_url="https://cus-2580.cloud.guardicore.com/api/v3.0/visibility/policy/sections/allow/rules"
    variable_filter= ""
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    print('Status HTTP Message GET Assets Status : '+str(r.status_code),r)
    r = r.json()
    return r

def get_labels_status2(token):
    header = {"Authorization": "Bearer " + token}
    mgmt_url = "https://cus-2580.cloud.guardicore.com//api/v3.0/exported_csv_files/7b0d2aa8-12cf-4503-9c61-50d6e634607f?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb3V0ZSI6Ii9hcGkvdjMuMC9leHBvcnRlZF9jc3ZfZmlsZXMvN2IwZDJhYTgtMTJjZi00NTAzLTljNjEtNTBkNmU2MzQ2MDdmIiwiZXhwIjoxNjIwNzc2MTEwLjcxNjc2MDQsIm9yaWdpbmF0b3JfdXNlcl9pZCI6IjVmOTY5MjNiNWJiOTVmNjhiMDg5ZGYwNSJ9.NuwbOnx_-MV6Nnw_wkU54_syaex-TGQalRODWYyKtUg"
    variable_filter= ""
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    print('Status HTTP Message GET Assets Status : '+str(r.status_code),r)
    r = r.json()
    return r

def get_labels_status3(token):
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/reveal/explore"
    header = {"Authorization": "Bearer " + token}
#    body={"state": {}, "filters": {"include": {"user_label": ["32116186-4a64-4724-bf9f-984655d3778d"]}, "exclude": {}}, "force": False,"overlays": {}}
    body={"state": {}, "filters": {"include": {}, "exclude": {}}, "force": False,"overlays": {}}
    #body=""
    variable_filter= "?saved_map_id=fb56bdcb-04d4-40a0-88ff-3941a0ef4299&start_time=1620257680843&end_time=1620261280843&group_by=APP,ROL&layout_key=15688038-676f-487c-9816-b8d18595f885"
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header,params=body)
    print('Status HTTP Message GET Assets Status : '+str(r.status_code),r)
    r = r.json()
    return r

def get_labels_status2(token):
    header = {"Authorization": "Bearer " + token}
    variable_filter= ""
    mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/visibility/labels?assets_status=on,off&limit=1000"
    r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
    print('Status HTTP Message GET Assets Status : '+str(r.status_code),r)
    r = r.json()
    return r