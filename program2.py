from apigc.api import auth_get_token
import streamlit as st
from datetime import datetime
from typing import List
from apigc import fetch_available_maps,fetch_available_label_group,fetch_available_label
from templates import generate_map_values, MapValues
import json,requests
from labels_report import fetch_labels,authenticate
import os
os.chdir(r'C:\cesar\webserver\traffic-flow-dashboard')

available_label: List[str] = fetch_available_label()
available_map_values: List[str] = fetch_available_maps()
available_label_group: List[str] = fetch_available_label_group()

st.sidebar.image("logo.jpg")
st.sidebar.title("Description")
option= st.sidebar.selectbox("Dashboard",("Flow Traffic","Reports","JSON"))
st.sidebar.write("-----------")
if option== "Flow Traffic":
    with st.form(key='my_form'):
        st.title("FLOW TRAFFIC Report")

        st.sidebar.write(datetime.now())
        start_date = st.date_input("Start Date", datetime.now())
        end_date = st.date_input("End Date", datetime.now())
        start_time = st.time_input("Start Time", datetime.now())
        end_time = st.time_input("End Time", datetime.now())
        selected_map = st.selectbox('Select your map', available_map_values)
        include_label = st.selectbox('Include filter label', available_label)
        exclude_label_group = st.selectbox('Exclude filter label group', available_label_group)

        ignore_internal_traffic = st.checkbox('Ignore Internal traffic')
        delete_temp_map = st.checkbox('Delete Temporal Map')
        expand_subnets = st.checkbox('Expand Subnets')
        expand_internet = st.checkbox('Expand Internet')
        output_flows_count = st.checkbox('Include counter flows')

        submitted = st.form_submit_button(label='Generate')

        if submitted:
            generated_yaml = generate_map_values(MapValues(
                start_date=start_date,
                end_date=end_date,
                start_time=start_time,
                end_time=end_time,
                selected_map=selected_map,
                include_label=include_label,
                exclude_label_group=exclude_label_group,
                ignore_internal_traffic=ignore_internal_traffic,
                delete_temp_map=delete_temp_map,
                expand_subnets=expand_subnets,
                expand_internet=expand_internet,
                output_flows_count=output_flows_count
            ))

            with open("aggregated_flows_export\generated_yaml.yaml", "w") as file:

                file.write(generated_yaml)
 
    
if option=="Reports":
    with st.form(key='my_form2'):
        st.title("Reports")
        submitted2 = st.form_submit_button(label='Generate')

        if submitted2:
            exec(open("labels_report\menu.py").read())
            st.title("Reports done")


if option == "JSON":
    with st.form(key='my_form3'):
        st.title("JSON REPORT")
        submitted3 = st.form_submit_button(label='Generate')

        if submitted3:
            st.title("JSON done")

            available_labels: List[str] = fetch_labels()
            st.write(available_labels)

            """
            mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/"
            creds= {"username": "admin", "password": "YTg7MDU2Nj35ZmQx"}
            headers = {'content-type': 'application/json'}
            r = requests.post(mgmt_url + "authenticate", data=json.dumps(creds), headers=headers, verify=False)
            print('Status HTTP Message AUTHENTICATION : '+str(r.status_code),r)
            token=r.json()['access_token']
            offset=10
            limit=20
            m={}
            mgmt_url = "https://cus-2580.cloud.guardicore.com/api/v3.0/assets"
            header = {"Authorization": "Bearer " + token}
            variable_filter= "?status=on&offset="+str(offset)+"&limit="+str(limit)+"&sort=status"
            r = requests.get( url = mgmt_url + variable_filter,verify=False,headers = header)
            r = r.json()
            for n in range(0,len(r["objects"])):
                m[r["objects"][n]["guest_agent_details"]["hostname"]]=r["objects"][n]["labels"]
            st.write(m)
            """


           



