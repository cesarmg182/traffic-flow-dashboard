import streamlit as st
from datetime import datetime
from typing import List
from apigc import fetch_available_maps,fetch_available_label_group,fetch_available_label
from templates import generate_map_values, MapValues
#from test import exec_my_script
import os
os.chdir(r'C:\cesar\webserver\traffic-flow-dashboard')

available_label: List[str] = fetch_available_label()
available_map_values: List[str] = fetch_available_maps()
available_label_group: List[str] = fetch_available_label_group()

with st.form(key='my_form'):
    st.sidebar.image("logo.jpg")
    st.sidebar.title("Description")
    oprtion= st.sidebar.selectbox("Dashboard",("Flow Traffic","Reports"))
    st.sidebar.write("-----------")
    
    
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

        # st.write(f"```yaml\n{generated_yaml}\n```")

        with open("aggregated_flows_export\generated_yaml.yaml", "w") as file:
        #with open("generated_yaml.yaml", "w") as file:

            file.write(generated_yaml)
            #exec(open("aggregated_flows_export\\aggregated_flows_export.py").read())
            #exec(open("test123.py").read())
            #aggregated_flows_export.main()

       # with open("aggregated_flows_export\\aggregated_flows_export.py", "r") as script:
           # exec(script)
            #exec_my_script()

            #aggregated_flows_export.main()
        #aggregated_flows_export()
