import streamlit as st
from datetime import datetime
from typing import List
from api import fetch_available_maps
from templates import generate_map_values, MapValues
# from xyz import exec_my_script


available_map_values: List[str] = fetch_available_maps()

with st.form(key='my_form'):
    st.write("Map Generator")

    start_date = st.date_input("Start Date", datetime.now())
    end_date = st.date_input("End Date", datetime.now())

    selected_map = st.selectbox('Select your map', available_map_values)

    ignore_internal_traffic = st.checkbox('Ignore Internal traffic')

    submitted = st.form_submit_button(label='Generate')

    if submitted:
        generated_yaml = generate_map_values(MapValues(
            start_date=start_date,
            end_date=end_date,
            selected_map=selected_map,
            ignore_internal_traffic=ignore_internal_traffic
        ))

        # st.write(f"```yaml\n{generated_yaml}\n```")

        with open("generated_yaml.yaml", "w") as file:
            file.write(generated_yaml)

        # with open("xyz.py", "r") as script:
        #     exec(script)

        # exec_my_script()
