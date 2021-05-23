from dataclasses import dataclass
from datetime import datetime


@dataclass
class MapValues:
    start_date: datetime
    end_date: datetime
    selected_map: str
    start_time: datetime
    end_time: datetime
    include_label: str
    exclude_label_group: str
    ignore_internal_traffic: bool
    output_flows_count: bool
    expand_internet: bool
    expand_subnets: bool
    delete_temp_map: bool

def generate_map_values(data: MapValues) -> str:
    with open("templates/map_template.yaml", "r") as tpl:
        t_doc = tpl.read()

        t_doc = t_doc.replace("$START_DATE", str(data.start_date)+" "+str(data.start_time))
        t_doc = t_doc.replace("$END_DATE", str(data.end_date)+" "+str(data.end_time))
        t_doc = t_doc.replace("$SELECTED_MAP", data.selected_map)
        t_doc = t_doc.replace("$INCLUDE_LABEL","- '"+data.include_label+"'")
        t_doc = t_doc.replace("$EXCLUDE_LABEL_GROUP","- '"+data.exclude_label_group+"'")

        iit = "True" if data.ignore_internal_traffic else "False"
        t_doc = t_doc.replace("$IGNORE_INTERNAL_TRAFFIC", iit)
        iit = "True" if data.delete_temp_map else "False"
        t_doc = t_doc.replace("$DELETE_TEMP_MAP", iit)
        iit = "True" if data.expand_subnets else "False"
        t_doc = t_doc.replace("$EXPAND_SUBNETS", iit)
        iit = "True" if data.expand_internet else "False"
        t_doc = t_doc.replace("$EXPAND_INTERNET", iit)
        iit = "True" if data.output_flows_count else "False"
        t_doc = t_doc.replace("$OUTPUT_FLOWS_COUNT", iit)

        return t_doc
