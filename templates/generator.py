from dataclasses import dataclass
from datetime import datetime


@dataclass
class MapValues:
    start_date: datetime
    end_date: datetime
    selected_map: str
    ignore_internal_traffic: bool


def generate_map_values(data: MapValues) -> str:
    with open("templates/map_template.yaml", "r") as tpl:
        t_doc = tpl.read()

        t_doc = t_doc.replace("$START_DATE", str(data.start_date))
        t_doc = t_doc.replace("$END_DATE", str(data.end_date))
        t_doc = t_doc.replace("$SELECTED_MAP", data.selected_map)

        iit = "true" if data.ignore_internal_traffic else "false"
        t_doc = t_doc.replace("$IGNORE_INTERNAL_TRAFFIC", iit)

        return t_doc
