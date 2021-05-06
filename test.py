from templates import generate_map_values, MapValues
from datetime import datetime

generated_yaml = generate_map_values(MapValues(
    start_date=datetime.now(),
    end_date=datetime.now(),
    selected_map="map0",
    ignore_internal_traffic=True
))

print(generated_yaml)