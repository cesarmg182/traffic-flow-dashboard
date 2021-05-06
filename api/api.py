from typing import List


def fetch_available_maps() -> List[str]:
    # TODO: Implement API fetch.
    return [f"map{i}" for i in range(10)]
