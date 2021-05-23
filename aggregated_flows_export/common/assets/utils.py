import logging

from typing import Generator, Optional, Dict, Any

from aggregated_flows_export.api.guardicore import RESTManagementAPI
from aggregated_flows_export.api.exceptions import CentraObjectNotFound
from aggregated_flows_export.common.assets.models import Asset

API_OBJECTS_TO_GET_AT_ONCE = 1000

logger = logging.getLogger("guardicore." + __name__)


def get_a_single_asset_from_centra(gc_api: RESTManagementAPI,
                                   asset_name: str = '',
                                   **filters) -> Optional[Dict[str, Any]]:
    """
    Get a single asset matching the provided filter from Centra API Centra. If asset_name was provided as an argument,
    only an asset whose name is identical to the asset_name will be returned.
    The filters supported are the same filters available in Centra's assets page, and also 'id' which does not appear
    in the assets page.
    :raises CentraObjectNotFound: If no asset was found in Centra matching the provided filter
    :return: The first asset matching the filter
    """
    response = gc_api.list_assets(**filters)
    if asset_name:
        for asset in response:
            if asset["name"] == asset_name:
                return asset
            else:
                raise CentraObjectNotFound(
                    f"An asset named {asset_name} was not found in Centra")
    else:
        if response:
            return response[0]
        else:
            raise CentraObjectNotFound(
                f"No asset matching the provided filter was found in Centra")


def get_assets(gc_api: RESTManagementAPI,
               objects_to_get_at_once: int = API_OBJECTS_TO_GET_AT_ONCE,
               **filters) -> Generator[Asset, None, None]:
    """
    Query Centra API for all the assets matching the provided filters, and yield them one by one. If no filters was
    provided, all the assets will be fetched.
    :param gc_api: RESTManagementAPI object
    :param objects_to_get_at_once: The amount of asset objects to request in a single API call
    :param filters: Only fetch assets matching the filters. The supported filters are similar to the filters in the
    assets page in Centra UI
    :return: A generator, yielding Asset objects
    """
    offset = 0
    logger.debug(
        f"Requesting a chunk of {objects_to_get_at_once} assets from Centra")
    response = gc_api.list_assets(limit=objects_to_get_at_once,
                                  **filters)
    while len(response) > 0:
        for asset_dict in response:
            yield Asset.from_api_dict(asset_dict)
        if len(response) == objects_to_get_at_once:
            offset += objects_to_get_at_once
            logger.debug(
                f"Requesting {objects_to_get_at_once} assets from Centra, with offset {offset}")
            response = gc_api.list_assets(limit=objects_to_get_at_once,
                                          offset=offset,
                                          **filters)
        else:
            break
