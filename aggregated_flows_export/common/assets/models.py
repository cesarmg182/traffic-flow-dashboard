from dataclasses import dataclass
from typing import Dict, Any, Tuple
from enum import Enum

from aggregated_flows_export.api.guardicore import RESTManagementAPI
from aggregated_flows_export.api.exceptions import CentraObjectNotFound


@dataclass()
class Asset:
    """ A representation of a single Centra Asset """
    class Status(Enum):
        ON = 'on'
        OFF = 'off'
        DELETED = 'deleted'

    name: str
    id: str = None
    ip_addresses: Tuple[str, ...] = None
    status: Status = None

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash((self.name, self.id))

    @classmethod
    def from_api_dict(cls, asset_dict: Dict[str, Any]) -> 'Asset':
        """
        Generate an Asset object that represents an asset in Centra from an asset object dictionary returned from
        Centra API.
        """
        name = asset_dict["name"]
        asset_id = asset_dict["id"]
        status = Asset.Status(asset_dict['status'])
        ip_addresses = tuple(asset_dict["ip_addresses"])

        return cls(name=name,
                   id=asset_id,
                   status=status,
                   ip_addresses=ip_addresses)

    def get_or_query_asset_id(self, gc_api: RESTManagementAPI = None):
        """
        Return the asset's id. If self.id is not already set, query Centra to get the id of an asset with a name
        matching the Asset object's name.
        ** NOTE ** - Since asset names are not unique in Centra, querying Centra for an asset id using an asset name
        will yield the id of a single asset matching the name - there is no way to guarantee which asset id will be
        returned.
        :param gc_api: A RESTManagementAPI object, used to query Centra API to get the asset's id if its not already set
        :raise AssertionError: If self.id is not set and gc_api was not provided
        :raise CentraObjectNotFound: If an asset named self.name was not found in Centra
        """
        if self.id:
            return self.id

        assert gc_api, "RESTManagementAPI object must be provided to query Centra for asset ids"

        response = gc_api.list_assets(search=self.name)
        for asset in response:
            if asset["name"] == self.name:
                self.id = asset["id"]
                return self.id

        raise CentraObjectNotFound(f"Could not get the asset id because an asset named {self.name} was not found in "
                                   f"Centra")
