import logging
import urllib.parse

from datetime import datetime, timedelta
from typing import Generator, Dict, List, Set, Tuple, Any
from netaddr import IPSet, IPAddress, IPNetwork

from aggregated_flows_export.api.guardicore import RESTManagementAPI
from aggregated_flows_export.api.exceptions import CentraObjectNotFound
from aggregated_flows_export.common.policy.models import PolicyRule, RuleSide
from aggregated_flows_export.common.assets.utils import get_a_single_asset_from_centra, get_assets
from aggregated_flows_export.common.labels.models import ShortLabel, LabelsIntersection, LabelsExpression

API_OBJECTS_TO_GET_AT_ONCE = 1000
MAXIMUM_AMOUNT_OF_IP_ELEMENTS_PER_RULE_SIDE = 9000

logger = logging.getLogger("guardicore." + __name__)


class RulesSizeManager:
    """
    This class can be used to calculate an estimation of the size (= amount of ip elements) of policy rules in Centra.
    The rule's size can be used to validate that the amount of ip elements in a specific rule does not exceed the
    maximum allowed per rule.

    NOTE - Due to the complexity of the rules derivation process in Centra the sizes calculated by this class are
    mere approximations - the actual rule size seen by the agent may vary to both directions.
    """

    def __init__(self,
                 gc_api: RESTManagementAPI,
                 max_rule_side_size: int = MAXIMUM_AMOUNT_OF_IP_ELEMENTS_PER_RULE_SIDE):

        self.logger = logging.getLogger("guardicore." + __name__)
        self.gc_api = gc_api
        self.max_rule_side_size = max_rule_side_size

        self.asset_ips_cache: Dict[str, List[IPAddress]] = {}
        self.labels_criteria_cache: Dict[str, IPSet] = {}
        self.assets_matching_labels_cache: Dict[str, Set[str]] = {}
        self.labels_intersection_criteria_cache: Dict[str, IPSet] = {}
        self.assets_matching_labels_intersection_cache: Dict[str, Set[str]] = {
        }
        self.labels_expression_criteria_cache: Dict[str, IPSet] = {}
        self.assets_matching_labels_expression_cache: Dict[str, Set[str]] = {}

        self.assets_size_cache: Dict[str, int] = {}
        self.labels_size_cache: Dict[str, int] = {}
        self.labels_intersection_size_cache: Dict[str, int] = {}
        self.labels_expression_size_cache: Dict[str, int] = {}

        self.asset_id_to_asset_name_mapping: Dict[str, str] = {}
        self.asset_name_to_asset_id_mapping: Dict[str, str] = {}

    def get_asset_size_by_id(self, asset_id: str) -> int:
        """
        Return the size of the asset with the provided asset_id. The asset's size equals to the amount of ip's it has.
        If the assets was not inspected before, the asset's object will be requested from Centra and it's details will
        be cached.
        :raise CentraObjectNotFound: if no asset was found in Centra matching the provided asset_id
        """
        if asset_id in self.assets_size_cache:
            return self.assets_size_cache[asset_id]
        try:
            asset = get_a_single_asset_from_centra(self.gc_api, id=asset_id)
        except CentraObjectNotFound:
            raise CentraObjectNotFound(
                f"There is no asset with id {asset_id} in Centra")
        self.logger.debug(f"Fetched the asset with id {asset_id} from Centra")
        asset_id = asset['id']
        asset_name = asset['name']
        self.asset_id_to_asset_name_mapping[asset_id] = asset_name
        self.asset_name_to_asset_id_mapping[asset_name] = asset_id
        asset_ips = [IPAddress(ip) for ip in asset["ip_addresses"]]
        self.asset_ips_cache[asset_id] = asset_ips
        self.assets_size_cache[asset_id] = len(asset_ips)
        return self.assets_size_cache[asset_id]

    def get_asset_size_by_name(self, asset_name: str) -> int:
        """
        Return the size of the asset with the provided asset_name. The asset's size equals to the amount of ip's it has.
        If the assets was not inspected before, the asset's object will be requested from Centra and it's details will
        be cached.
        Note - In case there are multiple asset objects in Centra with the same name - there is no guarantee which of
        them will be inspected.
        :raise CentraObjectNotFound: if no asset was found in Centra matching the provided asset_name
        """
        asset_id = self.asset_name_to_asset_id_mapping.get(asset_name)
        if asset_id and asset_id in self.assets_size_cache:
            return self.assets_size_cache[asset_id]

        try:
            asset = get_a_single_asset_from_centra(
                self.gc_api, asset_name=asset_name)
        except CentraObjectNotFound:
            raise CentraObjectNotFound(
                f"There is no asset with name {asset_name} in Centra")
        self.logger.debug(
            f"Fetched the asset with name {asset_name} from Centra")
        asset_id = asset['id']
        self.asset_id_to_asset_name_mapping[asset_id] = asset_name
        self.asset_name_to_asset_id_mapping[asset_name] = asset_id
        asset_ips = [IPAddress(ip) for ip in asset["ip_addresses"]]
        self.asset_ips_cache[asset_id] = asset_ips
        self.assets_size_cache[asset_id] = len(asset_ips)
        return self.assets_size_cache[asset_id]

    def get_assets_matching_a_label(self, label_api_dict: Dict[str, Any], label: ShortLabel) -> Set[str]:
        """
        Identify and fetch data regarding each asset that matches the provided label, either statically (=explicitly)
        or dynamically. Each asset that matches the label will be inspected and cached.
        :param label_api_dict: The label object's dictionary, as returned from Centra API
        :param label: The label's ShortLabel object
        :return: a set of the asset ids that match the label, either dynamically or explicitly
        """
        asset_ids_that_were_added_to_the_label_explicitly = set([criterion["argument"] for criterion in
                                                                 label_api_dict['equal_criteria']])
        for asset_id in asset_ids_that_were_added_to_the_label_explicitly:
            if asset_id not in self.asset_ips_cache:
                _ = self.get_asset_size_by_id(asset_id)

        assets_that_match_the_label_dynamically = get_assets(self.gc_api,
                                                             labels=label_api_dict["id"])
        dynamically_matching_asset_ids = set()
        for asset in assets_that_match_the_label_dynamically:
            self.logger.debug(
                f"Fetched the asset with name {asset} from Centra")
            dynamically_matching_asset_ids.add(asset.id)
            self.asset_id_to_asset_name_mapping[asset.id] = asset.name
            self.asset_name_to_asset_id_mapping[asset.name] = asset.id
            asset_ips = [IPAddress(ip) for ip in asset.ip_addresses]
            self.asset_ips_cache[asset.id] = asset_ips
            self.assets_size_cache[asset.id] = len(asset_ips)

        assets_matching_label = asset_ids_that_were_added_to_the_label_explicitly | dynamically_matching_asset_ids
        self.assets_matching_labels_cache[label.name] = assets_matching_label

        return assets_matching_label

    def get_label_size(self, label: ShortLabel) -> int:
        """
        Return the size of the provided label. The label's size is calculated by summing the following:
            1. The amount of subnet's in it's dynamic criteria
            2. The amount of ips of all the assets that match the label, provided that those ips are not already
            contained in the label's dynamic criteria
        If the label was not inspected before, the label's object will be requested from Centra and it's details will
        be cached.
        """
        if label.name in self.labels_size_cache:
            return self.labels_size_cache[label.name]

        response = self.gc_api.list_visibility_labels(
            key=label.key, value=label.value)["objects"]
        if not response:
            raise CentraObjectNotFound(
                f"The label {label} was not found in Centra")

        self.logger.debug(f"Fetched the label {label} from Centra")
        label_dict = response[0]
        label.id = label_dict["id"]
        label_criteria = [IPNetwork(criterion["argument"]) for criterion in
                          label_dict["dynamic_criteria"] if criterion["op"] == "SUBNET"]
        label_criteria_ipset = IPSet(label_criteria)
        self.labels_criteria_cache[label.name] = label_criteria_ipset

        label_size = len(label_criteria)
        for asset_id in self.get_assets_matching_a_label(label_dict, label):
            if asset_id in self.asset_ips_cache:
                asset_ips = self.asset_ips_cache[asset_id]
            else:
                _ = self.get_asset_size_by_id(asset_id)
                asset_ips = self.asset_ips_cache[asset_id]
            asset_ips_that_are_not_in_the_labels_criteria = [
                ip for ip in asset_ips if ip not in label_criteria_ipset]
            label_size += len(asset_ips_that_are_not_in_the_labels_criteria)

        self.labels_size_cache[label.name] = label_size

        return label_size

    def get_labels_intersection_size(self, labels_intersection: LabelsIntersection) -> int:
        """
        Return the size of the provided labels intersection. The labels intersection's size is calculated by summing
        the following:
            1. The amount of cidrs in the intersection of the subnets in the dynamic criteria of all the intersection's
               labels
            2. The amount of ips of all the assets that match all the intersection labels, provided that those ips are
               not already contained in the cidrs calculated in (1)
        """
        if str(labels_intersection) in self.labels_intersection_size_cache:
            return self.labels_intersection_size_cache[str(labels_intersection)]

        for label in labels_intersection.labels:
            if label.name not in self.labels_size_cache:
                _ = self.get_label_size(label)

        if len(labels_intersection.labels) == 1:
            self.labels_intersection_criteria_cache[str(labels_intersection)] = \
                self.labels_criteria_cache[str(labels_intersection)]
            self.assets_matching_labels_intersection_cache[str(labels_intersection)] = \
                self.assets_matching_labels_cache[str(labels_intersection)]
            self.labels_intersection_size_cache[str(labels_intersection)] = \
                self.labels_size_cache[str(labels_intersection)]
            return self.labels_intersection_size_cache[str(labels_intersection)]

        first_label = labels_intersection.labels[0]
        labels_intersection_criteria = self.labels_criteria_cache[first_label.name]
        assets_matching_the_labels_intersection = self.assets_matching_labels_cache[
            first_label.name]
        for label in labels_intersection.labels[1:]:
            label_criteria = self.labels_criteria_cache[label.name]
            labels_intersection_criteria = labels_intersection_criteria & label_criteria
            assets_matching_the_label = self.assets_matching_labels_cache[label.name]
            assets_matching_the_labels_intersection = (assets_matching_the_labels_intersection &
                                                       assets_matching_the_label)

        self.labels_intersection_criteria_cache[str(
            labels_intersection)] = labels_intersection_criteria
        self.assets_matching_labels_intersection_cache[str(labels_intersection)] = \
            assets_matching_the_labels_intersection

        labels_intersection_size = len(
            labels_intersection_criteria.iter_cidrs())
        for asset_id in assets_matching_the_labels_intersection:
            if asset_id in self.asset_ips_cache:
                asset_ips = self.asset_ips_cache[asset_id]
            else:
                _ = self.get_asset_size_by_id(asset_id)
                asset_ips = self.asset_ips_cache[asset_id]
            asset_ips_that_are_not_in_the_labels_intersection_criteria = [ip for ip in asset_ips if
                                                                          ip not in labels_intersection_criteria]
            labels_intersection_size += len(
                asset_ips_that_are_not_in_the_labels_intersection_criteria)

        self.labels_intersection_size_cache[str(
            labels_intersection)] = labels_intersection_size

        return labels_intersection_size

    def get_labels_expression_size(self, labels_expression: LabelsExpression):
        """
        Return the size of the provided labels expression. The labels expression's size is calculated by summing
        the following:
            1. The amount of cidrs in the union of the subnets in the dynamic criteria of all the labels expression's
               label members (labels and labels intersections)
            2. The amount of ips of all the assets that match at least one of the expression's members (labels and
               labels intersection), provided that those ips are not already contained in the cidrs calculated in (1)
        """
        if str(labels_expression) in self.labels_expression_size_cache:
            return self.labels_expression_size_cache[str(labels_expression)]

        for labels_intersection in labels_expression.labels_intersections:
            if str(labels_intersection) not in self.labels_intersection_size_cache:
                _ = self.get_labels_intersection_size(labels_intersection)

        if len(labels_expression.labels_intersections) == 1:
            self.labels_expression_criteria_cache[str(labels_expression)] = \
                self.labels_intersection_criteria_cache[str(labels_expression)]
            self.assets_matching_labels_expression_cache[str(labels_expression)] = \
                self.assets_matching_labels_intersection_cache[str(
                    labels_expression)]
            self.labels_expression_size_cache[str(labels_expression)] = \
                self.labels_intersection_size_cache[str(labels_expression)]
            return self.labels_expression_size_cache[str(labels_expression)]

        labels_expression_criteria = IPSet()
        assets_matching_the_labels_expression = set()
        for labels_intersection in labels_expression.labels_intersections:
            labels_intersection_criteria = self.labels_intersection_criteria_cache[str(
                labels_intersection)]
            labels_expression_criteria = labels_expression_criteria | labels_intersection_criteria
            assets_matching_the_labels_intersection = \
                self.assets_matching_labels_intersection_cache[str(
                    labels_intersection)]
            assets_matching_the_labels_expression = (assets_matching_the_labels_expression |
                                                     assets_matching_the_labels_intersection)

        self.assets_matching_labels_expression_cache[str(
            labels_expression)] = assets_matching_the_labels_expression
        self.labels_expression_criteria_cache[str(
            labels_expression)] = labels_expression_criteria

        labels_expression_size = len(labels_expression_criteria.iter_cidrs())
        for asset_id in assets_matching_the_labels_expression:
            if asset_id in self.asset_ips_cache:
                asset_ips = self.asset_ips_cache[asset_id]
            else:
                _ = self.get_asset_size_by_id(asset_id)
                asset_ips = self.asset_ips_cache[asset_id]
            asset_ips_that_are_not_in_the_labels_expression_criteria = [ip for ip in asset_ips if
                                                                        ip not in labels_expression_criteria]
            labels_expression_size += len(
                asset_ips_that_are_not_in_the_labels_expression_criteria)

        self.labels_expression_size_cache[str(
            labels_expression)] = labels_expression_size

        return labels_expression_size

    def get_rule_side_size(self, rule_side: RuleSide) -> int:
        """
        Calculate and return the size of a single rule side (=Source or Destination).

        :raises NotImplementedError: If the rule side contains combination of labels and subnets, assets and subnets
        or label groups.
        """
        if rule_side.labels:
            if rule_side.subnets:
                raise NotImplementedError("Calculating the size of an intersections between subnets and labels is not"
                                          " implemented")
            else:
                return self.get_labels_expression_size(rule_side.labels)
        elif rule_side.assets:
            if rule_side.subnets:
                raise NotImplementedError("Calculating the size of an intersections between subnets and assets is not"
                                          " implemented")
            else:
                return sum([self.get_asset_size_by_name(asset.name) for asset in rule_side.assets])
        elif rule_side.subnets:
            return len(rule_side.subnets)
        elif rule_side.label_groups:
            raise NotImplementedError(
                "Calculating the size of a label group is not implemented")
        else:
            return 0

    def get_rule_size(self, rule: PolicyRule) -> Tuple[int, int]:
        """ Calculate the size (= amount of ip elements) in a single policy rule """
        return self.get_rule_side_size(rule.source), self.get_rule_side_size(rule.destination)


def get_latest_policy_revision(gc_api: RESTManagementAPI) -> int:
    """Return the latest policy revision in Centra"""
    to_time = datetime.now()
    # Assuming there were policy published in the last 3 year
    from_time = to_time - timedelta(days=1080)
    return gc_api.get_policy_revisions(from_time, to_time)[0]["revision_number"]


def get_policy_rules(gc_api: RESTManagementAPI,
                     objects_to_get_at_once: int = API_OBJECTS_TO_GET_AT_ONCE,
                     **filters) -> Generator[PolicyRule, None, None]:
    """
    Query Centra API for all the rule matching the provided filters, and yield them one by one. If no filters was
    provided, all the rules will be fetched.
    :param gc_api: RESTManagementAPI object
    :param objects_to_get_at_once: The amount of rule objects to request in a single API call
    :param filters: Only fetch rules matching the filters. The supported filters are similar to the filters in the
    rules page in Centra UI
    :return: A generator, yielding PolicyRule objects
    """
    offset = 0
    logger.debug(
        f"Requesting a chunk of {objects_to_get_at_once} rules from Centra")
    response = gc_api.get_segmentation_rules(limit=objects_to_get_at_once,
                                             **filters)
    while len(response["objects"]) > 0:
        for rule_dict in response["objects"]:
            yield PolicyRule.from_api_dict(rule_dict)
        if len(response["objects"]) == objects_to_get_at_once:
            offset += objects_to_get_at_once
            logger.debug(
                f"Requesting {objects_to_get_at_once} rules from Centra, with offset {offset}")
            response = gc_api.get_segmentation_rules(limit=objects_to_get_at_once,
                                                     offset=offset,
                                                     **filters)
        else:
            break


def get_policy_rules_screen_url(management_address: str, port: int = 443, **filt) -> str:
    """ Return a url for a (optionally filtered) view of the policy rules page in Centra """
    url = f"https://{management_address}:{port}/overview/segmentation/segmentation-policy"
    if filt:
        url += '?' + urllib.parse.urlencode(filt, quote_via=urllib.parse.quote)
    return url
