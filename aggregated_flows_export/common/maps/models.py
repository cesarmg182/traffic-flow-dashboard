from dataclasses import dataclass
from typing import Dict, Union, Set, Any
from enum import Enum
from netaddr import IPNetwork

from aggregated_flows_export.api.guardicore import RESTManagementAPI
from aggregated_flows_export.common.policy.models import PortRange
from aggregated_flows_export.common.labels.models import LabelsExpression, ShortLabelGroup


@dataclass
class MapFilter:
    """ Representation of a Reveal map of graph filter """
    connection_types: Set['ConnectionType'] = None
    subnets: Set[IPNetwork] = None
    policy_actions: Set['PolicyAction'] = None
    ports: Set[Union[int, PortRange]] = None
    policy_rulesets: Set[str] = None
    processes: Set[str] = None
    protocols: Set['Protocol'] = None
    assets: Set[str] = None
    policy_rules: Set[str] = None
    label_groups: Set[ShortLabelGroup] = None
    address_classifications: Set['AddressClassification'] = None
    connections_from_subnets: Set[IPNetwork] = None
    connections_to_subnets: Set[IPNetwork] = None
    labels: LabelsExpression = None
    connections_from_labels: LabelsExpression = None
    connections_to_labels: LabelsExpression = None

    class ConnectionType(Enum):
        BLOCKED = "Blocked"
        REDIRECTED_TO_DECEPTION = "Redirected to Deception"
        ESTABLISHED = "Established"
        FAILED = "Failed"
        VIOLATED_SEGMENTATION_POLICY = "Violated Segmentation Policy"
        ASSOCIATED_WITH_INCIDENT = "associated with incident"

    class PolicyAction(Enum):
        ALLOWED_BY_POLICY = "Allowed By Policy"
        ALERTED_BY_POLICY = "Alerted By Policy"
        BLOCKED_BY_POLICY = "Blocked By Policy"
        NO_MATCHING_POLICY = "No Matching Policy"

    class Protocol(Enum):
        TCP = 'TCP'
        UDP = 'UDP'
        ICMP = 'ICMP'

    class AddressClassification(Enum):
        FROM_INTERNET = "From Internet"
        TO_INTERNET = "To Internet"

    @property
    def is_any(self) -> bool:
        return (not self.connection_types and
                not self.subnets and
                not self.policy_actions and
                not self.ports and
                not self.policy_rulesets and
                not self.processes and
                not self.protocols and
                not self.assets and
                not self.policy_rules and
                not self.label_groups and
                not self.connections_from_subnets and
                not self.connections_to_subnets and
                not self.labels and
                not self.connections_from_labels and
                not self.connections_to_labels)

    def to_api_format(self, gc_api: 'RESTManagementAPI' = None) -> Dict[str, Any]:
        """
        Returns a dict representation of the MapFilter in the format used in the include / exclude filters of Centra
        API map, graph and permalink requests. If the filter contain labels, in order to construct the output dict all
        their ids needs to be known. This can be achieved by manually setting the id of each ShortLabel which is a
        member of the filer, of by providing a RESTManagementAPI object which will be used to query Centra for the id.
        :raise AssertionError: If label filters are configured, the id of one of a member ShortLabels is not set and
        gc_api was not provided
        :raise LabelNotFoundInCentra: If a label matching the key and value of a ShortLabel was not found in Centra
        """
        filter_dict = {}
        if self.connection_types:
            filter_dict["connection_types"] = [
                connection_type.value for connection_type in self.connection_types]
        if self.subnets:
            filter_dict["ip_address"] = {
                "ip": [str(subnet) for subnet in self.subnets]}
        if self.policy_actions:
            filter_dict["policy"] = [
                policy_action.value for policy_action in self.policy_actions]
        if self.ports:
            filter_dict["ports"] = [str(port_or_port_range)
                                    for port_or_port_range in self.ports]
        if self.policy_rulesets:
            filter_dict["policy_rulesets"] = list(self.policy_rulesets)
        if self.processes:
            filter_dict["process_filter"] = list(self.processes)
        if self.protocols:
            filter_dict["protocols"] = [
                protocol.value for protocol in self.protocols]
        if self.assets:
            filter_dict["vm"] = list(self.assets)
        if self.policy_rules:
            filter_dict["policy_rule"] = {
                "policy_rule": list(self.policy_rules)}
        if self.connections_from_subnets:
            filter_dict["source_ip_address"] = {
                "ip": [str(subnet) for subnet in self.connections_from_subnets]}
        if self.connections_to_subnets:
            filter_dict["destination_ip_address"] = {
                "ip": [str(subnet) for subnet in self.connections_to_subnets]}
        if self.address_classifications:
            filter_dict["internet_flow"] = [
                classification.value for classification in self.address_classifications]
        if self.labels:
            filter_dict["user_label"] = self.labels.to_map_filter(gc_api)
        if self.connections_from_labels:
            filter_dict["source_label"] = self.connections_from_labels.to_map_filter(
                gc_api)
        if self.connections_to_labels:
            filter_dict["destination_label"] = self.connections_to_labels.to_map_filter(
                gc_api)
        if self.label_groups:
            filter_dict["label_groups"] = [
                str(label_group) for label_group in self.label_groups]

        return filter_dict
