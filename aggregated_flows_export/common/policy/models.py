from enum import Enum
from dataclasses import dataclass
from typing import Set, Dict, Any, Tuple, Union
from netaddr import IPNetwork

from aggregated_flows_export.api.guardicore import RESTManagementAPI
from aggregated_flows_export.common.labels.models import LabelsExpression, ShortLabelGroup, ShortLabel, LabelsIntersection
from aggregated_flows_export.common.assets.models import Asset


@dataclass(order=True, frozen=True)
class PortRange:
    """ Representation or a port range, i.e. ports 400-600 """
    start: int
    end: int

    def __post_init__(self):
        """
        Raise ValueError if the the start or end ports are not a legal port numbers, or if the start port is
        larger then the end port
        """
        if not 1 <= self.start <= self.end <= 65535:
            raise ValueError(f"{self} is not a legal port range")

    def __str__(self):
        return f"{self.start}-{self.end}"

    def to_dict(self) -> Dict[str, int]:
        return {
            "start": self.start,
            "end": self.end
        }

    @classmethod
    def from_dict(cls, port_range_dict: Dict[str, int]) -> 'PortRange':
        return cls(start=port_range_dict["start"],
                   end=port_range_dict["end"])


@dataclass
class PortsExpression:
    """
    Representation or a port expression used in Centra policy rule.
    Potentially containing:
        include ports: A network flow will match the rule if it's dest port is one of the include ports, unless the port
            also appears in the excluded ports / port ranges
        include port ranges: A network flow will match the rule if it's dest port is within one of the include port
            ranges, unless the port also appears in the excluded ports / port ranges
        exclude ports: A network flow will not match the rule if it's dest port is one of the exclude ports
        exclude port ranges: A network flow will not match the rule if it's dest port is within one of the exclude port
            ranges
    """
    include_ports: Set[int] = None
    include_port_ranges: Set[PortRange] = None
    exclude_ports: Set[int] = None
    exclude_port_ranges: Set[PortRange] = None

    def __init__(self,
                 include_ports: Set[int] = None,
                 include_port_ranges: Set[PortRange] = None,
                 exclude_ports: Set[int] = None,
                 exclude_port_ranges: Set[PortRange] = None):
        self.include_ports = include_ports if include_ports else set()
        self.include_port_ranges = include_port_ranges if include_port_ranges else set()
        self.exclude_ports = exclude_ports if exclude_ports else set()
        self.exclude_port_ranges = exclude_port_ranges if exclude_port_ranges else set()

    @property
    def is_any(self) -> bool:
        """ Return whether ANY port will match the expression """
        return (not self.include_ports and
                not self.include_port_ranges and
                not self.exclude_ports and
                not self.exclude_port_ranges)

    def __add__(self, other: 'PortsExpression'):
        if isinstance(other, PortsExpression):
            return PortsExpression(
                include_ports=self.include_ports | other.include_ports,
                include_port_ranges=self.include_port_ranges | other.include_port_ranges,
                exclude_ports=self.exclude_ports | other.exclude_ports,
                exclude_port_ranges=self.exclude_port_ranges | other.exclude_port_ranges
            )
        else:
            raise TypeError()

    def __ge__(self, other: 'PortsExpression'):
        """ Return true if the other PortsExpression is a subset of self, otherwise return False """
        if isinstance(other, PortsExpression):
            if self.is_any:
                return True
            elif other.is_any:
                return False
            else:
                return (
                    self.include_ports >= other.include_ports and
                    self.include_port_ranges >= other.include_port_ranges and
                    self.exclude_ports >= other.exclude_ports and
                    self.exclude_port_ranges >= other.exclude_port_ranges
                )
        else:
            raise TypeError()

    def __le__(self, other: 'PortsExpression'):
        """ Return true if the self is a subset of the other PortsExpression, otherwise return False """
        if isinstance(other, PortsExpression):
            if other.is_any:
                return True
            elif self.is_any:
                return False
            else:
                return (
                    self.include_ports <= other.include_ports and
                    self.include_port_ranges <= other.include_port_ranges and
                    self.exclude_ports <= other.exclude_ports and
                    self.exclude_port_ranges <= other.exclude_port_ranges
                )
        else:
            raise TypeError()

    def __contains__(self, other: 'PortsExpression'):
        """ Return true if the other PortsExpression is a subset of self, otherwise return False """
        return self.__ge__(other)

    def __str__(self):
        if self.is_any:
            return "ANY"
        expression_str = ', '.join(sorted(
            [str(port) for port in self.include_ports])) if self.include_ports else ''
        if self.include_port_ranges:
            if expression_str:
                expression_str += ', ' + \
                    ', '.join(sorted([str(pr)
                                      for pr in self.include_port_ranges]))
        if self.exclude_ports or self.exclude_port_ranges:
            expression_str = expression_str + \
                ', excluding: ' if expression_str else 'excluding: '
        if self.exclude_ports:
            expression_str += ', '.join(sorted([str(port)
                                                for port in self.exclude_ports]))
        if self.include_port_ranges:
            if self.exclude_ports:
                expression_str += ', '
            expression_str += ', '.join(sorted([str(pr)
                                                for pr in self.include_port_ranges]))
        return expression_str

    def to_csv_dict(self) -> Dict[str, str]:
        dest_ports = ""
        if self.include_ports:
            dest_ports += f"{', '.join(sorted([str(port) for port in self.include_ports]))}"
        if self.include_port_ranges:
            dest_ports += f"{', ' if self.include_ports else ''}"
            dest_ports += f"{', '.join(sorted([str(port_range) for port_range in self.include_port_ranges]))}"

        exclude_dest_ports = ""
        if self.exclude_ports:
            exclude_dest_ports += f"{', '.join(sorted([str(port) for port in self.exclude_ports]))}"
        if self.include_port_ranges:
            exclude_dest_ports += f"{', ' if self.exclude_ports else ''}"
            exclude_dest_ports += f"{', '.join(sorted([str(port_range) for port_range in self.exclude_port_ranges]))}"

        return {
            'dest_ports': dest_ports,
            'excluded_dest_ports': exclude_dest_ports
        }

    @classmethod
    def from_rule_api_dict(cls, rule_dict: Dict[str, Any]) -> 'PortsExpression':
        """
        Generate a PortsExpression object that represents the included and excluded ports of a rule dictionary
        returned from Centra API
        """
        include_ports = {int(port) for port in rule_dict["ports"]}
        include_port_ranges = {PortRange(int(pr["start"]), int(
            pr["end"])) for pr in rule_dict["port_ranges"]}
        exclude_ports = {int(port) for port in rule_dict["exclude_ports"]}
        exclude_port_ranges = {PortRange(int(pr["start"]), int(
            pr["end"])) for pr in rule_dict["exclude_port_ranges"]}

        return cls(include_ports, include_port_ranges, exclude_ports, exclude_port_ranges)


@dataclass
class UserGroup:
    id: str
    name: str

    def __str__(self):
        return self.name

    @classmethod
    def from_api_dict(cls, user_group_dict: Dict[str, Any]) -> 'UserGroup':
        """
        Generate a UserGroup object that represents a Centra user group from a user group dictionary returned from
        Centra API
        """
        return cls(
            id=user_group_dict["id"],
            name=user_group_dict["name"]
        )


@dataclass
class RuleSide:
    """ Representation of a policy rules side - the source / destination entities of the rule """
    labels: Union[LabelsExpression, LabelsIntersection, ShortLabel] = None
    subnets: Set[IPNetwork] = None
    assets: Set[Asset] = None
    processes: Set[str] = None
    label_group: ShortLabelGroup = None
    domains: Set[str] = None
    user_groups: Set[UserGroup] = None
    address_classification: 'AddressClassification' = None

    class AddressClassification(Enum):
        INTERNAL = "private"
        INTERNET = 'internet'

    def __post_init__(self):
        """ If self.labels is a ShortLabel or LabelsExpression, convert it to a LabelsExpression """
        if isinstance(self.labels, ShortLabel):
            self.labels = LabelsExpression(
                {LabelsIntersection((self.labels,))})
        if isinstance(self.labels, LabelsIntersection):
            self.labels = LabelsExpression({self.labels})

    def __str__(self):
        if self.is_any:
            return "ANY"
        elif self.labels:
            rule_side_str = f"labels: {str(self.labels)}"
            if self.subnets:
                rule_side_str += f', subnets: {",".join(sorted([str(subnet) for subnet in self.subnets]))}'
            if self.user_groups:
                rule_side_str += f', user groups: {", ".join(sorted([str(ug) for ug in self.user_groups]))}'
            if self.processes:
                rule_side_str += f', processes: {", ".join(sorted([process for process in self.processes]))}'
        elif self.assets:
            rule_side_str = f"assets: {','.join(sorted([str(asset) for asset in self.assets]))}"
            if self.subnets:
                rule_side_str += f', subnets: {",".join(sorted([str(subnet) for subnet in self.subnets]))}'
            if self.user_groups:
                rule_side_str += f', user groups: {", ".join(sorted([str(ug) for ug in self.user_groups]))}'
            if self.processes:
                rule_side_str += f', processes: {", ".join(sorted([process for process in self.processes]))}'
        elif self.label_group:
            rule_side_str = f"label group: {str(self.label_group)}"
            if self.subnets:
                rule_side_str += f', subnets: {",".join(sorted([str(subnet) for subnet in self.subnets]))}'
            if self.user_groups:
                rule_side_str += f', user groups: {", ".join(sorted([str(ug) for ug in self.user_groups]))}'
            if self.processes:
                rule_side_str += f', processes: {", ".join(sorted([process for process in self.processes]))}'
        elif self.domains:
            rule_side_str = f"domains: {','.join(sorted([str(domain) for domain in self.domains]))}"
            if self.subnets:
                rule_side_str += f', subnets: {",".join(sorted([str(subnet) for subnet in self.subnets]))}'
            if self.processes:
                rule_side_str += f', processes: {", ".join(sorted([process for process in self.processes]))}'
        elif self.subnets:
            rule_side_str = f'subnets: {",".join(sorted([str(subnet) for subnet in self.subnets]))}'
            if self.user_groups:
                rule_side_str += f', user groups: {", ".join(sorted([str(ug) for ug in self.user_groups]))}'
            if self.processes:
                rule_side_str += f', processes: {", ".join(sorted([process for process in self.processes]))}'
        elif self.processes:
            rule_side_str = f'processes: {", ".join(sorted([process for process in self.processes]))}'
        elif self.address_classification:
            rule_side_str = f"address classifications: {self.address_classification.value}"

        return rule_side_str

    @property
    def is_any(self) -> bool:
        """ Return whether the source or destination is ANY """
        return (not self.labels and
                not self.subnets and
                not self.assets and
                not self.processes and
                not self.label_group and
                not self.domains and
                not self.user_groups and
                not self.address_classification)

    def to_csv_dict(self) -> Dict[str, str]:
        """ Return a representation of the RuleSide suitable for saving the rule as a line in a CSV """
        return {
            "labels": str(self.labels) if self.labels else '',
            "subnets": ', '.join([str(subnet) for subnet in self.subnets]) if self.subnets else '',
            "assets": ', '.join([str(asset) for asset in self.assets]) if self.assets else '',
            "processes": ', '.join(self.processes) if self.processes else '',
            "label_groups": str(self.label_group) if self.label_group else '',
            "domains": ', '.join(self.domains) if self.domains else '',
            "user_groups": ', '.join([str(ug) for ug in self.user_groups]) if self.user_groups else '',
            "address_classification": self.address_classification.value if self.address_classification else ''
        }

    def to_api_dict(self, gc_api: RESTManagementAPI = None) -> Dict:
        """
        Return a representation of the RuleSide in the format suitable for use in the source / destination value of
        policy rules in Centra API. This operation requires knowing the ids of the all the RuleSide's child members
        (labels, assets, etc). In case the ids are not already set, providing a centra API connection is required to
        get query Centra to get them.
        :param gc_api: Optional - a RESTManagementAPI object, used to query Centra API to get ids of the rule member
        objects if those are not already set
        :raise AssertionError: will be raised if the id of one of the rule's member objects is unknown and gc_api was
        not provided
        :raise CentraObjectNotFound: will be raised if during the search for the id of a member object in Centra,
        an object matching the search criteria was not found
        """
        api_dict = {}
        if self.labels:
            api_dict["labels"] = self.labels.to_rule_format(gc_api)
        if self.subnets:
            api_dict["subnets"] = [str(subnet) for subnet in self.subnets]
        if self.assets:
            api_dict["asset_ids"] = [asset.get_or_query_asset_id(
                gc_api) for asset in self.assets]
        if self.processes:
            api_dict["processes"] = list(self.processes)
        if self.address_classification:
            api_dict["address_classification"] = self.address_classification.value.capitalize()
        if self.label_group:
            api_dict["label_group_ids"] = [
                self.label_group.get_or_query_label_group_id(gc_api)]
        if self.domains:
            api_dict["domains"] = list(self.domains)
        if self.user_groups:
            # todo implement me
            raise NotImplemented(
                "User groups are not implemented. Talk with Solution Center for more info")
        return api_dict

    @classmethod
    def from_rule_api_dict(cls, rule_dict: Dict[str, Any]) -> Tuple['RuleSide', 'RuleSide']:
        """
        Generate two RuleSide objects that represents the source or destination of a rule dictionary returned
        from Centra API.
        :return: A tuple with two 'RuleSide' objects representing the rule's source destination respectively
        """
        if rule_dict["source"].get("labels"):
            source_labels = LabelsExpression.from_rule_labels_dict(
                rule_dict["source"]["labels"])
        else:
            source_labels = None
        source_subnets = {IPNetwork(item['subnet'])
                          for item in rule_dict["source"].get("subnets", [])}
        source_assets = {Asset.from_api_dict(
            asset_dict) for asset_dict in rule_dict["source"].get("assets", [])}
        source_processes = {
            process for process in rule_dict["source"].get("processes", [])}
        if rule_dict["source"].get("address_classification"):
            source_address_classification = RuleSide.AddressClassification(rule_dict["source"]
                                                                           ["address_classification"].lower())
        else:
            source_address_classification = None
        if rule_dict["source"].get("label_groups"):
            source_label_group = ShortLabelGroup.from_api_dict(
                rule_dict["source"]["label_groups"][0])
        else:
            source_label_group = None
        source_user_groups = {UserGroup.from_api_dict(ug_dict) for ug_dict
                              in rule_dict["source"].get("user_groups", [])}

        source = cls(
            labels=source_labels,
            subnets=source_subnets if source_subnets else None,
            assets=source_assets if source_assets else None,
            processes=source_processes if source_processes else None,
            address_classification=source_address_classification,
            label_group=source_label_group if source_label_group else None,
            user_groups=source_user_groups if source_user_groups else None
        )

        if rule_dict["destination"].get("labels"):
            destination_labels = LabelsExpression.from_rule_labels_dict(
                rule_dict["destination"]["labels"])
        else:
            destination_labels = None
        destination_subnets = {IPNetwork(
            item['subnet']) for item in rule_dict["destination"].get("subnets", [])}
        destination_assets = {Asset.from_api_dict(asset_dict) for asset_dict in
                              rule_dict["destination"].get("assets", [])}
        destination_processes = {
            process for process in rule_dict["destination"].get("processes", [])}
        if rule_dict["destination"].get("address_classification"):
            destination_address_classification = RuleSide.AddressClassification(
                rule_dict["destination"]["address_classification"].lower())
        else:
            destination_address_classification = None
        if rule_dict["destination"].get("label_groups"):
            destination_label_group = ShortLabelGroup.from_api_dict(
                rule_dict["destination"]["label_groups"][0])
        else:
            destination_label_group = None
        destination_domains = {
            domain for domain in rule_dict["destination"].get("domains", [])}

        destination = cls(
            labels=destination_labels,
            subnets=destination_subnets if destination_subnets else None,
            assets=destination_assets if destination_assets else None,
            processes=destination_processes if destination_processes else None,
            address_classification=destination_address_classification,
            label_group=destination_label_group if destination_label_group else None,
            domains=destination_domains if destination_domains else None
        )

        return source, destination


@dataclass
class PolicyRule:
    """ Representation of a Centra policy rule """

    section: 'PolicyRule.Section'
    action: 'PolicyRule.Action'
    source: RuleSide
    destination: RuleSide
    dest_ports: PortsExpression
    protocols: Set['PolicyRule.Protocol']
    id: str = ""
    ruleset: str = ""
    author: str = ""
    enabled: bool = True
    comments: str = ""

    class Section(Enum):
        ALLOW = 'allow'
        ALERT = 'alert'
        BLOCK = 'block'
        OVERRIDE_ALLOW = 'override_allow'
        OVERRIDE_ALERT = 'override_alert'
        OVERRIDE_BLOCK = 'override_block'

    class Action(Enum):
        ALLOW = 'allow'
        ALERT = 'alert'
        BLOCK = 'block'
        BLOCK_AND_ALERT = 'block_and_alert'

    class Protocol(Enum):
        TCP = 'TCP'
        UDP = 'UDP'
        ICMP = 'ICMP'

    def get_rule_similarity_tuple(self,
                                  section: bool = True,
                                  action: bool = True,
                                  dest_ports: bool = True,
                                  protocols: bool = True,
                                  ruleset: bool = True,
                                  enabled: bool = True,
                                  source: bool = True,
                                  source_labels: bool = False,
                                  source_processes: bool = False,
                                  destination: bool = True,
                                  destination_labels: bool = False,
                                  destination_processes: bool = False
                                  ) -> Tuple[str, ...]:
        """ Return a tuple that allows comparing the rule (or parts of it's attributes) to other rules """
        rule_similarity_attributes = []
        if section:
            rule_similarity_attributes.append(self.section.value)
        if action:
            rule_similarity_attributes.append(self.action.value)
        if source:
            rule_similarity_attributes.append(str(self.source))
        else:
            if source_labels:
                rule_similarity_attributes.append(str(self.source.labels))
            if source_processes:
                if self.source.processes:
                    rule_similarity_attributes.append(
                        ", ".join(sorted([process for process in self.source.processes])))
                else:
                    rule_similarity_attributes.append("")
        if destination:
            rule_similarity_attributes.append(str(self.destination))
        else:
            if destination_labels:
                rule_similarity_attributes.append(str(self.destination.labels))
            if destination_processes:
                if self.destination.processes:
                    rule_similarity_attributes.append(", ".join(sorted([process for process in
                                                                        self.destination.processes])))
                else:
                    rule_similarity_attributes.append("")
        if dest_ports:
            rule_similarity_attributes.append(str(self.dest_ports))
        if protocols:
            rule_similarity_attributes.append(
                ', '.join(sorted([protocol.value for protocol in self.protocols])))
        if ruleset:
            rule_similarity_attributes.append(self.ruleset)
        if enabled:
            rule_similarity_attributes.append(self.enabled)

        return tuple(rule_similarity_attributes)

    def to_csv_dict(self) -> Dict[str, str]:
        """
        Return a representation of the rule that can be saved as a line in a CSV. This representation is similar to the
        one yielded by the 'export to csv' functionality in the policy rules page.
        """
        src_dict = self.source.to_csv_dict()
        dest_dict = self.destination.to_csv_dict()
        ports_dict = self.dest_ports.to_csv_dict()
        return {
            'id': self.id,
            'section': self.section.value,
            'source assets': src_dict['assets'],
            'source processes': src_dict['processes'],
            'source labels': src_dict['labels'],
            'source label groups': src_dict['label_groups'],
            'source subnets': src_dict['subnets'],
            'source user groups': src_dict['user_groups'],
            'source address classification': src_dict['address_classification'],
            'destination assets': dest_dict['assets'],
            'destination processes': dest_dict['processes'],
            'destination labels': dest_dict['labels'],
            'destination label groups': dest_dict['label_groups'],
            'destination subnets': dest_dict['subnets'],
            'destination domains': dest_dict['domains'],
            'destination address classification': dest_dict['address_classification'],
            'dest. ports': ports_dict['dest_ports'],
            'excluded dest. ports': ports_dict['excluded_dest_ports'],
            'ip_protocols': ', '.join([protocol.value for protocol in self.protocols]),
            'action': self.action.value,
            'ruleset': self.ruleset,
            'author': self.author,
            'comments': self.comments,
            'enabled': self.enabled,
        }

    def to_api_dict(self, gc_api: RESTManagementAPI = None) -> Dict[str, str]:
        """
        Return a representation of the PolicyRule in the format suitable for creating / updating rules through
        Centra API. This operation requires knowing the ids of the all the rule's child members (labels, assets, etc).
        In case the ids are not already set, providing a centra API connection is required to get query Centra to get
        them.
        :param gc_api: Optional - a RESTManagementAPI object, used to query Centra API to get ids of the rule member
        objects if those are not already set
        :raise AssertionError: will be raised if the id of one of the rule's member objects is unknown and gc_api was
        not provided
        :raise CentraObjectNotFound: will be raised if during the search for the id of a member object in Centra,
        an object matching the search criteria was not found
        """
        return {
            'id': self.id,
            'action': self.action.value,
            'section_position': self.section.value,
            'source': self.source.to_api_dict(gc_api),
            'destination': self.destination.to_api_dict(gc_api),
            'ports': list(self.dest_ports.include_ports),
            'port_ranges': [port_range.to_dict() for port_range in self.dest_ports.include_port_ranges],
            'exclude_ports': list(self.dest_ports.exclude_ports),
            'exclude_port_ranges': [port_range.to_dict() for port_range in self.dest_ports.exclude_port_ranges],
            'ip_protocols': [protocol.value for protocol in self.protocols],
            'ruleset_name': self.ruleset,
            'author': self.author,
            'comments': self.comments,
            'enabled': self.enabled,
        }

    @classmethod
    def from_api_dict(cls, rule_dict: Dict[str, Any]):
        """ Generate a PolicyRule object from a rule dictionary returned from Centra API """
        section = PolicyRule.Section(rule_dict["section_position"].lower())
        action = PolicyRule.Action(rule_dict["action"].lower())
        author = rule_dict["author"]["username"]
        comments = rule_dict.get("comments", "")
        enabled = rule_dict["enabled"]
        rule_id = rule_dict["id"]
        ruleset = rule_dict["ruleset_name"]
        protocols = {PolicyRule.Protocol(protocol.upper())
                     for protocol in rule_dict["ip_protocols"]}
        dest_ports = PortsExpression.from_rule_api_dict(rule_dict)
        source, destination = RuleSide.from_rule_api_dict(rule_dict)
        return cls(
            section=section,
            action=action,
            source=source,
            destination=destination,
            dest_ports=dest_ports,
            protocols=protocols,
            id=rule_id,
            ruleset=ruleset,
            author=author,
            enabled=enabled,
            comments=comments
        )
