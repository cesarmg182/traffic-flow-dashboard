from dataclasses import dataclass
from typing import Set, Dict, Any, Union, Tuple, List

from api.guardicore import RESTManagementAPI
from api.exceptions import CentraObjectNotFound
from common.labels.exceptions import LabelNotFoundInCentra


@dataclass
class ShortLabel:
    """
    Short representation of a Centra label, compounded of key: value pair, potentially also containing the id of this
    label in Centra
    """
    key: str
    value: str
    id: str = None

    @property
    def name(self):
        return f'{self.key}: {self.value}'

    def __post_init__(self):
        """ Raise ValueError if the key or value are empty """
        if not self.key:
            raise ValueError(f"Label's key must not be empty")
        if not self.value:
            raise ValueError(f"Label's value must not be empty")

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash((self.key, self.value))

    def __and__(self, other) -> 'LabelsIntersection':
        if isinstance(other, ShortLabel):
            return LabelsIntersection((self, other))
        if isinstance(other, LabelsIntersection):
            return LabelsIntersection((self, *other.labels))
        else:
            raise TypeError()

    def __eq__(self, other):
        if isinstance(other, ShortLabel):
            return self.key == other.key and self.value == other.value
        else:
            raise TypeError()

    def get_or_query_label_id(self, gc_api: RESTManagementAPI = None):
        """
        Return the id of the label in Centra if self.id is set, or otherwise query Centra to get the id.
        :param gc_api: A RESTManagementAPI object, used to query Centra API to get the label's id if its not already set
        :raise AssertionError: If self.id is not set and gc_api was not provided
        :raise LabelNotFoundInCentra: If a label matching the key and value of the ShortLabel was not found in Centra
        """
        if self.id:
            return self.id

        assert gc_api, "RESTManagementAPI object must be provided to query Centra for label ids"

        try:
            label_id = gc_api.get_label_id(self.key, self.value)
            self.id = label_id
            return self.id
        except CentraObjectNotFound as e:
            raise LabelNotFoundInCentra(str(e))

    @classmethod
    def from_api_dict(cls, label_dict: Dict[str, Any]) -> 'ShortLabel':
        """
        Generate a ShortLabel object from a label's dictionary returned from Centra API
        """
        return cls(
            key=label_dict['key'],
            value=label_dict['value'],
            id=label_dict['id']
        )


@dataclass
class ShortLabelGroup:
    """
    Short representation of a Centra label group, compounded of key: value pair, potentially also containing the id
    of this label group in Centra
    """
    key: str
    value: str
    id: str = None

    @property
    def name(self):
        return f'{self.key}: {self.value}'

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash((self.key, self.value))

    def get_or_query_label_group_id(self, gc_api: RESTManagementAPI = None):
        """
        Return the label group's id. If self.id is not set, query Centra to get the label group's id.
        :param gc_api: A RESTManagementAPI object, used to query Centra API to get the label group's id if its not
        already set
        :raise AssertionError: If self.id is not set and gc_api was not provided
        :raise CentraObjectNotFound: will be raised by get_label_group_id If a label group matching the key and value
        of the ShortLabelGroup was not found in Centra
        """
        if self.id:
            return self.id

        assert gc_api, "RESTManagementAPI object must be provided to query Centra for label ids"

        label_group_id = gc_api.get_label_group_id(self.key, self.value)
        self.id = label_group_id
        return self.id

    @classmethod
    def from_api_dict(cls, label_dict: Dict[str, Any]) -> 'ShortLabelGroup':
        """
        Generate a ShortLabelGroup object from a label group's dictionary returned from Centra API
        """
        return cls(
            key=label_dict['key'],
            value=label_dict['value'],
            id=label_dict['id']
        )

    @classmethod
    def from_str(cls, string: str) -> 'ShortLabelGroup':
        """ Generate a ShortLabelGroup object from a 'key: value' string """
        key, value = string.split(':')
        return cls(key, value)


@dataclass(frozen=True)
class LabelsIntersection:
    """
    Representation of an intersection between multiple Centra labels with an AND relation between them.
    i.e
        logically: Environment: Production AND App: Accounting
        textually: Environment: Production & App: Accounting
    """
    labels: Tuple[ShortLabel, ...]

    @property
    def keys(self) -> List[str]:
        return [label.key for label in self.labels]

    def __post_init__(self):
        """ Raise ValueError if the more than one label with the same key was provided """
        if len(set(self.keys)) != len(self.labels):
            raise ValueError("Label intersection cannot contain more than one label for the same key")

    def __str__(self):
        return f"{' & '.join([str(label) for label in self.labels])}"

    def __and__(self, other) -> 'LabelsIntersection':
        if isinstance(other, ShortLabel):
            return LabelsIntersection((*self.labels, other))
        if isinstance(other, LabelsIntersection):
            return LabelsIntersection((*self.labels, *other.labels))
        else:
            raise TypeError()

    def __or__(self, other: Union['LabelsExpression', 'LabelsIntersection']) -> 'LabelsExpression':
        if isinstance(other, LabelsExpression):
            return LabelsExpression({self} | other.labels_intersections)
        elif isinstance(other, LabelsIntersection):
            return LabelsExpression({self} | {other})
        else:
            raise TypeError()

    @classmethod
    def from_str(cls, string: str) -> 'LabelsIntersection':
        """
        Generate a LabelsIntersection object from a string representing one or more label(s). Multiple labels should
        be separated with an ampersand (&), e.g. Environment: Production & Application: CRM
        """
        intersection_labels = []
        for label in string.split('&'):
            key, value = label.split(':')
            intersection_labels.append(ShortLabel(key.strip(), value.strip()))
        return cls(tuple(intersection_labels))


@dataclass
class LabelsExpression:
    """
    Representation of a compound label expression, containing multiple label intersections with an OR relation between
    them.
    i.e
        logically: Environment: (Production AND App: Accounting) OR (Environment: Production AND App: CRM)
        textually: Environment: Production & App: Accounting, Production & App: CRM
    """
    labels_intersections: Set[LabelsIntersection]

    def __str__(self):
        return f"{', '.join(sorted([str(label_intersection) for label_intersection in self.labels_intersections]))}"

    def __or__(self, other: Union['LabelsExpression', LabelsIntersection]) -> 'LabelsExpression':
        if isinstance(other, LabelsExpression):
            return LabelsExpression(self.labels_intersections | other.labels_intersections)
        elif isinstance(other, LabelsIntersection):
            return LabelsExpression(self.labels_intersections | {other})
        else:
            raise TypeError()

    def __ge__(self, other: 'LabelsExpression'):
        """ Return true if the other LabelsExpression is a subset of self, otherwise return False """
        if isinstance(other, LabelsExpression):
            return self.labels_intersections >= other.labels_intersections
        else:
            raise TypeError()

    def __le__(self, other: 'LabelsExpression'):
        """ Return true if self is a subset of the other LabelsExpression, otherwise return False """
        if isinstance(other, LabelsExpression):
            return self.labels_intersections <= other.labels_intersections
        else:
            raise TypeError()

    def __contains__(self, item: LabelsIntersection):
        """ Return true if a LabelsIntersection is in self.labels_intersections, otherwise return False """
        if isinstance(item, LabelsIntersection):
            return item in self.labels_intersections
        else:
            raise TypeError()

    @classmethod
    def from_rule_labels_dict(cls, labels_expression_dict) -> 'LabelsExpression':
        """
        Generate a LabelsExpression from a dictionary representing a labels expression in the source or destination
        of a Centra policy rule.
        The following example input dictionary represents the logical label expression
        (Environment:Production AND App: Accounting) OR Role: DB:
            {
                "or_labels": [
                    {
                        "and_labels": [
                            {"key": "Environment", "value": "Production", "id": "aaaa-bbbb-ccc....", ...},
                            {"key": "App", "value": "Accounting", "id": "cccc-dddd-eee....", ...},
                        ]
                    },
                    {
                        "and_labels": [
                            {"key": "Role", "value": "DB", "id": "dddd-eeee-ffff....", ...},
                        ]
                    }
            }
        """
        label_intersections = set()
        for label_intersection in labels_expression_dict["or_labels"]:
            labels = []
            for label_dict in label_intersection["and_labels"]:
                labels.append(ShortLabel.from_api_dict(label_dict))
            label_intersections.add(LabelsIntersection(tuple(labels)))
        return cls(label_intersections)

    def to_rule_format(self, gc_api: RESTManagementAPI = None) -> Dict[str, List[Dict[str, List[str]]]]:
        """
        Return a representation of the LabelExpression in the format suitable for using in the source / destination
        of policy rules. This operation requires knowing all the ids of the ShortLabel which are members of this label
        expression. In case the ids are not already set, providing a centra API connection is required to get those.
        :param gc_api: Optional - a RESTManagementAPI object, used to query Centra API to get the label ids of each
        ShortLabel
        members if those are not already set
        """
        label_intersections = []
        for label_intersection in self.labels_intersections:
            labels = []
            for label in label_intersection.labels:
                labels.append(label.get_or_query_label_id(gc_api))
            label_intersections.append({"and_labels": labels})
        return {"or_labels": label_intersections}

    def to_map_filter(self, gc_api: RESTManagementAPI = None) -> List[List[str]]:
        """
        Return a representation of the LabelExpression in the format suitable for label filters in the map and graph
        API requests. This operation requires knowing all the ids of the ShortLabel which are members of this label
        expression. In case the ids are not already set, providing a centra API connection is required to get those.
        :param gc_api: A RESTManagementAPI object, used to query Centra API to get the label ids of each ShortLabel
        members if those are not already set
        """
        map_filter = []
        for label_intersection in self.labels_intersections:
            intersection_labels = []
            for label in label_intersection.labels:
                intersection_labels.append(label.get_or_query_label_id(gc_api))
            map_filter.append(intersection_labels)
        return map_filter
