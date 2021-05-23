import logging

from collections import namedtuple
from typing import Dict, List, Any, Generator
from time import sleep

from aggregated_flows_export.api.guardicore import RESTManagementAPI, ManagementAPITimeoutError
from aggregated_flows_export.api.exceptions import CentraObjectNotFound
from aggregated_flows_export.common.labels.exceptions import IllegalLabelException, LabelKeyOrValueIsEmpty, LabelContainsIllegalCharacters, \
    LabelNotFoundInCentra

LABEL_OBJECTS_TO_GET_AT_ONCE = 1000
LABEL_OBJECTS_TO_GET_AT_ONCE_AFTER_TIMEOUT = 50
DYNAMIC_CRITERIA_LIMIT = 500000

CHARS_ILLEGAL_IN_LABELS = set("\\/:?][,")


logger = logging.getLogger("guardicore." + __name__)


# todo remove me after redirecting all the usage to models.ShortLabel
class Label(namedtuple('Label', ['key', 'value'])):
    __slots__ = ()

    def __str__(self):
        return f'{self.key}: {self.value}'


class NameCriterion(namedtuple('NameCriteria', ['name', 'criterion_type'])):
    """
    Represent a Centra label name dynamic criterion. NameCriterion has two attributes:
    name: the string to match
    criterion_type: The matching method - one of: EQUALS (EXACT in Centra UI), STARTSWITH, ENDSWITH, CONTAINS, WILDCARDS
    """
    __slots__ = ()

    def __str__(self):
        if self.criterion_type == "STARTSWITH":
            return f"Asset name starts with '{self.name}'"
        elif self.criterion_type == "ENDSWITH":
            return f"Asset name ends with '{self.name}'"
        elif self.criterion_type == "CONTAINS":
            return f"Asset name contains '{self.name}'"
        elif self.criterion_type == "WILDCARDS":
            return f"Asset name matches the pattern '{self.name}'"
        elif self.criterion_type == "EQUALS":  # matches Exact name criteria in Centra UI
            return f"Asset name is exactly '{self.name}'"
        else:
            raise UnexpectedNameCriteriaType(
                f"Named criteria '{repr(self)}' has an unknown criteria type")

    @staticmethod
    def convert_string_to_name_dynamic_criteria_object(s: str):
        """
        Converts a string to a NameCriteria object. The criteria type will be determined in the following way:
        EQUALS (EXACT in Centra UI): matched if the string starts and ends with two '*' signs.
        STARTSWITH: matched by chars followed by a single '*' sign at the end of the target string
        ENDSWITH: matched by a single '*' sign at the beginning of the target string followed by other chars
        CONTAINS: matched by a single '*' sign at the beginning and a single '*' sign the end of the target
        string
        WILDCARDS: matched if the target string contains a '*' sign but doesnt match any of the above
        :raises StringIsNotDynamicCriteria: If the target string does not match any of the above criteria types
        :return: NameCriteria object
        """
        num_of_asterisks_in_string = s.count('*')
        if num_of_asterisks_in_string > 0:
            if num_of_asterisks_in_string > 4 or len(s) == num_of_asterisks_in_string:
                return NameCriterion(s, 'WILDCARDS')
            elif s.startswith('**') and s.endswith('**') and num_of_asterisks_in_string == 4:
                return NameCriterion(s.strip('*'), "EQUALS")
            elif s.startswith('*'):
                if s.endswith('*') and num_of_asterisks_in_string == 2:
                    return NameCriterion(s.strip('*'), "CONTAINS")
                elif num_of_asterisks_in_string == 1:
                    return NameCriterion(s.strip('*'), "ENDSWITH")
            elif s.endswith('*') and num_of_asterisks_in_string == 1:
                return NameCriterion(s.strip('*'), "STARTSWITH")
            return NameCriterion(s, 'WILDCARDS')
        raise StringIsNotNameCriterion(
            f"The string {s} cannot be converted to a NameCriteria object")

    def to_export_string(self):
        """
        Returns a string representing the name dynamic criteria in its "Export" form.
        See the documentation of convert_string_to_name_dynamic_criteria_object for more info about the representation
        of name criterias as strings
        """
        if self.criterion_type == "WILDCARDS":
            return f"{self.name}"
        elif self.criterion_type == "CONTAINS":
            return f"*{self.name}*"
        elif self.criterion_type == "ENDSWITH":
            return f"*{self.name}"
        elif self.criterion_type == "STARTSWITH":
            return f"{self.name}*"
        elif self.criterion_type == "EQUALS":
            return f"**{self.name}**"
        else:
            raise UnexpectedNameCriteriaType(
                f"Unexpected criterion_type for name dynamic criteria '{repr(self)}'")


class NameDynamicCriteriaException(Exception):
    """Parent class for exceptions related to name dynamic criterias"""
    pass


class UnexpectedNameCriteriaType(NameDynamicCriteriaException):
    """Raised when a name dynamic criteria has an unsupported type"""
    pass


class StringIsNotNameCriterion(NameDynamicCriteriaException):
    """Raised when a string cannot be converted to a name criterion object"""
    pass


def get_centra_labels(gc_api: RESTManagementAPI, label_objects_to_get_at_once: int = LABEL_OBJECTS_TO_GET_AT_ONCE,
                      **filters) -> List[Dict[str, Any]]:
    """
    Query Centra API for all the labels matching the provided filters. If no filters was provided, all the labels will
    be fetched
    :param gc_api: RESTManagementAPI object
    :param label_objects_to_get_at_once: The amount of label objects to request from the API in a single call
    :param filters: Only fetch labels matching the filters. The supported filters are similar to the filters in the
    labels page in Centra UI
    :return: a list containing all Centra label objects as they are returned from the API
    """
    centra_labels = list()
    offset = 0
    logger.debug(
        f"Requesting a chunk of {label_objects_to_get_at_once} labels from Centra")
    try:
        response = gc_api.list_visibility_labels(limit=label_objects_to_get_at_once,
                                                 dynamic_criteria_limit=DYNAMIC_CRITERIA_LIMIT, **filters)
    except ManagementAPITimeoutError:
        logger.warning("The request for labels from Centra has timed out")
        logger.info(
            "Sleeping for 60 seconds and trying again with a lower the number of labels requested at once.")
        label_objects_to_get_at_once = LABEL_OBJECTS_TO_GET_AT_ONCE_AFTER_TIMEOUT
        sleep(60)
        response = gc_api.list_visibility_labels(limit=label_objects_to_get_at_once,
                                                 dynamic_criteria_limit=DYNAMIC_CRITERIA_LIMIT, **filters)
    while len(response["objects"]) > 0:
        for label_obj in response["objects"]:
            try:
                validate_label_or_label_group(
                    f"{label_obj.get('key')}: {label_obj.get('value')}")
                centra_labels.append(label_obj)
            except IllegalLabelException as e:
                logger.warning(f"Invalid label with label id {label_obj.get('id', 'N/A')} was found in Centra: {e}. "
                               f"Please contact Guardicore support")
                logger.debug(label_obj)
        if len(response["objects"]) == label_objects_to_get_at_once:
            offset += label_objects_to_get_at_once
            logger.debug(
                f"Requesting {label_objects_to_get_at_once} labels from Centra, with offset {offset}")
            response = gc_api.list_visibility_labels(limit=label_objects_to_get_at_once,
                                                     offset=offset,
                                                     dynamic_criteria_limit=DYNAMIC_CRITERIA_LIMIT,
                                                     **filters)
        else:
            break
    logger.debug(f"Got {len(centra_labels)} labels from Centra")
    return centra_labels


def get_centra_labels_generator(gc_api: RESTManagementAPI,
                                label_objects_to_get_at_once: int = LABEL_OBJECTS_TO_GET_AT_ONCE,
                                **filters) -> Generator[Dict[str, Any], None, None]:
    """
    Query Centra API for all the labels matching the provided filters. If no filters was provided, all the labels will
    be fetched. The labels are validated and yielded one by one
    :param gc_api: RESTManagementAPI object
    :param label_objects_to_get_at_once: The amount of label objects to request from the API in a single call
    :param filters: Only fetch labels matching the filters. The supported filters are similar to the filters in the
    labels page in Centra UI
    :return: a list containing all Centra label objects as they are returned from the API
    """
    offset = 0
    logger.debug(
        f"Requesting a chunk of {label_objects_to_get_at_once} labels from Centra")
    try:
        response = gc_api.list_visibility_labels(limit=label_objects_to_get_at_once,
                                                 dynamic_criteria_limit=DYNAMIC_CRITERIA_LIMIT, **filters)
    except ManagementAPITimeoutError:
        logger.warning("The request for labels from Centra has timed out")
        logger.info(
            "Sleeping for 60 seconds and trying again with a lower the number of labels requested at once.")
        label_objects_to_get_at_once = LABEL_OBJECTS_TO_GET_AT_ONCE_AFTER_TIMEOUT
        sleep(60)
        response = gc_api.list_visibility_labels(limit=label_objects_to_get_at_once,
                                                 dynamic_criteria_limit=DYNAMIC_CRITERIA_LIMIT, **filters)
    while len(response["objects"]) > 0:
        for label_obj in response["objects"]:
            try:
                validate_label_or_label_group(
                    f"{label_obj.get('key')}: {label_obj.get('value')}")
                yield label_obj
            except IllegalLabelException as e:
                logger.warning(f"Invalid label with label id {label_obj.get('id', 'N/A')} was found in Centra: {e}. "
                               f"Please contact Guardicore support")
                logger.debug(label_obj)
        if len(response["objects"]) == label_objects_to_get_at_once:
            offset += label_objects_to_get_at_once
            logger.debug(
                f"Requesting {label_objects_to_get_at_once} labels from Centra, with offset {offset}")
            response = gc_api.list_visibility_labels(limit=label_objects_to_get_at_once, offset=offset,
                                                     dynamic_criteria_limit=DYNAMIC_CRITERIA_LIMIT, **filters)
        else:
            break


def get_label_id(key: str, value: str, gc_api: RESTManagementAPI) -> str:
    """Search for a label in centra and return the label's id. If not, raise LabelNotFoundInCentra"""
    try:
        return gc_api.get_label_id(key, value)
    except CentraObjectNotFound:
        raise LabelNotFoundInCentra(
            f"The label {key}: {value} was not found in Centra")


def validate_label_or_label_group(label: str) -> None:
    """
    Validates a label or label group string is legal
    :param label: The string representing the label in the form of 'key: value'
    :raises IllegalLabelException: If the provided label is not string or if the label contains more or less than one
    colon
    :raises LabelKeyOrValueIsEmpty: If the key or the value of the label is empty
    :raises LabelContainsIllegalCharacters: If the label contains character which is illegal to use in labels
    """
    if not isinstance(label, str):
        raise IllegalLabelException(
            f"The provided label '{repr(label)}' is not string")
    try:
        # ValueError will be raised if there more or less than 1 ':'
        key, value = label.split(':')
    except ValueError:
        raise IllegalLabelException(
            f"The label '{label}' does not contain exactly one colon (':')")
    if not len(key.strip()) > 0:
        raise LabelKeyOrValueIsEmpty(
            f"The key of the label '{label}' is empty")
    if not len(value.strip()) > 0:
        raise LabelKeyOrValueIsEmpty(
            f"The value of the label '{label}' is empty")
    illegal_chars_in_key = [c for c in key if c in CHARS_ILLEGAL_IN_LABELS]
    if illegal_chars_in_key:
        raise LabelContainsIllegalCharacters(f"The key of the label '{label}' contains illegal characters: "
                                             f"{', '.join(illegal_chars_in_key)}")
    illegal_chars_in_value = [c for c in value if c in CHARS_ILLEGAL_IN_LABELS]
    if illegal_chars_in_value:
        raise LabelContainsIllegalCharacters(f"The value of the label '{label}' contains illegal characters: "
                                             f"{', '.join(illegal_chars_in_value)}")


def labels_str_to_rule_format(labels_string: str, gc_api: RESTManagementAPI) -> Dict[str, List[Dict[str, List[str]]]]:
    """
    Convert a labels string to the format accepted by the API for policy rules
    :param labels_string: a string describing labels in form of: 'key: value, key: value & key: value' i.e
    "Environment: Users, Environment: Corp & App: Jumpboxes" meaning "(Environment: Users) OR (Environment:
    Corp AND App: Jumpboxes)". spaces will be disregarded around the labels_string and around the special chars & , :.
    :param gc_api: A RESTManagementAPI object. Will be used to query to translate each label (key: value) to its
    label id
    :return: [['label_id_1'], ['label_id_2', 'label_id_3']]
    """
    structured_labels = {"or_labels": list()}
    # Normalize spaces
    labels_string = labels_string.replace(", ", ",").replace(
        " ,", ",").replace("& ", "&").replace(" &", "&")
    labels_string = labels_string.replace(": ", ":").replace(" :", ":").strip()

    for or_label in labels_string.split(','):
        and_labels = {"and_labels": list()}
        for and_label in or_label.split('&'):
            key, value = and_label.split(':')
            and_labels["and_labels"].append(get_label_id(key, value, gc_api))
        structured_labels["or_labels"].append(and_labels)
    return structured_labels


def labels_str_to_filter_format(labels_string: str, gc_api: RESTManagementAPI) -> List[List[str]]:
    """
    Convert a labels string to the format accepted by the API for map and graph filters.
    The input label_string can be a simple label name (Key: Value) or a complex label expression.
    :param labels_string: a string describing labels in form of: 'key: value, key: value & key: value' i.e
    "Environment: Users, Environment: Corp & App: Jumpboxes" meaning "(Environment: Users) OR (Environment:
    Corp AND App: Jumpboxes)". spaces will be disregarded around the labels_string and around the special chars & , :.
    :param gc_api: A RESTManagementAPI object. Will be used to query Centra for the label if of each label
    :return: list of lists - [["label_id_1"], ["label_id_2", "label_id_3"]
    """
    labels_string = labels_string.replace(": ", ":").replace(" :", ":").strip()

    structured_labels = []
    if labels_string.count(':') > 1:  # format complex label expressions
        labels_string = labels_string.replace(", ", ",").replace(
            " ,", ",").replace("& ", "&").replace(" &", "&")
        for or_label in labels_string.split(','):
            and_labels = []
            for and_label in or_label.split('&'):
                key, value = and_label.split(':')
                and_labels.append(get_label_id(key, value, gc_api))
            structured_labels.append(and_labels)
    else:  # format individual labels
        key, value = labels_string.split(':')
        structured_labels.append([get_label_id(key, value, gc_api)])
    return structured_labels
