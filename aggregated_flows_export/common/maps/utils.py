import logging
import csv

from datetime import datetime
from time import sleep
from typing import Dict, List, Union, Any, Set
from io import StringIO
from netaddr import IPNetwork

from api.guardicore import RESTManagementAPI, ManagementAPITimeoutError, GraphExpired
from common.common import INTERNET_FILTER_MAP, CONNECTION_TYPES_MAP, POLICY_ACTIONS_MAP
from common.labels.models import LabelsIntersection, LabelsExpression, ShortLabelGroup
from common.labels.utils import labels_str_to_filter_format
from common.labels.exceptions import LabelNotFoundInCentra
from common.maps.models import MapFilter
from common.maps.exceptions import SavedMapIsEmpty, SavedMapCreationFailed, SavedMapNotFound, SavedMapIsNotReady, \
    GraphGenerationTimedOut, NoFlowsMatchTheFilter, MapExportTimedOut, MapExportJobError
from common.policy.models import PortRange

# Increase csv max field size to handle flow with long text in one of the fields
DEFAULT_CSV_FIELD_SIZE = csv.field_size_limit()
csv.field_size_limit(DEFAULT_CSV_FIELD_SIZE*1000)

SUPPORTED_MAP_FILTER_FIELDS = {"connection_types", "connections_to_labels", "connections_from_labels", "labels",
                               "internet", "connections_to_subnets", "connections_from_subnets", "label_groups",
                               "policy_rules", "assets", "protocols", "processes", "policy_rulesets", "ports",
                               "policy_actions", "subnets", "address_classifications"}

MAX_NUMBER_OF_DEST_PORTS_TO_ALLOW_VM_EXPANDING = 100
VM_GRAPH_ENDPOINT_TYPE = 2


logger = logging.getLogger("guardicore." + __name__)


def generate_saved_map(gc_api: RESTManagementAPI, map_name: str, start_time: datetime, end_time: datetime,
                       include_filter: Dict[str, Union[str, int, List]] = None,
                       exclude_filter: Dict[str, Union[str, int, List]] = None, time_resolution: bool = False,
                       include_flow_hit_count: bool = False, include_incident_marks: bool = False,
                       map_type: int = 0, include_processes: bool = True,
                       delete_empty_saved_maps: bool = False) -> Dict[str, Any]:
    """
    Generate a Reveal Saved Map in Centra according to the provided parameters. See filter structure in
    the documentation of the map_filter_helper function
    :param gc_api: Centra API session object
    :param map_name: Name for the map
    :param start_time: Map flows start time
    :param end_time: Map flows end time
    :param include_filter: Flows matching this filter will be included in the map
    :param exclude_filter: Flows matching this filter will be excluded from the map
    :param time_resolution: Whether to include exact flows time in the map creation
    :param include_flow_hit_count: Whether to include flows hit count in the map
    :param include_incident_marks: Whether to include incidents data on map flows
    :param map_type: 0 - public map, 1 - Admins only map
    :param include_processes: Whether to include processes in the map creation. This option is deprecated starting of
    v31.7, and processes will be included in any saved map.
    :param delete_empty_saved_maps: If True, if the the generated saved map is empty, it will be automatically deleted.
    :return: The saved map object of the newly created map as it is returned form the API
    """
    include_filter = include_filter if include_filter is not None else {}
    exclude_filter = exclude_filter if exclude_filter is not None else {}
    include_policy_filter, exclude_policy_filter = None, None
    if "policy" in include_filter:
        logger.info(
            "policy_actions filter is not supported for map creation. The map will be created without this "
            "filter, but it still can be applied by filtering the graph (map view)")
        include_policy_filter = include_filter["policy"].copy()  # Save the filter to restore it later
        del (include_filter["policy"])
    if "policy" in exclude_filter:
        logger.info(
            "policy_actions filter is not supported for map creation. The map will be created without this "
            "filter, but it still can be applied by filtering the graph (map view)")
        exclude_policy_filter = exclude_filter["policy"].copy()  # Save the filter to restore it later
        del (exclude_filter["policy"])

    logger.debug(f"Map generation start time: {datetime.now()}")
    generated_saved_map_id = gc_api.generate_saved_map(map_name, start_time, end_time, include_filter=include_filter,
                                                       exclude_filter=exclude_filter, time_resolution=time_resolution,
                                                       include_flow_hit_count=include_flow_hit_count,
                                                       include_incident_marks=include_incident_marks,
                                                       map_type=map_type, include_processes=include_processes)["id"]
    try:
        saved_map = wait_for_saved_map(gc_api, generated_saved_map_id)
    except SavedMapIsEmpty as e:
        if delete_empty_saved_maps:
            try:
                gc_api.delete_saved_map(generated_saved_map_id)
                logger.info(f"Successfully deleted the empty saved map")
            except Exception as err:
                logger.warning(f"Could not delete the empty saved map. {repr(err)}")
        raise e
    logger.debug(f"Map generation end time: {datetime.now()}")
    if include_policy_filter:
        include_filter["policy"] = include_policy_filter
    if exclude_policy_filter:
        exclude_filter["policy"] = exclude_policy_filter
    return saved_map


def wait_for_saved_map(gc_api: RESTManagementAPI, map_id: str,
                       seconds_to_sleep_between_checks: int = 10) -> Dict[str, Any]:
    """
    Wait until the saved map with the provided map_id is in ready state.
    :param gc_api: Centra API session object
    :param map_id: The id of the map to wait for
    :param seconds_to_sleep_between_checks: time to sleep between the status checks, in seconds
    :return: The saved map object as it is returned form the API
    """
    while True:
        saved_map = find_saved_map_data(gc_api, map_id)
        state = saved_map['state'].upper()

        if state == 'EMPTY':
            raise SavedMapIsEmpty("Saved map is empty")

        if state == 'READY':
            logger.info("Saved map is ready")
            return saved_map

        if state not in ['QUEUED', 'IN_PROGRESS']:
            raise SavedMapCreationFailed(f"Saved Map creation failed: {saved_map['error']}")

        if saved_map.get('completion_percentage', 100) != 100:
            logger.info(f"The saved map is being created ({saved_map.get('completion_percentage', 'N/A')}% complete). "
                        f"Waiting {seconds_to_sleep_between_checks} seconds before checking again.")
        else:
            logger.info(f"The saved map is being created. Waiting {seconds_to_sleep_between_checks} seconds "
                        f"before checking again")
        sleep(seconds_to_sleep_between_checks)


def find_saved_map_data(gc_api: RESTManagementAPI, map_id: str) -> Dict[str, Any]:
    """
    Search for a saved map with id equals to map_id in Centra. If the map is not found, raise SavedMapNotFound exception
    :param gc_api: Centra API session object
    :param map_id: The id of the map to get data for
    :return: The saved map object as it is returned form the API
    """
    response = gc_api.list_saved_maps(search=map_id, sort="-creation_time", time_range_filter="0,2147483647000")
    try:
        return response[0]
    except IndexError:
        raise SavedMapNotFound(f"Saved map with map id {map_id} was not found in Centra")


def get_existing_saved_map_data(gc_api: RESTManagementAPI, map_id: str) -> Dict[str, Any]:
    """
    Get the data of an existing ready saved map. If the map is empty, raise SavedMapIsEmpty. If the map is not ready,
    raise SavedMapIsNotReady
    :param gc_api: Centra API session object
    :param map_id: The id of the map to get data for.
    :return: The saved map object as it is returned form the API
    """
    map_data = find_saved_map_data(gc_api, map_id)
    state = map_data["state"].upper()
    if state == 'EMPTY':
        raise SavedMapIsEmpty(f"The saved map {map_data['id']} ({map_data['name']}) is empty")
    if state != 'READY':
        raise SavedMapIsNotReady(f"The saved map {map_data['id']} ({map_data['name']}) is not ready")
    return map_data


def map_filter_helper(raw_filter: Dict[str, Union[List[str], List[int]]] = None,
                      gc_api: RESTManagementAPI = None) -> Dict[str, Union[str, List, Dict]]:
    """
    Format a map filter to the format accepted by Centra API in saved map generation or graph generation
    (= generating a map view) API calls. This function is suitable both for include and exclude filters.
    :param raw_filter: Raw filter to format. See validate_map_filter for documentation of the acceptable input
    :param gc_api: In case the raw filter contains labels (labels, connections_from_labels, or
    connections_to_labels), providing a RESTManagementAPI object it required to query Centra for the ids of the mentioned
    labels in order to format those fields. If the filter contains labels and gc_api was not provided, the function
    will raise an AssertionError. If the label was mentioned in the filter but not found in Centra,
    LabelNotFoundInCentra will be raised.
    :return: a filter suitable to be sent to Centra API
    """
    if not raw_filter:
        return {}
    un_supported_filters = [filt for filt in raw_filter if filt not in SUPPORTED_MAP_FILTER_FIELDS]
    assert not un_supported_filters, f"The following provided filter(s) are not supported: " \
                                     f"{', '.join(un_supported_filters)}"
    filt = dict()
    if "connection_types" in raw_filter:
        filt["connection_types"] = [CONNECTION_TYPES_MAP[filt.lower()] for filt in raw_filter["connection_types"]]
    if "subnets" in raw_filter:
        filt["ip_address"] = {"ip": raw_filter["subnets"]}
    if "policy_actions" in raw_filter:
        filt["policy"] = [POLICY_ACTIONS_MAP[filt.lower()] for filt in raw_filter["policy_actions"]]
    if "ports" in raw_filter:
        filt["ports"] = [str(port) for port in raw_filter["ports"]]
    if "policy_rulesets" in raw_filter:
        filt["policy_rulesets"] = raw_filter["policy_rulesets"]
    if "processes" in raw_filter:
        filt["process_filter"] = raw_filter["processes"]
    if "protocols" in raw_filter:
        filt["protocols"] = [protocol.upper() for protocol in raw_filter["protocols"]]
    if "assets" in raw_filter:
        filt["vm"] = raw_filter["assets"]
    if "policy_rules" in raw_filter:
        filt["policy_rule"] = {"policy_rule": raw_filter["policy_rules"]}
    if "label_groups" in raw_filter:
        filt["label_groups"] = raw_filter["label_groups"]
    if "connections_from_subnets" in raw_filter:
        filt["source_ip_address"] = {"ip": raw_filter["connections_from_subnets"]}
    if "connections_to_subnets" in raw_filter:
        filt["destination_ip_address"] = {"ip": raw_filter["connections_to_subnets"]}
    if "internet" in raw_filter:
        filt["internet_flow"] = [INTERNET_FILTER_MAP[filt.lower()] for filt in raw_filter["internet"]]
    if "labels" in raw_filter:
        assert isinstance(gc_api, RESTManagementAPI), "Could not structure labels filter. gc_api object must be " \
                                                      "provided"
        labels_as_string = ','.join(raw_filter["labels"])
        if labels_as_string:
            try:
                filt["user_label"] = labels_str_to_filter_format(labels_as_string, gc_api)
            except LabelNotFoundInCentra as e:
                raise LabelNotFoundInCentra(f"Could not structure labels filter. {e}")
    if "connections_from_labels" in raw_filter:
        assert isinstance(gc_api, RESTManagementAPI), "Could not structure connections_from_labels filter. gc_api " \
                                                      "object must be provided."
        labels_as_string = ','.join(raw_filter["connections_from_labels"])
        try:
            filt["source_label"] = labels_str_to_filter_format(labels_as_string, gc_api)
        except LabelNotFoundInCentra as e:
            raise LabelNotFoundInCentra(f"Could not structure connections_from_labels filter. {e}")
    if "connections_to_labels" in raw_filter:
        assert isinstance(gc_api, RESTManagementAPI), "Could not structure connections_to_labels filter. gc_api " \
                                                      "object must be provided"
        labels_as_string = ','.join(raw_filter["connections_to_labels"])
        try:
            filt["destination_label"] = labels_str_to_filter_format(labels_as_string, gc_api)
        except LabelNotFoundInCentra as e:
            raise LabelNotFoundInCentra(f"Could not structure connections_to_labels filter. {e}")

    return filt


def generate_permalink(gc_api: RESTManagementAPI, map_id: str, start_time: str, end_time: str,
                       include_filter: Dict[str, Union[str, List, Dict]] = None,
                       exclude_filter: Dict[str, Union[str, List, Dict]] = None, group_by: List[str] = None,
                       zoom_in_count: int = 2, objects_to_expand: Set[str] = None,
                       expand_unmanaged_assets: bool = False) -> str:
    """
    Generate permalink for a saved map. This will be done by generating a graph (a map view) according to the requested
    parameters, and expanding (equals to double clicking on the map) the objects mentioned in objects_to_expand
    zoom_in_count times.
    :param gc_api: Centra API session object
    :param map_id: The id of the map to generate the permalink for
    :param start_time: Network flows start time, in milliseconds since epoch
    :param end_time: Network flows end time, in milliseconds since epoch
    :param group_by: List of label keys to group the map by
    :param include_filter: An include filter, generated by map_filter_helper
    :param exclude_filter: An include filter, generated by map_filter_helper
    :param zoom_in_count: Total number of times to expand the map objects mentioned in objects_to_expand. A graph will
    be generated and objects will be expanded zoom_in_count times. If 0 is passed, the graph will be generated but no
    objects will be expanded
    :param objects_to_expand: A list of objects to expand. The optional values are:
        'group' - signifies labels
        'subnets' - signifies subnets
        'vm' - signifies managed assets
        'Process' - signifies process objects (processes with the same name on the same vm are aggregated, so they
        might also require expanding)
        'internet' - signifies internet sources and destinations
        Expanding other types is not implemented, but can be added in the same way later.
    :param expand_unmanaged_assets: Whether to expand unmanaged assets (Default - No). Setting this to True does not
    necessarily imply that unmanaged assets will be expanded. In order to expand those, `vm` should also be provided
    in the objects_to_expand parameter
    :raises NoFlowsMatchTheFilter: if there are no flows matching the provided filters
    :return: A permalink ID
    """
    group_by = group_by if group_by is not None else []
    include_filter = include_filter if include_filter is not None else {}
    exclude_filter = exclude_filter if exclude_filter is not None else {}
    objects_to_expand = objects_to_expand if objects_to_expand is not None else set()
    logger.debug(f"Generating permalink for the map {map_id}, from {start_time} to {end_time} "
                 f"grouping by '{', '.join(group_by) if group_by else 'Ungrouped'}'. The map will be zoomed "
                 f"{zoom_in_count} times, expanding objects of types {', '.join(objects_to_expand)}")
    if zoom_in_count == 0:
        # Only generate base graph for the permalink
        logger.debug(f"Generating graph for the map {map_id}, from {start_time} to {end_time} "
                     f"grouping by '{', '.join(group_by) if group_by else 'Ungrouped'}'.")
        try:
            graph = gc_api.generate_map_graph(map_id, start_time, end_time, group_by=group_by,
                                              include_filter=include_filter,
                                              exclude_filter=exclude_filter, force_creation=True)
        except ManagementAPITimeoutError:
            raise GraphGenerationTimedOut("The Graph generation request timed out.")
        except GraphExpired:
            raise MapExportJobError("The results for the graph request was GraphExpired")
        if not graph:
            raise NoFlowsMatchTheFilter("No flows matched the provided filters")
        graph_state = {obj["id"]: dict(type=obj["type"], open=obj["is_open"], parent=obj["parent"]) for obj in graph}

    else:
        # Generate graph zoom_in_count times, each time expanding the graph objects whose type matches the
        # objects_to_expand
        graph_state = {}
        for i in range(1, zoom_in_count + 1):
            logger.debug(f"Generating graph number {i} for the map {map_id}, from {start_time} to {end_time} "
                         f"grouping by '{', '.join(group_by) if group_by else 'Ungrouped'}'.")
            try:
                graph = gc_api.generate_map_graph(map_id, start_time, end_time,
                                                  group_by=group_by, graph_state=graph_state,
                                                  include_filter=include_filter,
                                                  exclude_filter=exclude_filter, force_creation=True)
            except ManagementAPITimeoutError:
                raise GraphGenerationTimedOut("The Graph generation request timed out.")
            if not graph:
                raise NoFlowsMatchTheFilter("No flows matched the provided filters")

            graph_state = {}
            vms_that_should_not_be_expanded = list_vm_nodes_that_should_not_be_expanded(graph)
            for obj in graph:
                if obj["type"] in objects_to_expand:
                    if obj.get('id', '') in vms_that_should_not_be_expanded:
                        logger.debug(f"Skipping expending the vm {obj.get('id')} because the flows incoming to it "
                                     f"has too many distinct destination ports")
                    else:
                        if not (graph_object_is_unmanaged_asset(obj) and not expand_unmanaged_assets):
                            graph_state[obj["id"]] = dict(type=obj["type"], open=True, parent=obj["parent"])
                            continue

                # keep all objects that should not be expanded opened or closed as they were in the original graph
                if "is_open" in obj:
                    graph_state[obj["id"]] = dict(type=obj["type"], open=obj["is_open"], parent=obj["parent"])

    permalink_id = gc_api.generate_map_permalink_for_flows_export(map_id, start_time, end_time, group_by=group_by,
                                                                  graph=graph_state, include_filter=include_filter,
                                                                  exclude_filter=exclude_filter)
    return permalink_id


def export_flows_from_permalink(gc_api: RESTManagementAPI, permalink_id: str, seconds_to_sleep_between_checks: int = 10,
                                seconds_until_timeout: int = 600) -> csv.DictReader:
    """
    Export the network flows from the provided permalink (frozen map view). This is done by request a map export to CSV
    job form Centra, waiting until it is done and downloading it.
    :param gc_api: Centra API session object
    :param permalink_id: The id of the permalink to download the flows from
    :param seconds_to_sleep_between_checks: time to sleep between the status checks, in seconds
    :param seconds_until_timeout: The number of seconds to wait until timing out the request
    :raise MapExportJobError if the status of the export job indicates a failure
    :raise
    :return: A csv.DictReader containing the resulted flows
    """
    logger.debug(f"Exporting flows from Centra Map Permalink with id {permalink_id}")
    export_job_id = gc_api.request_map_export_job(permalink_id)

    while True:
        export_job_status = gc_api.get_map_export_job_status(export_job_id)
        state = export_job_status.get("state")
        if state is None:
            logger.error(f"Status without 'state' returned from Centra: {repr(export_job_status)}")
            raise MapExportJobError(f"Flows export CSV job has failed, bad status returned.")
        if state in {0, 1}:  # CSV is being created
            if export_job_status.get('total_records', 1) == 0:
                logger.info(f"The flows are being prepared for export. "
                            f"Waiting {seconds_to_sleep_between_checks} seconds before checking again.")
            else:
                logger.info(f"The flows are being prepared for export "
                            f"({export_job_status.get('records_written', 'N/A')} of "
                            f"{export_job_status.get('total_records', 'N/A')} completed). "
                            f"Waiting {seconds_to_sleep_between_checks} seconds before checking again.")
            if seconds_until_timeout > 0:
                seconds_until_timeout -= seconds_to_sleep_between_checks
                sleep(seconds_to_sleep_between_checks)
            else:
                raise MapExportTimedOut("The map to flows export has timed out")
        elif state == 2:  # CSV is ready
            logger.debug("The flows are ready to download.")
            break
        else:
            raise MapExportJobError(f"Flows export CSV job has failed with status '{state}'")

    logger.debug(f"Downloading the export job to CSV")
    raw_flows = gc_api.download_map_export_csv(export_job_status["exported_csv_file_id"])
    f = StringIO(raw_flows)
    return csv.DictReader(f, delimiter=',')


def list_vm_nodes_that_should_not_be_expanded(graph: List[Dict], include_unmanaged_assets: bool = False) -> Set[str]:
    """
    Iterate over all the connection dictionaries in the graph request, to locate vm objects that have flows with very
    high amount of distinct destination ports incoming to them. This allows to avoid expanding those objects in graph
    requests, to increase the chance of Centra to be able to generate the export.
    :param graph: A map graph as it is returned from Centra API
    :param include_unmanaged_assets: Whether to include or automatically ignore unmanaged assets. This should be True
    if unmanaged assets are expanded also
    :return: A set of vm nodes that should not be
    """
    vms_that_should_not_be_expanded = set()
    for connection in (graph_obj for graph_obj in graph if graph_obj["type"] in ('flow', 'failed_flow')):
        if len(connection["destination_ports"]) > MAX_NUMBER_OF_DEST_PORTS_TO_ALLOW_VM_EXPANDING:
            if connection["destination_endpoint_type"] == VM_GRAPH_ENDPOINT_TYPE:
                if connection["type"] == 'failed_flow':
                    destination_endpoint_id = connection["destination_endpoint_id"]
                    if not graph_object_is_unmanaged_asset(connection) or include_unmanaged_assets:
                        vms_that_should_not_be_expanded.add(destination_endpoint_id)
                else:
                    destination_endpoint_id = connection["out"]
                    if 'ip:' not in destination_endpoint_id or include_unmanaged_assets:
                        vms_that_should_not_be_expanded.add(destination_endpoint_id)
    return vms_that_should_not_be_expanded


def graph_object_is_unmanaged_asset(graph_obj: Dict) -> bool:
    """Return True if the graph object provided is an unmanaged asset"""
    return graph_obj.get("type") == "vm" and graph_obj.get("id", '').startswith("ip:")


def get_map_filter_from_args(raw_filter: Dict[str, List[str]]) -> MapFilter:
    """
    Parse the raw map filter dictionary and return a MapFilter object matching the provided filters.
    :raises ValueError: if the value provided for a filter is invalid
    :raises TypeError: if the type of the value provided for one of the filters is incorrect
    """
    un_supported_filters = [filt for filt in raw_filter if filt not in MapFilter.__annotations__]
    if un_supported_filters:
        raise ValueError(f"The provided filter(s) {', '.join(un_supported_filters)} are not supported")

    filter_dict = {}

    if "connection_types" in raw_filter:
        if not isinstance(raw_filter["connection_types"], list):
            raise TypeError("connection_types filter should be a list")
        try:
            filter_dict["connection_types"] = {MapFilter.ConnectionType[str(connection_type).upper().replace(' ', '_')]
                                               for connection_type in raw_filter["connection_types"]}
        except KeyError as e:
            raise ValueError(f"Invalid connection_types filter provided: {e}")

    if "subnets" in raw_filter:
        if not isinstance(raw_filter["subnets"], list):
            raise TypeError("subnets filter should be a list")
        try:
            filter_dict["subnets"] = {IPNetwork(subnet) for subnet in raw_filter["subnets"]}
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid subnets were provided for subnets filter: {e}")

    if "policy_actions" in raw_filter:
        if not isinstance(raw_filter["policy_actions"], list):
            raise TypeError("policy_actions filter should be a list")
        try:
            filter_dict["policy_actions"] = {MapFilter.PolicyAction[str(policy_action).upper().replace(' ', '_')]
                                             for policy_action in raw_filter["policy_actions"]}
        except KeyError as e:
            raise ValueError(f"Invalid policy_actions were provided: {e}")

    if "ports" in raw_filter:
        if not isinstance(raw_filter["ports"], list):
            raise TypeError("ports filter should be a list")
        ports_filter = set()
        try:
            for port_element in raw_filter["ports"]:
                if isinstance(port_element, str):
                    start, end = port_element.split('-')
                    ports_filter.add(PortRange(int(start), int(end)))
                elif isinstance(port_element, int):
                    if not 1 <= port_element <= 65535:
                        raise ValueError(f"{port_element} is not a valid port")
                    ports_filter.add(port_element)
                else:
                    raise ValueError(f"{repr(port_element)} is not a valid port")
            filter_dict["ports"] = ports_filter
        except ValueError as e:
            raise ValueError(f"Invalid ports were provided: {e}")

    if "policy_rulesets" in raw_filter:
        if not isinstance(raw_filter["policy_rulesets"], list):
            raise TypeError("policy_rulesets filter should be a list")
        try:
            filter_dict["policy_rulesets"] = {str(ruleset) for ruleset in raw_filter["policy_rulesets"]}
        except ValueError as e:
            raise ValueError(f"Invalid policy_rulesets were provided: {e}")

    if "processes" in raw_filter:
        if not isinstance(raw_filter["processes"], list):
            raise TypeError("processes filter should be a list")
        try:
            filter_dict["processes"] = {str(process) for process in raw_filter["processes"]}
        except ValueError as e:
            raise ValueError(f"Invalid processes were provided: {e}")

    if "protocols" in raw_filter:
        if not isinstance(raw_filter["protocols"], list):
            raise TypeError("protocols filter should be a list")
        try:
            filter_dict["protocols"] = {MapFilter.Protocol(protocol.upper()) for protocol in raw_filter["protocols"]}
        except ValueError as e:
            raise ValueError(f"Invalid protocols were provided: {e}")

    if "assets" in raw_filter:
        if not isinstance(raw_filter["assets"], list):
            raise TypeError("assets filter should be a list")
        try:
            filter_dict["assets"] = {str(asset) for asset in raw_filter["assets"]}
        except ValueError as e:
            raise ValueError(f"Invalid assets were provided: {e}")

    if "policy_rules" in raw_filter:
        if not isinstance(raw_filter["policy_rules"], list):
            raise TypeError("policy_rules filter should be a list")
        try:
            filter_dict["policy_rules"] = {str(rule) for rule in raw_filter["policy_rules"]}
        except ValueError as e:
            raise ValueError(f"Invalid policy_rules were provided: {e}")

    if "label_groups" in raw_filter:
        if not isinstance(raw_filter["label_groups"], list):
            raise TypeError("label_groups filter should be a list")
        try:
            filter_dict["label_groups"] = {ShortLabelGroup.from_str(label_group) for label_group in
                                           raw_filter["label_groups"]}
        except ValueError as e:
            raise ValueError(f"Invalid label_groups were provided: {e}")

    if "connections_from_subnets" in raw_filter:
        if not isinstance(raw_filter["connections_from_subnets"], list):
            raise TypeError("connections_from_subnets filter should be a list")
        try:
            filter_dict["connections_from_subnets"] = {IPNetwork(subnet) for subnet in
                                                       raw_filter["connections_from_subnets"]}
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid connections_from_subnets were provided for subnets filter: {e}")

    if "connections_to_subnets" in raw_filter:
        if not isinstance(raw_filter["connections_to_subnets"], list):
            raise TypeError("connections_to_subnets filter should be a list")
        try:
            filter_dict["connections_to_subnets"] = {IPNetwork(subnet) for subnet in
                                                     raw_filter["connections_to_subnets"]}
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid connections_to_subnets were provided for subnets filter: {e}")

    if "address_classifications" in raw_filter:
        if not isinstance(raw_filter["address_classifications"], list):
            raise TypeError("address_classifications filter should be a list")
        try:
            filter_dict["address_classifications"] = \
                {MapFilter.AddressClassification[str(address_classification).upper().replace(' ', '_')] for
                 address_classification in raw_filter["address_classifications"]}
        except KeyError as e:
            raise ValueError(f"Invalid values provided for the address_classifications filter: {e}")

    if "labels" in raw_filter:
        if not isinstance(raw_filter["labels"], list):
            raise TypeError("labels filter should be a list")

        labels_intersections = set()
        try:
            for labels_string in raw_filter["labels"]:
                labels_intersections.add(LabelsIntersection.from_str(labels_string))
            filter_dict["labels"] = LabelsExpression(labels_intersections)
        except ValueError as e:
            raise ValueError(f"Invalid values provided for the labels filter: {e}")

    if "connections_from_labels" in raw_filter:
        if not isinstance(raw_filter["connections_from_labels"], list):
            raise TypeError("connections_from_labels filter should be a list")

        labels_intersections = set()
        try:
            for labels_string in raw_filter["connections_from_labels"]:
                labels_intersections.add(LabelsIntersection.from_str(labels_string))
            filter_dict["connections_from_labels"] = LabelsExpression(labels_intersections)
        except ValueError as e:
            raise ValueError(f"Invalid values provided for the connections_from_labels filter: {e}")

    if "connections_to_labels" in raw_filter:
        if not isinstance(raw_filter["connections_to_labels"], list):
            raise TypeError("connections_to_labels filter should be a list")

        labels_intersections = set()
        try:
            for labels_string in raw_filter["connections_to_labels"]:
                labels_intersections.add(LabelsIntersection.from_str(labels_string))
            filter_dict["connections_to_labels"] = LabelsExpression(labels_intersections)
        except ValueError as e:
            raise ValueError(f"Invalid values provided for the connections_to_labels filter: {e}")

    return MapFilter(**filter_dict)
