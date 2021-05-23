"""
    aggregated_flows_export.py - Export filtered and aggregated flows from Centra
    Version: 1.0.4
    Release date: 16/02/2021
"""

import yaml
import sys
import os
import logging

from collections import defaultdict
from pathlib import Path
from datetime import datetime
from getpass import getpass
from argparse import ArgumentParser
from typing import Dict, Union, List, Any, Iterable, Tuple, Set

from aggregated_flows_export.api.guardicore import RESTManagementAPI, ManagementAPIError
from aggregated_flows_export.common.common import get_gc_api, remove_empty_values, validate_python_version
from aggregated_flows_export.common.logger import Logger
from aggregated_flows_export.common.models.aggregated_flow import AggregatedFlow
from aggregated_flows_export.common.maps.utils import generate_saved_map, generate_permalink, \
    get_existing_saved_map_data, export_flows_from_permalink, get_map_filter_from_args
from aggregated_flows_export.common.maps.models import MapFilter
from aggregated_flows_export.common.maps.exceptions import SavedMapException, NoFlowsMatchTheFilter, MapExportTimedOut, \
    GraphGenerationTimedOut, SavedMapIsEmpty
from aggregated_flows_export.common.labels.exceptions import IllegalLabelException, LabelNotFoundInCentra
from .save_flows_to_xlsx import save_flows_to_xlsx

DEFAULT_ARGUMENTS_FILE_LOCATION = Path(os.path.dirname(
    os.path.realpath(__file__))).joinpath("generated_yaml.yaml")
DEFAULT_EXPORT_JOB_NAME = "Aggregated Flows Export *.xlsx"
BASE_LOGGER_NAME = "guardicore"

ACCEPTABLE_YAML_ARGS = {"management_address", "auth_username", "auth_password", "management_port", "flows_start_time",
                        "flows_end_time", "aggregation_keys", "aggregate_similar_flows", "log_verbose",
                        "enhanced_flow_csv_export_is_on", "ignore_internal_traffic", "include_filter",
                        "exclude_filter", "export_file_name", "delete_temporary_map", "expand_internet",
                        "expand_subnets", "pre_existing_map_id", "log_file_path", "exact_connection_times",
                        "output_flows_count", "aggregate_flows_with_different_processes"}

validate_python_version()


class ExportFlowsFromMap:
    """
    This class is intended to export the network flows which match the provided filter and time range from Centra,
    aggregate them (or not) and return a list of aggregated flows.
    """

    def __init__(self,
                 gc_api: RESTManagementAPI,
                 flows_start_time: datetime,
                 flows_end_time: datetime,
                 include_filter: MapFilter,
                 exclude_filter: MapFilter,
                 objects_to_expand: Set[str],
                 aggregation_keys: List[str] = None,
                 aggregate_similar_flows: bool = False,
                 aggregate_flows_with_different_processes: bool = False,
                 ignore_internal_traffic: bool = False,
                 enhanced_flow_csv_export_is_on: bool = False,
                 pre_existing_map_id: str = None,
                 name_for_map_to_generate: str = None,
                 delete_temporary_map: bool = False,
                 exact_connection_times: bool = False,
                 output_flows_count: bool = False):
        """
        :param gc_api: Centra API session object
        :param flows_start_time: The start time that will be used for the map creation. If a pre generated map was
        provided, this param is not used
        :param flows_end_time: The end time that will be used for the map creation. If a pre generated map was
        provided, this param is not used
        :param include_filter: Flows matching this filter will be included in the export
        :param exclude_filter: Flows matching this filter will not be included in the export
        :param objects_to_expand: A set of objects to expand. The common values are:
            'group' - signifies labels
            'subnets' - signifies subnets
            'vm' - signifies managed assets
            'Process' - signifies process objects (processes with the same name on the same vm are aggregated, so they
                                                   might also require expanding)
            'internet' - signifies internet sources and destinations
        :param aggregation_keys: A list of label key's whose values should have a dedicated column in the exported
            flows CSV, and according which the flows can be aggregated
        :param aggregate_similar_flows: If true, flows whose values for all of the aggregation_keys are the same and
        have similar protocol, port, process and application will be aggregated together. The Source Asset, Source IP,
        destination Asset and Destination IP values of an aggregated processed flow will be set to 'Multiple'. Flows
        will be considered similar only if they have values for all the aggregation_keys is missing.
        :param aggregate_flows_with_different_processes: Whether flows with different processes and process application
        names but all else aggregation fields identical will be aggregated together or not.
        :param ignore_internal_traffic: If true, flows whose source values for all of the the aggregation_keys are
        identical to the destination values of the aggregation_keys (for example same Environment, App, Role) will be
        ignored and not processed. Flows without any values for the aggregation_keys will not be ignored.
        :param enhanced_flow_csv_export_is_on: set to true if query_elastic_for_flow_data is turned ON in the customer's
        management, which means the flows csv exported from Centra contain a value for the protocol field.
        :param pre_existing_map_id: An id of a pre existing map to export flows from. If not provided, a new map will
        be generated according to the provided filter
        :param name_for_map_to_generate: A name for the map to generate. Irrelevant if pre_existing_map_id was provided
        :param delete_temporary_map: Whether to delete the map generated for the report creation. Irrelevant if
        pre_existing_map_id was provided
        :param exact_connection_times: Whether the map should be created with the "Exact connection time" flag. If this
        is False, the map's start and end time will be rounded by Centra to the closest aggregated flows index time.
        Passing True might cause the export to take longer, or even to fail in very large exports.
        :param output_flows_count: Whether to include flows count in the export. Passing True might cause the export to
        take longer, or even to fail in very large exports.
        """
        self.logger = logging.getLogger(
            'guardicore.' + self.__class__.__name__)
        self.gc_api = gc_api
        self.flows_start_time = flows_start_time
        self.flows_end_time = flows_end_time
        self.include_filter = include_filter
        self.exclude_filter = exclude_filter
        self.objects_to_expand = objects_to_expand
        self.aggregation_keys = aggregation_keys if aggregation_keys else []
        self.aggregate_similar_flows = aggregate_similar_flows
        self.aggregate_flows_with_different_processes = aggregate_flows_with_different_processes
        self.ignore_internal_traffic = ignore_internal_traffic
        self.enhanced_flow_csv_export_is_on = enhanced_flow_csv_export_is_on
        self.pre_existing_map_id = pre_existing_map_id
        self.map_to_generate_name = name_for_map_to_generate
        self.delete_temporary_map = delete_temporary_map
        self.exact_connection_times = exact_connection_times
        self.output_flows_count = output_flows_count

        self.flows_are_exported_from_a_pre_existing_map = pre_existing_map_id is not None
        self.map_data = None

    def get_aggregated_flows(self) -> List[AggregatedFlow]:
        """
        The main function of the class, returns a list of AggregatedFlows that matched the filters within the provided
        time range, according to the provided init configuration params
        :raises AssertionError: In case self.gc_api is not a valid RESTManagementAPI object.
        :raises LabelNotFoundInCentra: In case the label which was mentioned in the provided filtered was not found in
        Centra
        """
        try:
            include_filter = self.include_filter.to_api_format(self.gc_api)
        except (AssertionError, LabelNotFoundInCentra) as e:
            raise type(e)(f"Failed to process map include filters: {e}")
        try:
            exclude_filter = self.exclude_filter.to_api_format(self.gc_api)
        except (AssertionError, LabelNotFoundInCentra) as e:
            raise type(e)(f"Failed to process map exclude filters: {e}")

        try:
            self.map_data = self.get_saved_map(include_filter, exclude_filter)
        except SavedMapIsEmpty:
            self.logger.info("The saved map is empty. No flows to export")
            return []
        try:
            aggregated_flows = self.export_flows_from_map(
                self.map_data, include_filter, exclude_filter)
        except NoFlowsMatchTheFilter:
            self.logger.info(
                "There are no flows matching the provided filter. No flows to export")
            return []

        if self.delete_temporary_map and not self.flows_are_exported_from_a_pre_existing_map:
            logger.info(
                f"Deleting the temporary saved map {self.map_data['name']}")
            try:
                self.gc_api.delete_saved_map(self.map_data['id'])
                logger.info(f"Successfully deleted the map")
            except ManagementAPIError as e:
                logger.error(f"Could not delete the temporary map: {repr(e)}")

        return aggregated_flows

    def get_saved_map(self, include_filter: Dict[str, Any], exclude_filter: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get or create a saved map to export flows from. In case the id of an existing map was provided, this method
        will try to query Centra for the pre generated map data. Otherwise, a new map will be generated according to
        the provided filter
        :param include_filter: Flows matching this filter will be included in the map. The format of this parameter
        should be the format Centra API accepts for filters
        :param exclude_filter: Flows matching this filter will be excluded from the map. The format of this parameter
        should be the format Centra API accepts for filters
        :return: The map's data dict, as it is returned from Centra API
        """
        if self.flows_are_exported_from_a_pre_existing_map:
            logger.info(
                f"Using the existing map with map id {self.pre_existing_map_id} for the flows export")
            return get_existing_saved_map_data(self.gc_api, self.pre_existing_map_id)
        else:
            logger.info(f"Generating map '{self.map_to_generate_name}'.")
            return generate_saved_map(gc_api=self.gc_api,
                                      map_name=self.map_to_generate_name,
                                      start_time=self.flows_start_time,
                                      end_time=self.flows_end_time,
                                      include_filter=include_filter,
                                      exclude_filter=exclude_filter,
                                      time_resolution=self.exact_connection_times,
                                      include_flow_hit_count=self.output_flows_count,
                                      delete_empty_saved_maps=self.delete_temporary_map)

    def export_flows_from_map(self,
                              map_data: Dict[str, Any],
                              include_filter: Dict[str, Any],
                              exclude_filter: Dict[str, Any]) -> List[AggregatedFlow]:
        """
        export the flows that match the provided filter from the map.
        :param map_data: The map's data dict, as it is returned from Centra API
        :param include_filter: Flows matching this filter will be included in the map. The format of this parameter
        should be the format Centra API accepts for filters
        :param exclude_filter: Flows matching this filter will be excluded from the map. The format of this parameter
        should be the format Centra API accepts for filters
        :raises NoFlowsMatchTheFilter: In case no flows in the provided map matched the provided filter
        :return: The map's data dict, as it is returned from Centra API
        """
        aggregated_flows = []
        if not self.enhanced_flow_csv_export_is_on:
            protocols = include_filter.get("protocols") if include_filter.get(
                "protocols") else ["TCP", "UDP"]
        else:
            protocols = [""]

        for protocol in protocols:
            logger.info(
                f"Generating permalink for {protocol + ' ' if protocol else ''}connections")
            if protocol:
                include_filter["protocols"] = [protocol]
            try:
                permalink_id = generate_permalink(self.gc_api,
                                                  map_id=map_data["id"],
                                                  start_time=map_data["start_time_filter"],
                                                  end_time=map_data["end_time_filter"],
                                                  include_filter=include_filter,
                                                  exclude_filter=exclude_filter,
                                                  objects_to_expand=self.objects_to_expand,
                                                  zoom_in_count=1)
            except NoFlowsMatchTheFilter:
                self.logger.info(f"There are no {protocol + ' ' if protocol else ''}flows for that matched the "
                                 f"provided filter in the provided time range")
                continue
            except GraphGenerationTimedOut:
                self.logger.warning(f"The Graph request timed out")
                self.logger.info(
                    "Trying to generate permalink without expanding VMs")
                objects_to_expand = {obj_type for obj_type in self.objects_to_expand
                                     if obj_type not in ["vm", "Process"]}
                permalink_id = generate_permalink(self.gc_api, map_data["id"], map_data["start_time_filter"],
                                                  map_data["end_time_filter"],
                                                  include_filter=include_filter,
                                                  exclude_filter=exclude_filter,
                                                  objects_to_expand=objects_to_expand)
            if protocol:
                logger.info(f"Successfully generated permalink for {protocol} connections. "
                            f"Permalink id: {permalink_id}")
            else:
                logger.info(
                    f"Successfully generated permalink. Permalink id: {permalink_id}")
            logger.info(f"Downloading flows from permalink id {permalink_id}")
            raw_flows = export_flows_from_permalink(self.gc_api, permalink_id)

            aggregated_flows.extend(self.process_raw_flows(
                raw_flows, override_flows_protocol=protocol))

        if not aggregated_flows:
            raise NoFlowsMatchTheFilter()

        return self.sort_aggregated_flows_by_count(aggregated_flows)

    def process_raw_flows(self, raw_flows: Iterable[Dict[str, str]],
                          override_flows_protocol: str = "") -> List[AggregatedFlow]:
        """
        Process the raw flows and generate a list of flows to export, and generate a list of AggregatedFlows.
        :param raw_flows: An iterable containing all the raw flows to process
        :param override_flows_protocol: If provided, the flow's protocol (TCP / UDP) will be overridden with the
        provided value. This is necessary when `enhanced_flow_csv_export` feature is not ON in Centra configurations,
        the flow's protocol is not exported to the CSV so it needs to be set artificially.
        :return: The list of processed flows
        """
        aggregated_flows: List[AggregatedFlow] = []
        flow_aggregation_tuple_to_flow_index: Dict[Tuple[str], int] = {}

        for raw_flow in raw_flows:
            all_src_labels = raw_flow['source_labels'].split(
                ',') if raw_flow.get('source_labels') else []
            src_aggregation_labels: Dict[str, List[str]] = defaultdict(list)
            src_additional_labels = []
            for label in all_src_labels:
                try:
                    # ValueError will be raised if there more or less than 1 ':'
                    key, value = label.split(': ')
                except ValueError:
                    raise IllegalLabelException(
                        f"The label {label} is illegal")
                if key in self.aggregation_keys:
                    src_aggregation_labels[key].append(value)
                else:
                    src_additional_labels.append(label)
            src_asset = raw_flow.get('source_asset_name', "")
            src_ip = raw_flow['source_connection_ip_address'] if raw_flow.get('source_connection_ip_address') else \
                raw_flow.get('source_ip_addresses', "")
            src_application = raw_flow.get('source_application', "")
            src_process = raw_flow['source_process_full_path'] if raw_flow.get('source_process_full_path') else \
                raw_flow.get('source_process_name', "")
            if "unknown client" in src_process.lower():  # Get rid of unknown source processes
                src_process = ""
            if "unknown client" in src_application.lower():  # Get rid of unknown source application
                src_application = ""
            all_dest_labels = raw_flow['destination_labels'].split(
                ',') if raw_flow.get('destination_labels') else []
            dest_aggregation_labels: Dict[str, List[str]] = defaultdict(list)
            dest_additional_labels = []
            for label in all_dest_labels:
                try:
                    # ValueError will be raised if there more or less than 1 ':'
                    key, value = label.split(': ')
                except ValueError:
                    raise IllegalLabelException(
                        f"The label {label} is illegal")
                if key in self.aggregation_keys:
                    dest_aggregation_labels[key].append(value)
                else:
                    dest_additional_labels.append(label)
            dest_asset = raw_flow.get('destination_asset_name', "")
            dest_ip = raw_flow['destination_connection_ip_address'] if \
                raw_flow.get('destination_connection_ip_address') else raw_flow.get('destination_ip_addresses', "")
            dest_application = raw_flow.get('destination_application', "")
            dest_process = raw_flow['destination_process_full_path'] if raw_flow.get(
                'destination_process_full_path') else \
                raw_flow.get('destination_process_name', "")
            if "unknown server" in dest_process.lower():  # Get rid of unknown destination processes
                dest_process = ""
            if "unknown server" in dest_application.lower():  # Get rid of unknown destination application
                dest_application = ""
            protocol = override_flows_protocol if override_flows_protocol else raw_flow.get(
                'ip_protocol', "")
            count = int(raw_flow["count"]) if raw_flow["count"] else ""
            for dest_port in raw_flow['destination_ports'].split(','):
                flow = AggregatedFlow(src_aggregation_labels, src_asset, src_ip, src_process, src_application,
                                      src_additional_labels, dest_aggregation_labels, dest_asset, dest_ip, dest_process,
                                      dest_application, dest_additional_labels, protocol, dest_port, count,
                                      self.aggregation_keys, self.aggregate_flows_with_different_processes)

                if self.ignore_internal_traffic and flow.is_internal_flow():
                    continue

                if self.aggregate_similar_flows and flow.is_eligible_for_aggregation():
                    flow_aggregation_tuple = flow.get_flow_aggregation_tuple()
                    if flow_aggregation_tuple in flow_aggregation_tuple_to_flow_index:
                        similar_flow_index = flow_aggregation_tuple_to_flow_index[
                            flow_aggregation_tuple]
                        similar_flow = aggregated_flows[similar_flow_index]
                        similar_flow.aggregate_flow(flow)
                    else:
                        flow_aggregation_tuple_to_flow_index[flow_aggregation_tuple] = len(
                            aggregated_flows)
                        aggregated_flows.append(flow)
                else:
                    aggregated_flows.append(flow)

        return aggregated_flows

    @staticmethod
    def sort_aggregated_flows_by_count(aggregated_flows: List[AggregatedFlow]) -> List[AggregatedFlow]:
        """ Return a list of aggregated flows sorted by flow occurrences count """
        return sorted(aggregated_flows, key=lambda f: f.count, reverse=True)


def get_centra_login_details(management_address, auth_username, auth_password,
                             management_port) -> Dict[str, Union[str, int]]:
    """
    Get Centra login details according to the following priority:
    1. Credentials that were provided as command line arguments
    2. Credentials that were provided in the arguments yaml file
    3. If the authentication user's password was not provided in the yaml file, prompt the user asking for the password.
    :return: A dictionary containing Centra login details
    """
    centra_login_details = dict()
    centra_login_details["management_address"] = command_line_args.management_address if \
        command_line_args.management_address else management_address
    centra_login_details["auth_username"] = command_line_args.auth_username if \
        command_line_args.auth_username else auth_username
    if not auth_password:
        auth_password = getpass(
            f"Please provide the password for the user {centra_login_details['auth_username']}: ")
    centra_login_details["auth_password"] = auth_password
    centra_login_details["management_port"] = management_port
    return centra_login_details


def read_yaml_args_file(args_file_path: Path) -> Dict[str, Union[str, int, bool, List, Dict, datetime]]:
    """Read arguments from yaml file, stripping empty values or nested empty values"""
    with open(args_file_path, 'r') as f:
        return remove_empty_values(yaml.safe_load(f))


def validate_args(args: Dict[str, Union[str, int, bool, List, Dict, datetime]]) -> None:
    """
    Validate the script arguments read from the yaml file and the provided command line arguments.
    If invalid or missing arguments are detected, AssertionError will be raised.
    :param args: arguments read from the args yaml file
    """

    unknown_args = [arg for arg in args if arg not in ACCEPTABLE_YAML_ARGS]
    assert not unknown_args, f"Unexpected argument(s) were provided in the yaml: {', '.join(unknown_args)}"

    assert "management_address" in args or command_line_args.management_address, \
        "management_address parameter must be provided in the yaml or via command line arguments"
    assert "https://" not in args.get("management_address", ""), \
        "management_address parameter mustn't contain https://"
    assert "auth_username" in args or command_line_args.auth_username, \
        "auth_username parameter must be provided in the yaml or via command line arguments"
    if "auth_password" in args:
        assert isinstance(args["auth_password"],
                          str), "auth_password parameter must be a string"
    if "management_port" in args:
        assert isinstance(
            args["management_port"], int), "management_port parameter must be an integer"
        assert 1 <= args["management_port"] <= 65535, "management_port parameter must be between 1 to 65535"

    if "export_file_name" in args:
        assert isinstance(args["export_file_name"],
                          str), "export_file_name parameter must be a string"
    if "log_verbose" in args:
        assert isinstance(args["log_verbose"],
                          bool), "log_verbose must be True or False"
    if "log_file_path" in args:
        assert isinstance(args["log_file_path"],
                          str), "log_file_path must be a string"
    if "delete_temporary_map" in args:
        assert isinstance(args["delete_temporary_map"],
                          bool), "delete_temporary_map must be True or False"

    if "pre_existing_map_id" in args:
        assert isinstance(args["pre_existing_map_id"],
                          str), "pre_existing_map_id parameter must be a string"
    assert isinstance(args.get("flows_start_time"), datetime), \
        "flows_start_time parameter must be provided in the yaml and must be in the format YYYY-MM-DD HH:MM:SS"
    assert isinstance(args.get("flows_end_time"), datetime), \
        "flows_end_time parameter must be provided in the yaml and must be in the format YYYY-MM-DD HH:MM:SS"
    if "expand_subnets" in args:
        assert isinstance(args["expand_subnets"],
                          bool), "expand_subnets must be True or False"
    if "expand_internet" in args:
        assert isinstance(args["expand_internet"],
                          bool), "expand_internet must be True or False"
    if "enhanced_flow_csv_export_is_on" in args:
        assert isinstance(args["enhanced_flow_csv_export_is_on"], bool), \
            "enhanced_flow_csv_export_is_on must be True or False"

    assert isinstance(args.get("include_filter", {}),
                      dict), "include_filter parameter must be a dictionary"
    try:
        _ = get_map_filter_from_args(args["include_filter"])
    except (ValueError, TypeError, AttributeError) as e:
        raise AssertionError(
            f"include_filter parameter has illegal value: {e}")
    assert isinstance(args.get("exclude_filter", {}),
                      dict), "exclude_filter parameter must be a dictionary"
    try:
        _ = get_map_filter_from_args(args["exclude_filter"])
    except (ValueError, TypeError, AttributeError) as e:
        raise AssertionError(
            f"exclude_filter parameter has illegal value: {e}")

    if "aggregation_keys" in args:
        assert isinstance(args["aggregation_keys"],
                          list), "aggregation_keys parameter must be a list"
        for key in "aggregation_keys":
            assert isinstance(key, str), f"aggregation_key {key} is not string"
    if "aggregate_similar_flows" in args:
        assert isinstance(args["aggregate_similar_flows"],
                          bool), "aggregate_similar_flows must be True or False"
    if "ignore_internal_traffic" in args:
        assert isinstance(args["ignore_internal_traffic"],
                          bool), "ignore_internal_traffic must be True or False"
    if "aggregate_flows_with_different_processes" in args:
        assert isinstance(args["aggregate_flows_with_different_processes"], bool), \
            "aggregate_flows_with_different_processes must be True or False"
    if "exact_connection_times" in args:
        assert isinstance(args["exact_connection_times"],
                          bool), "exact_connection_times must be True or False"
    if "output_flows_count" in args:
        assert isinstance(args["output_flows_count"],
                          bool), "exact_connection_times must be True or False"


def generate_export_job_name(export_file_name: str) -> str:
    """
    Return a name for the export job, based on the current time. The name will be used as the map's name and as the
    name of the exported CSV file. '*' signed will be replaced with current date and time.
    """
    return export_file_name.replace("*", datetime.now().strftime('%Y-%m-%d %H-%M-%S'))


def get_args_parser() -> ArgumentParser:
    """Return a command line argument parser for the script"""
    arg_parser = ArgumentParser(
        description="Export filtered and aggregated flows from Centra")
    arg_parser.add_argument("-m", "--management_address",
                            help="Management server FQDN or IP")
    arg_parser.add_argument("-u", "--auth_username",
                            help="Centra username to use for API authentication")
    arg_parser.add_argument("--management_port", help="Specify non-default port to connect to Centra API", type=int,
                            default=443)
    arg_parser.add_argument("-a", "--args_file", default=DEFAULT_ARGUMENTS_FILE_LOCATION,
                            help="Specify non-default location to search the yaml file containing the script arguments "
                                 f"(default is {DEFAULT_ARGUMENTS_FILE_LOCATION} in the script's directory)")
    arg_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Log verbose information")
    return arg_parser


def main():
    """ The main function of the script """
    centra_login_details = get_centra_login_details(yaml_args.get("management_address"), yaml_args.get("auth_username"),
                                                    yaml_args.get("auth_password"), yaml_args.get("management_port"))
    export_job_name = generate_export_job_name(
        yaml_args.get("export_file_name", DEFAULT_EXPORT_JOB_NAME))
    objects_to_expand = {"vm", "Process"}
    if yaml_args.get("expand_subnets", True):
        objects_to_expand.add("subnet")
    if yaml_args.get("expand_internet", True):
        objects_to_expand.add("internet")
    try:
        with get_gc_api(**centra_login_details) as gc_api:
            flows_exporter = ExportFlowsFromMap(
                gc_api=gc_api,
                flows_start_time=yaml_args["flows_start_time"],
                flows_end_time=yaml_args["flows_end_time"],
                include_filter=get_map_filter_from_args(
                    yaml_args.get("include_filter", {})),
                exclude_filter=get_map_filter_from_args(
                    yaml_args.get("exclude_filter", {})),
                objects_to_expand=objects_to_expand,
                aggregation_keys=yaml_args.get("aggregation_keys", []),
                aggregate_similar_flows=yaml_args.get(
                    "aggregate_similar_flows", False),
                aggregate_flows_with_different_processes=yaml_args.get("aggregate_flows_with_different_processes",
                                                                       False),
                ignore_internal_traffic=yaml_args.get(
                    "ignore_internal_traffic", False),
                enhanced_flow_csv_export_is_on=yaml_args.get(
                    "enhanced_flow_csv_export_is_on", False),
                pre_existing_map_id=yaml_args.get("pre_existing_map_id"),
                name_for_map_to_generate=f"Generated Map for {export_job_name}",
                delete_temporary_map=yaml_args.get(
                    "delete_temporary_map", False),
                exact_connection_times=yaml_args.get(
                    "exact_connection_times", False),
                output_flows_count=yaml_args.get("output_flows_count", False)
            )
            try:
                flows = flows_exporter.get_aggregated_flows()
            except MapExportTimedOut:
                logger.error(
                    "Could not export the flows because the flows export request has timed out")
                logger.info("Try to set expand_subnets and expand_internet parameters to False, or change the filter "
                            "to reduce the number of flows exported")
                sys.exit(1)
            except IllegalLabelException as e:
                logger.error(f"An illegal label was found in Centra: {e}.")
                logger.info(
                    f"This can be caused in case a label in Centra contains a comma.")
                logger.info("Please reach for Guardicore support")
                sys.exit(1)
            except (AssertionError, LabelNotFoundInCentra, SavedMapException) as e:
                logger.error(
                    f"An error occurred while trying to export the flows from the map: {e}")
                sys.exit(1)
            except ManagementAPIError as e:
                logger.error(f"Centra API error: {repr(e)}")
                logger.info("Could not export flows from the map. Aborting..")
                sys.exit(1)

            if not flows:
                logger.info("No flows to export. Exiting")
                sys.exit(0)

            if flows_exporter.flows_are_exported_from_a_pre_existing_map or not flows_exporter.delete_temporary_map:
                management_address = centra_login_details['management_address']
                management_port = centra_login_details.get('management_port')
                management_full_address = \
                    f"{management_address}:{management_port}" if management_port else management_address
                map_link = f"https://{management_full_address}/overview/reveal/explore?" \
                           f"saved_map_id={flows_exporter.map_data['id']}&" \
                           f"start_time={flows_exporter.map_data['start_time_filter']}&" \
                           f"end_time={flows_exporter.map_data['end_time_filter']}"
            else:
                map_link = ""
            logger.info(f"Writing the flows to '{export_job_name}'")
            flows_start_time = datetime.fromtimestamp(
                int(flows_exporter.map_data["start_time_filter"]) / 1000)
            flows_end_time = datetime.fromtimestamp(
                int(flows_exporter.map_data["end_time_filter"]) / 1000)
            try:
                save_flows_to_xlsx(flows, yaml_args,
                                   export_job_name, flows_start_time, flows_end_time, map_link,
                                   flows_exporter.flows_are_exported_from_a_pre_existing_map,
                                   aggregation_keys=flows_exporter.aggregation_keys)
            except IOError as e:
                logger.error(
                    f"Could not write flows to '{export_job_name}': {e.strerror}")
                sys.exit(1)
            logger.info(f"Successfully saved the flows to '{export_job_name}'")
            if flows_exporter.flows_are_exported_from_a_pre_existing_map or not flows_exporter.delete_temporary_map:
                logger.info(
                    f"Link to the map in centra used to generate the flows export: {map_link}")
    except ManagementAPIError as error:
        logger.error(f"Could not connect to Centra API: {repr(error)}")
        logger.info("Aborting..")
        sys.exit(1)


command_line_args = get_args_parser().parse_args()
try:
    yaml_args = read_yaml_args_file(Path(command_line_args.args_file))
    validate_args(yaml_args)
except IOError as err:
    print(
        f"Could not read args from the file {command_line_args.args_file}: {err.strerror}")
    sys.exit(1)
except AssertionError as err:
    print(f"Invalid or missing arguments were found in the yaml file: {err}")
    sys.exit(1)
except yaml.scanner.ScannerError as err:
    print(
        f"Could not parse {command_line_args.args_file}: {err.problem} in line {err.context_mark.line}")
    sys.exit(1)

if command_line_args.verbose or yaml_args.get("log_verbose"):
    log_level = logging.DEBUG
else:
    log_level = logging.INFO
log_file = Path(yaml_args["log_file_path"]) if yaml_args.get(
    "log_file_path") else None

log_verbose = command_line_args.verbose or yaml_args.get("log_verbose")
logger = Logger(logger_name=BASE_LOGGER_NAME,
                log_level=log_level, log_file_path=log_file)

if __name__ == "__main__":
    main()
    sys.exit(0)
