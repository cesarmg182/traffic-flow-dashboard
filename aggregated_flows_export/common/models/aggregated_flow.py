from typing import Dict, List, Tuple, Set


class AggregatedFlow(object):
    """Represent a network flow that can be aggregated with other flows"""

    def __init__(self, src_aggregation_labels: Dict[str, List[str]], src_name: str, src_ip: str, src_process: str,
                 src_application: str, src_additional_labels: List[str], dest_aggregation_labels: Dict[str, List[str]],
                 dest_name: str, dest_ip: str, dest_process: str, dest_application: str,
                 dest_additional_labels: List[str], protocol: str, dest_port: str, count: int,
                 aggregation_keys: List[str], aggregate_flows_with_different_processes: bool):
        """
        :param src_aggregation_labels: Dict containing each aggregation label key mapped to a list of values that the
        source of the flow is labeled with. {"Environment": ["Prod"], "App": ["Ecomm", "Accounting"]}.
        :param src_name: If the source of the flow is an asset - this field will be the asset name. Otherwise, if the
         flow's source is an unmanaged asset, this field will be populated with dns of the source as collected by
         reveal or the ip itself if no dns record was collected for this ip
        :param src_ip: The flow source ip
        :param src_process: The source process of the flow
        :param src_application: The source process application name of the flow
        :param src_additional_labels: All the labels the source IP belongs to that do not match into the
        src_aggregation_labels
        :param dest_aggregation_labels: Dict containing each aggregation label key mapped to a list of values that the
        source of the flow is labeled with. {"Environment": ["Prod"], "App": ["Ecomm", "Accounting"]}.
        :param dest_name: If the destination of the flow is an asset - this field will be the asset name. Otherwise, if
        the flow's destination is an unmanaged asset, this field will be populated with dns of the destination as
        collected by reveal or the ip itself if no dns record was collected for this ip
        :param dest_ip: The flow destination ip
        :param dest_process: The destination process of the flow
        :param dest_application: The destination process application name of the flow
        :param dest_additional_labels: All the labels the destination IP belongs to that do not match into
        dest_aggregation_labels
        :param protocol: The flow's protocol - TCP / UDP
        :param dest_port: The flows dest ports
        :param count: The number of occurrences of the flow
        :param aggregation_keys: The label keys used for aggregation with other flows
        :param aggregate_flows_with_different_processes: Whether this flow can be aggregated with another flow even if
        the other flow's processes and process application name are not identical to the ones of this flow
        """
        self.src_aggregation_labels: Dict[str, Set[str]] = {key: set(values) for key, values in
                                                            src_aggregation_labels.items()}
        self.src_name = src_name
        self.src_ips = src_ip
        self.src_processes: Set[str] = {src_process} if src_process else set()
        self.src_applications: Set[str] = {src_application} if src_application else set()
        self.src_additional_labels: Set[str] = set(src_additional_labels)
        self.dest_aggregation_labels: Dict[str, Set[str]] = {key: set(values) for key, values in
                                                             dest_aggregation_labels.items()}
        self.dest_name = dest_name
        self.dest_ips = dest_ip
        self.dest_processes: Set[str] = {dest_process} if dest_process else set()
        self.dest_applications: Set[str] = {dest_application} if dest_application else set()
        self.dest_additional_labels: Set[str] = set(dest_additional_labels)
        self.protocol = protocol.upper()
        self.dest_port = dest_port
        self.count = count
        self.aggregation_keys = aggregation_keys
        self.aggregate_flows_with_different_processes = aggregate_flows_with_different_processes

    def __repr__(self):
        return str(self.__dict__)

    def is_eligible_for_aggregation(self) -> bool:
        """
        Return True if the flow is eligible to be aggregated with other AggregatedFlows, False otherwise.
        Flow is eligible to be aggregated if it has non-empty values for all the aggregation_keys (both in the src and
        in the dest), protocol and destination ports
        """
        for key in self.aggregation_keys:
            if len(self.src_aggregation_labels.get(key, set())) == 0:
                return False
            if len(self.dest_aggregation_labels.get(key, set())) == 0:
                return False
        if not self.dest_port or not self.protocol:
            return False
        return True

    def get_flow_aggregation_tuple(self) -> Tuple[str]:
        """
        Return the aggregation tuple of the flow.
        Two flows with identical aggregation tuple can be aggregated together
        """
        flow_aggregation_data = []
        for key in self.aggregation_keys:
            flow_aggregation_data.append(', '.join(sorted(self.src_aggregation_labels[key])))
            flow_aggregation_data.append(', '.join(sorted(self.dest_aggregation_labels[key])))
        flow_aggregation_data.append(self.protocol)
        flow_aggregation_data.append(self.dest_port)
        if not self.aggregate_flows_with_different_processes:
            flow_aggregation_data.append(', '.join(sorted(self.src_processes)))
            flow_aggregation_data.append(', '.join(sorted(self.src_applications)))
            flow_aggregation_data.append(', '.join(sorted(self.dest_processes)))
            flow_aggregation_data.append(', '.join(sorted(self.dest_applications)))
        return tuple(flow_aggregation_data)

    def aggregate_flow(self, flow_to_aggregate: 'AggregatedFlow') -> None:
        """Aggregate the data from an additional AggregatedFlow instance into this AggregatedFlow"""
        assert self.aggregation_keys == flow_to_aggregate.aggregation_keys, "Cannot aggregate two flows that do not " \
                                                                            "share the same aggregation keys"
        assert (self.aggregate_flows_with_different_processes ==
                flow_to_aggregate.aggregate_flows_with_different_processes), \
            "The two flows do not have identical values for aggregate_flows_with_different_processes"
        if self.src_name != flow_to_aggregate.src_name:
            self.src_name = "Multiple"
        if self.src_ips != flow_to_aggregate.src_ips:
            self.src_ips = "Multiple"
        self.src_additional_labels.update(flow_to_aggregate.src_additional_labels)
        if self.dest_name != flow_to_aggregate.dest_name:
            self.dest_name = "Multiple"
        if self.dest_ips != flow_to_aggregate.dest_ips:
            self.dest_ips = "Multiple"
        if self.aggregate_flows_with_different_processes:
            self.src_processes.update(flow_to_aggregate.src_processes)
            self.src_applications.update(flow_to_aggregate.src_applications)
            self.dest_processes.update(flow_to_aggregate.dest_processes)
            self.dest_applications.update(flow_to_aggregate.dest_applications)
        self.dest_additional_labels.update(flow_to_aggregate.dest_additional_labels)
        self.count += flow_to_aggregate.count

    def is_internal_flow(self) -> bool:
        """Return True if the values for the source and destination aggregation labels are non empty and identical"""
        for key in self.aggregation_keys:
            src_values = sorted(self.src_aggregation_labels.get(key, set()))
            dest_values = sorted(self.dest_aggregation_labels.get(key, set()))
            if not src_values or not dest_values or src_values != dest_values:
                return False
        return True

    def to_output_dict(self) -> Dict:
        """Return a dictionary containing the AggregatedFlow data in the form it is saved to the excel sheet"""
        flow_dict = {
            "Protocol": self.protocol,
            "Destination Ports": self.dest_port,
            "Source Asset": self.src_name,
            "Source IP": self.src_ips,
            "Source Process": ', '.join(self.src_processes),
            "Source Process Application Name": ', '.join(self.src_applications),
            "Source Additional Labels": ', '.join(self.src_additional_labels),
            "Destination Asset": self.dest_name,
            "Destination IP": self.dest_ips,
            "Destination Process": ', '.join(self.dest_processes),
            "Destination Process Application Name": ', '.join(self.dest_applications),
            "Destination Additional Labels": ', '.join(self.dest_additional_labels),
            "Count": self.count}

        for key in self.aggregation_keys:
            flow_dict[f'Source {key} Label Value'] = ', '.join(sorted(self.src_aggregation_labels.get(key, [])))
            flow_dict[f'Destination {key} Label Value'] = ', '.join(sorted(self.dest_aggregation_labels.get(key, [])))

        return flow_dict
