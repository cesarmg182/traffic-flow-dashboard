from datetime import datetime
from typing import Dict, List

import xlsxwriter

from aggregated_flows_export.common.models.aggregated_flow import AggregatedFlow


def save_flows_to_xlsx(flows: List[AggregatedFlow], yaml_args: Dict, out_file_name: str,
                       report_flows_start_time: datetime, report_flows_end_time: datetime, map_link: str,
                       flows_are_exported_from_a_pre_existing_map, aggregation_keys: List[str] = None) -> None:
    """
    Save the processed flows and the script arguments to an xlsx file.
    :param flows: The processed flows to save
    :param yaml_args: parsed args provided as dict
    :param map_link: A link to the map from which the flows were exported
    :param out_file_name: The name of the output file
    :param report_flows_start_time: The start time of the flows that are included in the report
    :param report_flows_end_time: The end time of the flows that are included in the report
    :param aggregation_keys: A list of label key's whose values should have a dedicated column in the exported flows CSV
    :param flows_are_exported_from_a_pre_existing_map: Whether flows were exported from a pre existing map or from a
    map that was generated for the report
    """
    with xlsxwriter.Workbook(out_file_name) as workbook:
        bold = workbook.add_format({'bold': True})

        # Flows page
        flows_page = workbook.add_worksheet('Flows')
        header_format = workbook.add_format({'bold': True,
                                             'align': 'center',
                                             'valign': 'vcenter',
                                             'fg_color': '#D7E4BC',
                                             'border': 1})
        row, col = 0, 0
        flows_page.freeze_panes(row + 1, col)  # Freeze the header row
        aggregation_keys = aggregation_keys if aggregation_keys is not None else []
        fieldnames = []
        approved_filed_txt = 'Approved (YES / NO)'
        fieldnames.extend(
            [f'Source {key} Label Value' for key in aggregation_keys])
        fieldnames.extend(['Source Asset',
                           'Source IP',
                           'Source Process',
                           'Source Process Application Name',
                           'Source Additional Labels'])
        fieldnames.extend(
            [f'Destination {key} Label Value' for key in aggregation_keys])
        fieldnames.extend(['Destination Asset',
                           'Destination IP',
                           'Destination Process',
                           'Destination Process Application Name',
                           'Destination Additional Labels',
                           'Protocol',
                           'Destination Ports',
                           'Count',
                           approved_filed_txt])
        flows_page.set_column(col, len(fieldnames), width=28)
        flows_page.autofilter(row, col, len(flows), len(fieldnames))
        for i, header in enumerate(fieldnames):
            flows_page.write(0, col + i, header, header_format)
        row += 1
        # Set 'Approved' column to selection from drop down list of YES / NO
        flows_page.data_validation(row, fieldnames.index(approved_filed_txt), len(flows),
                                   fieldnames.index(approved_filed_txt),
                                   {'validate': 'list', 'source': ['YES', 'NO']})
        for flow in flows:
            flow_dict = flow.to_output_dict()
            for i, field in enumerate(fieldnames):
                flows_page.write(row, col + i, flow_dict.get(field, ""))
            row += 1

        # Arguments page
        args_page = workbook.add_worksheet('Parameters')
        title_format = workbook.add_format({
            'bold': 1,
            'border': 0,
            'align': 'center',
            'valign': 'vcenter',
            'font_size': 12,
            'bg_color': '#D8E4BC'})
        row, col = 0, 0
        args_page.set_column(col, col, width=39)
        args_page.set_column(col + 1, col + 1, width=28)
        args_page.merge_range(row, col, row, col + 4,
                              f"Parameters for {out_file_name}", title_format)
        row += 1
        if map_link:
            if flows_are_exported_from_a_pre_existing_map:
                args_page.write(row, col, "Pre existing map link", bold)
            else:
                args_page.write(row, col, "Saved map link", bold)
            args_page.write(row, col + 1, map_link)
            row += 1
        row += 1
        args_page.write(row, col, "Include Filter", bold)
        args_page.write(row + 1, col, "value")
        for i, (filt, values) in enumerate(yaml_args.get("include_filter", {}).items(), 1):
            args_page.write(row, col + i, filt, bold)
            args_page.write(row + 1, col + i,
                            ', '.join([str(value) for value in values]))
        row += 3
        args_page.write(row, col, "Exclude Filter", bold)
        args_page.write(row + 1, col, "value")
        for i, (filt, values) in enumerate(yaml_args.get("exclude_filter", {}).items(), 1):
            args_page.write(row, col + i, filt, bold)
            args_page.write(row + 1, col + i,
                            ', '.join([str(value) for value in values]))
        row += 3
        args_page.write(row, col, "Flows start time", bold)
        args_page.write(
            row, col + 1, report_flows_start_time.strftime('%Y-%m-%d %H:%M:%S'))
        row += 1
        args_page.write(row, col, "Flows end time", bold)
        args_page.write(
            row, col + 1, report_flows_end_time.strftime('%Y-%m-%d %H:%M:%S'))
        row += 2
        if "aggregation_keys" in yaml_args:
            args_page.write(row, col, "aggregation_keys", bold)
            args_page.write(
                row, col + 1, ', '.join(yaml_args["aggregation_keys"]))
            row += 1
        if "aggregate_similar_flows" in yaml_args:
            args_page.write(row, col, "aggregate_similar_flows", bold)
            args_page.write(row, col + 1, yaml_args["aggregate_similar_flows"])
            row += 1
        if "aggregate_flows_with_different_processes" in yaml_args:
            args_page.write(
                row, col, "aggregate_flows_with_different_processes", bold)
            args_page.write(
                row, col + 1, yaml_args["aggregate_flows_with_different_processes"])
            row += 1
        if "ignore_internal_traffic" in yaml_args:
            args_page.write(row, col, "ignore_internal_traffic", bold)
            args_page.write(row, col + 1, yaml_args["ignore_internal_traffic"])
            row += 1
        if "enhanced_flow_csv_export_is_on" in yaml_args:
            args_page.write(row, col, "enhanced_flow_csv_export_is_on", bold)
            args_page.write(
                row, col + 1, yaml_args["enhanced_flow_csv_export_is_on"])
            row += 1
        if "expand_subnets" in yaml_args:
            args_page.write(row, col, "expand_subnets", bold)
            args_page.write(row, col + 1, yaml_args["expand_subnets"])
            row += 1
        if "expand_internet" in yaml_args:
            args_page.write(row, col, "expand_internet", bold)
            args_page.write(row, col + 1, yaml_args["expand_internet"])
            row += 1
        if "exact_connection_times" in yaml_args:
            args_page.write(row, col, "exact_connection_times", bold)
            args_page.write(row, col + 1, yaml_args["exact_connection_times"])
            row += 1
        if "output_flows_count" in yaml_args:
            args_page.write(row, col, "output_flows_count", bold)
            args_page.write(row, col + 1, yaml_args["output_flows_count"])
            row += 1
