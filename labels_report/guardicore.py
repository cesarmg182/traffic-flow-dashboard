import calendar
import datetime
from functools import wraps
import json
import logging
import requests
from requests.auth import AuthBase
try:
    # Python 3
    from urllib.parse import urljoin
except ImportError:
    # Python 2
    from urlparse import urljoin
try:
    import urllib3
    # Disable InsecureRequestWarning (best effort)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except AttributeError:
    pass

__author__ = 'Lior'


TIME_FORMAT_STRING = "%Y/%m/%d %H:%M:%S.%f"  # this should be parsable by dateutil.parser
AUTHENTICATION_ERROR_HTTP_STATUS_CODE = 403
MANAGEMENT_REST_API_PORT = 443
NEW_REST_API_BASE_URL = '/api/v3.0/'


class ManagementAPIError(Exception):
    def __init__(self, message):
        super(ManagementAPIError, self).__init__(message)


class RESTAuthenticationError(ManagementAPIError):
    def __init__(self, response):
        data = response.json()
        super(RESTAuthenticationError, self).__init__('%s: %s' % (data['error'],
                                                                  data['description']))
        self.data = data


class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime(TIME_FORMAT_STRING)
            # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


class JWTAuth(AuthBase):
    """Attaches JWT Authentication to the given Request object."""
    def __init__(self, token):
        # setup any auth-related data here
        if token is None:
            raise ManagementAPIError("REST Token not set!")
        self.token = token

    def __call__(self, r):
        # modify and return the request
        r.headers['Authorization'] = 'Bearer ' + self.token
        return r


def rest_auto_reconnect():
    def decorator(f):
        @wraps(f)
        def decorated(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except RESTAuthenticationError as e:
                if not self.rest_auth_enabled or not self.auto_reconnect:
                    # either this is an authentication request which failed,
                    # or authentication is disabled but the server probably thinks authentication *is* required.
                    raise

                self.logger.error('Rest authentication error: %s', e.message)
                self.logger.info("Token might have expired; re-authenticating")
                self.connect()
                return f(self, *args, **kwargs)

        return decorated

    return decorator


def datetime_to_timestamp(dt):
    """
    Convert a datetime object to timestamp in ms since epoch (which is the format
     used to query management).
    :param dt: datetime timestamp
    :return: dt as milliseconds since epoch
    """
    return int(calendar.timegm(dt.timetuple()) * 1000 + dt.microsecond / 1000)


class RESTManagementAPI(object):
    def __init__(self, management_host, username=None, password=None, rest_auth_enabled=True,
                 auto_connect=True, auto_reconnect=True, port=MANAGEMENT_REST_API_PORT,
                 proxy_host=None, proxy_port=None, proxy_username=None, proxy_password=None, allow_2fa_auth=False):

        self.logger = logging.getLogger('guardicore.RESTManagementAPI')
        self.callback_func = None
        self.management_host = management_host

        self.http_server_root = 'https://%s:%d' % (self.management_host, int(port))

        self.proxies = {}
        if proxy_host:
            if proxy_username:
                proxy_auth = '{}:{}@'.format(proxy_username, proxy_password)
            else:
                proxy_auth = ''

            proxy = 'http://{}{}:{}'.format(proxy_auth, proxy_host, proxy_port)

            self.logger.debug('Using proxy: {}'.format(proxy))
            self.proxies['http'] = proxy
            self.proxies['https'] = proxy

        self._requests_session = requests.Session()
        self._requests_session.verify = False
        self._requests_session.proxies = self.proxies

        self.json_encoder = DatetimeEncoder()

        self.token = None
        self.rest_username = username
        self.rest_password = password
        self.rest_auth_enabled = rest_auth_enabled
        self.auto_connect = auto_connect
        self.auto_reconnect = auto_reconnect
        self.allow_2fa_auth = allow_2fa_auth
        self.authentication_handler = self.rest_authenticate

        if self.rest_auth_enabled and self.auto_connect:
            self.connect()

    def connect(self):
        self.authentication_handler(self.rest_username, self.rest_password)

    def set_token(self, token):
        """
        Set JWT token, used for authentication with REST API
        :param token:
        """
        self.logger.debug("Setting REST token")
        self.token = token
        self._requests_session.auth = JWTAuth(self.token)  # so others can use this session

    def rest_authenticate(self, rest_username, rest_password):
        """
        Perform JWT authentication through management REST API with username/password
        :param rest_username:
        :param rest_password:
        """
        self.logger.debug("REST Authenticating")
        response = self.json_query(uri=urljoin(NEW_REST_API_BASE_URL, 'authenticate'),
                                   method='POST',
                                   data={'username': rest_username, 'password': rest_password},
                                   authenticate=False)
        if 'access_token' in response:
            token = response['access_token']
        elif response.get("2fa_required", False) and self.allow_2fa_auth:
            self.logger.info("2FA Authentication is needed.")
            temp_token = response["2fa_temp_token"]
            access_code = input("Please supply 2fa access code for user {}: ".format(rest_username))
            token = self.rest_2fa_authenticate(rest_username, access_code, temp_token)
        else:
            self.logger.debug("2FA Authenticating is needed but not allowed")
            raise ManagementAPIError("2FA Authenticating is needed but not allowed")
        self.set_token(token)
        self.logger.debug("REST token obtained and set")

    def rest_2fa_authenticate(self, rest_username, access_code, temp_token):
        self.logger.debug("REST Authenticating 2FA phase 2")
        return self.json_query(uri=urljoin(NEW_REST_API_BASE_URL, 'authenticate'),
                               method='POST',
                               data={'username': rest_username, 'password': access_code,
                                     "two_factor_auth_phase": 1, "temp_token": temp_token},
                               authenticate=False)['access_token']

    @rest_auto_reconnect()
    def _query(self, uri, method="GET", data=None, params=None, authenticate=True, files=None, **kwargs):
        if params is None:
            params = {}

        self.logger.debug("%s %s%s", method, uri, ('' if not params
                                                   else '?' + '&'.join("%s=%s" % (key, value)
                                                                       for key, value in params.items())))

        method_func = {"GET": self._requests_session.get,
                       "POST": self._requests_session.post,
                       "PUT": self._requests_session.put,
                       "PATCH": self._requests_session.patch,
                       "DELETE": self._requests_session.delete}[method]

        headers = {'content-type': 'application/json'} if files is None else None
        auth = JWTAuth(self.token) if (authenticate and self.rest_auth_enabled) else None
        # print urljoin(self.http_server_root, uri), data, headers, params
        try:
            r = method_func(urljoin(self.http_server_root, uri), data=data, headers=headers,
                            params=params, auth=auth, files=files, **kwargs)
        except requests.exceptions.RequestException as e:
            raise ManagementAPIError("Error while handling %s request for uri %s: %s" % (method, uri, e))

        if AUTHENTICATION_ERROR_HTTP_STATUS_CODE == r.status_code:  # This is a potential authorization error
            raise RESTAuthenticationError(r)

        if 200 != r.status_code:
            try:
                json_obj = json.loads(r.content)
            except:
                json_obj = r.content

            raise ManagementAPIError(json_obj)

        return r

    def json_query(self, uri, method="GET", data=None, return_json=True, params=None, authenticate=True, files=None,
                   convert_data_to_json=True):
        if data is not None and convert_data_to_json:
            data = self.json_encoder.encode(data)
        response = self._query(uri=uri, method=method, data=data,
                               params=params, authenticate=authenticate, files=files)
        try:
            if not return_json:
                return response.content
            try:
                json_obj = json.loads(response.content)
            except TypeError:
                json_obj = json.loads(response.content.decode('utf-8'))
            if json_obj is not None and "code" in json_obj and 0 != json_obj["code"]:
                raise ManagementAPIError("Error: %s" % (json_obj["message"], ))

            return json_obj
        except ValueError as exc:
            raise ManagementAPIError("Error reading server response: %s :: [%s]" % (str(exc), response.content))

    # Assets
    def list_assets(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'assets'), params=filt)['objects']

    def count_assets(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'assets'), params=filt)['total_count']

    def get_asset(self, vm_id):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'assets/%s' % (vm_id,)))

    # Incidents
    def list_incidents(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'incidents'), params=filt)['objects']

    # Visibility
    def list_network_visibility_flows(self, start_time=None, end_time=None, offset=None, limit=None,
                                      apply_network_policy=False,
                                      filters=None, group_by=None,
                                      open_vms=None, open_groups=None,
                                      open_subnets=None, open_internets=None):
        params = dict(apply_network_policy=apply_network_policy)
        if start_time is not None:
            params['start_time'] = datetime_to_timestamp(start_time)
        if end_time is not None:
            params['end_time'] = datetime_to_timestamp(end_time)
        if offset is not None:
            params['offset'] = offset
        if limit is not None:
            params['limit'] = limit
        if group_by is not None:
            params['group_by'] = group_by

        body = dict(state={})
        if open_groups:
            for group_id in open_groups:
                body['state'][group_id] = dict(type='group', open=True)

        if open_vms:
            for vm_id in open_vms:
                body['state'][vm_id] = dict(type='vm', open=True)

        if open_subnets:
            for subnet_id in open_subnets:
                body['state'][subnet_id] = dict(type='subnet', open=True)

        if open_internets:
            for internet_id in open_internets:
                body['state'][internet_id] = dict(type='internet', open=True)

        if filters:
            body['filters'] = filters

        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/flows'),
                               method='POST',
                               params=params, data=body)['objects']

    def get_asset_policy(self, asset_id):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/asset/' + asset_id))

    def get_process_policy(self, process_id):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/policy'),
                               params={'process_id': process_id})

    def set_process_policy(self, process_id, incoming_rules, outgoing_rules):
        _, vm_id, process_name = process_id.split('_')
        vm_name = self.get_asset(vm_id=vm_id)['name']

        try:
            policy_id = self.get_process_policy(process_id=process_id)['id']
            return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/' + policy_id),
                                   method='PUT',
                                   data={
                                       'id': policy_id,
                                       'incoming_rules': incoming_rules,
                                       'outgoing_rules': outgoing_rules
                                   }, return_json=False)
        except:
            return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/policy'),
                                   method='POST',
                                   data={
                                       'protected_app': {
                                           "display_name": process_name,
                                           "remote_type": "PROCESS",
                                           "vm_id": vm_id,
                                           "asset": {
                                               "name": vm_name,
                                               "asset_type": "Virtual Machine"
                                           }
                                       },
                                       'incoming_rules': incoming_rules,
                                       'outgoing_rules': outgoing_rules
                                   })

    def set_asset_locking(self, asset_id, lock_state):
        assert lock_state in ('NOT_LOCKED', 'INCOMING_LOCKED', 'OUTGOING_LOCKED', 'FULLY_LOCKED')
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/asset/' + asset_id),
                               method='PUT', data={'asset_policy': lock_state})

    def delete_process_policy(self, process_id):
        policy_id = self.get_process_policy(process_id=process_id)['id']
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/' + policy_id),
                               method='DELETE',
                               data={'id': policy_id},
                               return_json=False)

    def add_visibility_label(self, asset_ids, label_key, label_value):
        endpoint = 'assets/labels/{}/{}'.format(label_key, label_value)
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, endpoint),
                               method='POST',
                               data=dict(vms=asset_ids,
                                         delete=False))

    def delete_visibility_label(self, asset_ids, label_key, label_value):
        endpoint = 'assets/labels/{}/{}'.format(label_key, label_value)
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, endpoint),
                               method='POST',
                               data=dict(vms=asset_ids,
                                         delete=True))

    def list_visibility_labels(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/labels'), params=filt)

    def get_visibility_label_by_id(self, label_id):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/{}'.format(label_id)), method='GET')

    def delete_label_by_id(self, label_id):
        endpoint = 'visibility/labels/{}'.format(label_id)
        self.json_query(urljoin(NEW_REST_API_BASE_URL, endpoint), method='DELETE')

    def add_dynamic_label(self, key, value, dynamic_field=None,
                          dynamic_criterion_operation=None, dynamic_argument=None):
        """
        Creates a dynamic label.
        For example:
            If we're creating a label a:b, for assets whose names begin with 'Attacker', then pass the following params:
            key - 'a'
            value - 'b'
            dynamic_field - 'name'
            dynamic_criterion_operation - LabelCriterionOperation.STARTSWITH
            dynamic_argument - 'Attacker'

        :param dynamic_field: Should be either 'name' or 'numeric_ip_addresses'
        :param dynamic_criterion_operation: Should be one of management.models.labels.LabelCriterionOperation
        :type dynamic_criterion_operation: LabelCriterionOperation
        :param dynamic_argument: The argument itself
        :return:
        """

        def has_dynamic_criteria():
            dynamic_params = [dynamic_field, dynamic_criterion_operation, dynamic_argument]

            if all(dynamic_params):
                return True
            if not any(dynamic_params):
                return False

            raise Exception('You must pass either none, or all of the above: dynamic_name ({}), '
                            'dynamic_criterion_operation ({}), dynamic_argument({})'.format(dynamic_field,
                                                                                            dynamic_criterion_operation,
                                                                                            dynamic_argument))

        endpoint = 'visibility/labels'
        criteria = []

        if has_dynamic_criteria():
            criteria_dict = {
                'field': dynamic_field,
                'op': dynamic_criterion_operation,
                'argument': dynamic_argument
            }
            criteria.append(criteria_dict)

        data = {
            'id': None,
            'key': key,
            'value': value,
            'criteria': criteria
        }

        return self.json_query(urljoin(NEW_REST_API_BASE_URL, endpoint), method='POST', data=data)

    def add_multiple_labels(self, labels):
        """
        Imports mass amount of labels.
        :param labels: list of label dictionaries.
        Example:
            {'key': 'Role',
            'value': 'External',
            'asset_ids': [id1, id2,...]}
        :return: True if at least one label/asset was modified. False otherwise
        """
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/bulk'),
                               method='POST',
                               data={'labels': labels, 'action': 'add'})

    def delete_multiple_labels(self, label_ids):
        """
        Delete multiple labels from centra
        :param label_ids: list of label ids to delete
        :return: Success message if all labels were deleted. raises an 'OperationFailed' error if there were InPolicy
        labels or if labels were not found
        """
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/bulk'),
                               method='POST',
                               data={'label_ids': label_ids, 'action': 'delete'})

    def add_dynamic_label_with_multiple_criteria(self, key, value, criteria_list=None):
        """
        Creates a dynamic label.
        For example:
            If we're creating a label a:b, for assets whose names begin with 'Attacker', then pass the following params:
            key - 'a'
            value - 'b'
            criteria_list = list of dicts:
                {field - 'name'
                 op - LabelCriterionOperation.STARTSWITH
                 argument - 'Attacker'}
        """

        data = {
            'id': None,
            'key': key,
            'value': value,
            'criteria': criteria_list
        }
        try:
            return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/labels'), method='POST', data=data)
        except ManagementAPIError as error:
            if "Duplicate label" in error.args[0]["error_dump"]:
                self.add_dynamic_criteria_to_label(key, value, criteria_list)
            else:
                raise ManagementAPIError(error)

    def get_env_name(self):
        return str(self.json_query(urljoin(NEW_REST_API_BASE_URL, 'system-status'))["environment_customer_name"])

    def update_map(self, map_id):
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/saved-maps/')
        query = urljoin(query, map_id)
        data = {"action": "update"}
        return self.json_query(query, method='POST', data=data)

    def set_reveal_default_grouping(self, reveal_default_grouping):
        query = urljoin(NEW_REST_API_BASE_URL, 'system-configuration?view=system')
        data = {"reveal": {"default_label_for_grouping": reveal_default_grouping}}
        return self.json_query(query, method='PUT', data=data)

    def set_incident_timeouts(self, hard_timeout, idle_timeout):
        query = urljoin(NEW_REST_API_BASE_URL, 'reputation?view=reputation')
        data = {"advanced": {"hard_timeout": hard_timeout, "idle_timeout": idle_timeout}}
        return self.json_query(query, method='PUT', data=data)

    def set_slack_integration(self, site_name, webhook_address, output_audit=True, output_incidents=False):
        query = urljoin(NEW_REST_API_BASE_URL, 'system-configuration?view=integrations.slack')
        data = {"slack": {"output_audit_log_to_slack": output_audit, "slack_webhook_address": webhook_address,
                          "slack_site_name": site_name, "output_incidents_to_slack": output_incidents}}
        return self.json_query(query, method='PUT', data=data)

    def create_ui_user(self, username, email, password, description=None, can_access_passwords=True,
                       two_factor_auth_enabled=False, permission_scheme_id="administrator"):
        query = urljoin(NEW_REST_API_BASE_URL, 'system/user')
        data = {"action": "create", "username": username, "email": email, "description": description,
                "permission_scheme_id": permission_scheme_id, "password": password, "password_confirm": password,
                "two_factor_auth_enabled": two_factor_auth_enabled, "can_access_passwords": can_access_passwords}
        return self.json_query(query, method='POST', data=data)

    def configure_vsphere_orchestration(self, user, password, vcenter_ip, name="vSphere", aggr_cluster="default",
                                        create_labels=True, vsphere_cluster=None, nuage_enabled=False, port=443):
        query = urljoin(NEW_REST_API_BASE_URL, 'orchestration')
        data = {"orchestration_type": "vSphere", "name": name, "cluster_id": aggr_cluster, "configuration":
                {"admin_user": user, "admin_password": password, "auth_host": vcenter_ip, "auth_port": port,
                 "nuage_integration_enabled": nuage_enabled, "vsphere_clusters": vsphere_cluster,
                 "metadata_labels": create_labels}}
        return self.json_query(query, method="POST", data=data)

    def get_orchestrations(self):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'orchestration'))["objects"]

    def create_segmentation_rule(self, section, action, source=None, destination=None, ports=None, port_ranges=None,
                                 ip_protocols=None, ruleset=None, ruleset_name=None, ruleset_id=None, comments="",
                                 enabled=True, state="created"):
        if source is None:
            source = dict()
        if destination is None:
            destination = dict()
        if ports is None:
            ports = list()
        if port_ranges is None:
            port_ranges = list()
        if ip_protocols is None:
            ip_protocols = ["TCP"]
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/sections/{}/rules'.format(section))
        data = {"rule": {"section_position": section, "action": action, "source": source,
                         "destination": destination, "ports": ports, "port_ranges": port_ranges,
                         "ip_protocols": ip_protocols, "comments": comments, "enabled": enabled, "state": state}}
        if ruleset:
            data["rule"]["ruleset"] = ruleset
            data["rule"]["ruleset_name"] = ruleset_name
        else:
            data["rule"]["ruleset_id"] = ruleset_id

        return self.json_query(query, method="POST", data=data)

    def publish_segmentation_policy(self, comments):
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/revisions')
        data = {"action": "publish", "comments": comments}
        return self.json_query(query, method="POST", data=data)

    def create_fim_policy(self, title, files, hash_type="SHA256", affected_label_ids=None, affected_asset_ids=None,
                          enabled=True, description=""):
        query = urljoin(NEW_REST_API_BASE_URL, 'fim/templates')
        if affected_asset_ids is None:
            affected_asset_ids = list()
        data = {"templates": [{"title": title, "description": description, "files": files, "hash_type": hash_type,
                "affected_label_ids": affected_label_ids, "affected_asset_ids": affected_asset_ids, "enabled": enabled}]}
        return self.json_query(query, method="POST", data=data)

    def publish_fim_policy(self):
        query = urljoin(NEW_REST_API_BASE_URL, 'fim/revisions/publish')
        data = {"id": "publish"}
        return self.json_query(query, method="POST", data=data)

    def add_dynamic_criteria_to_label(self, key, value, criteria):
        label = self.list_visibility_labels(key=key, value=value)
        if len(label["objects"]) > 1:
            raise Exception('Search result for key: "{}" and value: "{}" returned more than one label (returned {}),'
                            ' please change the filter'.format(key, value, len(label["objects"])))
        if len(label["objects"]) == 0:
            raise Exception('No label was found for key: "{}" and value: "{}", '
                            'please change the filter'.format(key, value))
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/{}'.format(label["objects"][0]["id"]))
        new_criteria = label["objects"][0].get("criteria")
        new_criteria += criteria
        return self.json_query(query, method="PUT", data={"criteria": new_criteria})

    def update_visibility_label_details_by_id(self, label_id, key="", value="", criteria=None):
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/{}'.format(label_id))
        if criteria is None:
            criteria = list()
        data = dict()
        if key not in ("", None):
            data["key"] = key
        if value not in ("", None):
            data["value"] = value
        if len(criteria) != 0:
            data["criteria"] = criteria
        assert len(list(data.keys())) != 0, "No data to update"
        return self.json_query(query, method='PUT', data=data)

    def update_visibility_label(self, label):
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/{}'.format(label['_id']))
        data = dict()
        data["key"] = label['key']
        data["value"] = label['value']
        data["criteria"] = label['criteria']
        self.logger.info("Updating criteria for label with label id {}".format(label['_id']))
        self.logger.debug("New label data: {}".format(data))
        return self.json_query(query, method='PUT', data=data)

    def get_labels_for_assets(self, asset_ids):
        """
        returns all the labels applied to the assets associated with the requested asset ids
        :param asset_ids: Accepts asset_id (str) or a list of asset_ids (list)
        :return:
        """
        if type(asset_ids) is str:
            temp = asset_ids
            asset_ids = list()
            asset_ids.append(temp)
        assert type(asset_ids) == list, "Function accepts one asset id (type str) or a list of asset ids"

        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/assets')
        data = {'asset_ids': asset_ids}
        return self.json_query(query, method='POST', data=data)

    def list_agents(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'agents'), params=filt)

    def get_users(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'system/users'), params=filt)

    def get_aggregators(self):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'agent_aggregators'))["objects"]

    def get_collectors(self):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'collectors'))["objects"]

    def set_aggregator_as_cluster_orchestration_role_holder(self, aggregator_id):
        data = {
            "aggregator": {"aggregator_features": {"cluster_orchestration": True}},
            "component_ids": [aggregator_id],
            "negate_args": None # fixme is it needed?
        }
        query = urljoin(NEW_REST_API_BASE_URL, 'agent_aggregators/configuration')
        return self.json_query(query, method='PUT', data=data)

    def restart_aggregator_services(self, aggregator_ids):
        if isinstance(aggregator_ids, str):
            aggregator_ids = [aggregator_ids]
        data = {
            "action": "restart",
            "component_ids": aggregator_ids,
            "negate_args": None  # fixme is it needed?
        }
        query = urljoin(NEW_REST_API_BASE_URL, 'agent_aggregators')
        return self.json_query(query, method='POST', data=data)

    def restart_collector_services(self, collector_ids):
        if isinstance(collector_ids, str):
            aggregator_ids = [collector_ids]
        data = {
            "action": "restart",
            "component_ids": collector_ids,
            "negate_args": None  # fixme is it needed?
        }
        query = urljoin(NEW_REST_API_BASE_URL, 'agent_aggregators')
        return self.json_query(query, method='POST', data=data)