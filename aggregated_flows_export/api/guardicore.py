import datetime
import json
import logging
import requests

from requests.auth import AuthBase
from functools import wraps
from typing import List, Dict, Union, Any, Optional
from collections import defaultdict

from aggregated_flows_export.api.exceptions import CentraObjectNotFound

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

DYNAMIC_CRITERIA_LIMIT = 500000


class ManagementAPIError(Exception):
    def __init__(self, message):
        super(ManagementAPIError, self).__init__(message)


class ManagementAPITimeoutError(ManagementAPIError):
    def __init__(self, message):
        super(ManagementAPITimeoutError, self).__init__(message)


class RESTAuthenticationError(ManagementAPIError):
    def __init__(self, response):
        data = response.json()
        super(RESTAuthenticationError, self).__init__('%s: %s' % (data['error'],
                                                                  data['description']))
        self.data = data


class GraphMaxFlowsReached(ManagementAPIError):
    """Raised when a call for Graph fails because there are too many visible nodes and `force_creation` is not True"""
    pass


class GraphExpired(ManagementAPIError):
    """Raised when a call for Graph returns graph_expired error"""
    pass


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

                self.logger.error('Rest authentication error: %s', repr(e))
                self.logger.info("Token might have expired; re-authenticating")
                self.connect()
                return f(self, *args, **kwargs)

        return decorated

    return decorator


def datetime_to_timestamp(dt: datetime) -> int:
    """
    Convert a datetime object to timestamp in ms since epoch (which is the format used to query management).
    :param dt: datetime timestamp
    :return: dt as milliseconds since epoch
    """
    return int(dt.timestamp()) * 1000


class RESTManagementAPI(object):
    def __init__(self, management_host, username=None, password=None, rest_auth_enabled=True,
                 auto_connect=True, auto_reconnect=True, port=MANAGEMENT_REST_API_PORT,
                 proxy_host=None, proxy_port=None, proxy_username=None, proxy_password=None, allow_2fa_auth=False,
                 mfa_access_code_callback=None):

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
        self.mfa_access_code_callback = mfa_access_code_callback

        self.label_cache: Dict[str, Dict[str, str]] = defaultdict(dict)  # Key and Value to label_id
        self.label_group_cache: Dict[str, Dict[str, str]] = defaultdict(dict)  # Key and Value to label_group_id

        if self.rest_auth_enabled and self.auto_connect:
            self.connect()

    def connect(self):
        self.authentication_handler(self.rest_username, self.rest_password)

    def disconnect(self):
        self.json_query(urljoin(NEW_REST_API_BASE_URL, 'logout'),
                        method='POST', return_json=False)

    def logout(self):
        self.disconnect()

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
            access_code = ""
            if self.mfa_access_code_callback is None:
                access_code = input("Please supply 2fa access code for user {}: ".format(rest_username))
            else:
                access_code = self.mfa_access_code_callback()
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
    def _query(self, uri, method="GET", data=None, params=None, authenticate=True, files=None, follow_redirects=False,
               **kwargs):
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

        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0',
                   'content-type': 'application/json' if files is None else None}
        auth = JWTAuth(self.token) if (authenticate and self.rest_auth_enabled) else None
        # print urljoin(self.http_server_root, uri), data, headers, params
        try:
            r = method_func(urljoin(self.http_server_root, uri), data=data, headers=headers,
                            params=params, auth=auth, files=files, **kwargs)
            if follow_redirects and r.status_code == 406:
                r = self._query(uri=r.headers['Location'], method=method, data=data,
                                params=params, authenticate=authenticate, files=files)
        except requests.exceptions.RequestException as e:
            raise ManagementAPIError("Error while handling %s request for uri %s: %s" % (method, uri, e))

        if AUTHENTICATION_ERROR_HTTP_STATUS_CODE == r.status_code:  # This is a potential authorization error
            raise RESTAuthenticationError(r)

        if r.status_code == 403:
            raise RESTAuthenticationError(r)

        if 200 != r.status_code:
            try:
                json_obj = json.loads(r.content)
            except:
                json_obj = r.content
                if isinstance(json_obj, bytes) and b"504 Gateway Time-out" in json_obj:
                    raise ManagementAPITimeoutError(json_obj)

            raise ManagementAPIError(json_obj)

        return r

    def json_query(self, uri, method="GET", data=None, return_json=True, params=None, authenticate=True, files=None,
                   convert_data_to_json=True, follow_redirects=True) -> Union[bytes, Dict, str]:
        if data is not None and convert_data_to_json:
            data = self.json_encoder.encode(data)
        response = self._query(uri=uri, method=method, data=data, params=params, authenticate=authenticate, files=files,
                               follow_redirects=follow_redirects)
        try:
            if not return_json:
                return response.content
            try:
                json_obj = json.loads(response.content)
            except TypeError:
                json_obj = json.loads(response.content.decode('utf-8'))
            if json_obj is not None and "code" in json_obj and 0 != json_obj["code"]:
                raise ManagementAPIError("Error: %s" % (json_obj["message"],))

            return json_obj
        except ValueError as exc:
            raise ManagementAPIError("Error reading server response: %s :: [%s]" % (str(exc), response.content))

    # Assets
    def list_assets(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'assets'), params=filt)['objects']

    def list_agents(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'agents'),
                               params=filt)['objects']

    def count_assets(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'assets'), params=filt)['total_count']

    def get_asset(self, vm_id):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'assets/%s' % (vm_id,)))

    # Incidents
    def list_incidents(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'incidents'), params=filt)['objects']

    def get_incident_events(self, incident_id):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'incidents/{}/events'.format(incident_id)))

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
                               method='POST', data=dict(vms=asset_ids, delete=False))

    def remove_assets_from_label(self, asset_ids, label_key, label_value):
        """
        Remove a list of assets from label
        :param asset_ids: asset ids of the assets to remove (disassociate) from the label
        :param label_key:
        :param label_value:
        :return:
            On successful removal, a short label object - id, key, value and name
            On unsuccessful removal, error msg

        """
        endpoint = 'assets/labels/{}/{}'.format(label_key, label_value)
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, endpoint),
                               method='POST',
                               data=dict(vms=asset_ids,
                                         delete=True))

    def list_visibility_labels(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/labels'), params=filt)

    def get_visibility_label_by_id(self, label_id):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/{}'.format(label_id)), method='GET')

    def get_label_id(self, key: str, value: str) -> str:
        """ Return the id of the label with the key and value provided """
        label_id = self.label_cache.get(key, {}).get(value)
        if label_id:
            return label_id

        response = self.list_visibility_labels(key=key, value=value)
        if response["total_count"] == 0:
            raise CentraObjectNotFound(f"The label '{key}: {value}' was not found in Centra")

        label_id = response["objects"][0]["id"]
        self.label_cache[key][value] = label_id
        return label_id

    def get_label_group_id(self, key: str, value: str) -> str:
        """ Return the id of the label group with the provided key and value """
        label_group_id = self.label_group_cache.get(key, {}).get(value)
        if label_group_id:
            return label_group_id

        response = self.get_label_groups(key=key, value=value)
        if response["total_count"] == 0:
            raise CentraObjectNotFound(f"The label group '{key}: {value}' was not found in Centra")

        label_group_id = response["objects"][0]["id"]
        self.label_group_cache[key][value] = label_group_id
        return label_group_id

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
            if "Duplicate label" in str(error) or "Label name already in use" in str(error):
                self.add_dynamic_criteria_to_label(key, value, criteria_list)
            else:
                raise ManagementAPIError(error)

    def get_env_name(self):
        return str(self.json_query(urljoin(NEW_REST_API_BASE_URL, 'system-status'))["environment_customer_name"])

    def get_env_version(self) -> Dict[str, str]:
        """Returns the major and minor versions of Centra in a dict: {major: x, minor: y}"""
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'system-status'))["version"]["full_version"]

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

    def create_ui_user(self, username, password, email=None, description=None, can_access_passwords=True,
                       two_factor_auth_enabled=False, permission_scheme_ids=None,
                       disable_password_change_on_next_login=False):
        if not permission_scheme_ids:
            permission_scheme_ids = ["administrator"]
        query = urljoin(NEW_REST_API_BASE_URL, 'system/user')
        data = {"action": "create", "username": username, "email": email, "description": description,
                "permission_scheme_ids": permission_scheme_ids, "password": password, "password_confirm": password,
                "two_factor_auth_enabled": two_factor_auth_enabled, "can_access_passwords": can_access_passwords}
        response = self.json_query(query, method='POST', data=data)
        if disable_password_change_on_next_login:
            users = self.get_users(username=username)["objects"]
            for user in users:
                if user["username"] == username:
                    user_id = user["_id"]
                    break
            assert user_id, "Could not find ID for user {}".format(username)
            data["action"] = "update"
            data["id"] = user_id
            del data["password"]
            del data["password_confirm"]
            return self.json_query(query, method='POST', data=data)
        return response

    def update_ui_user(self, id, username, email=None, description=None, can_access_passwords=True,
                       two_factor_auth_enabled=False, permission_scheme_ids=None):
        """
        Updates a UI user's configuration
        :param id: User's ID
        :param username:
        :param email:
        :param description:
        :param can_access_passwords: T/F
        :param two_factor_auth_enabled: T/F
        :param permission_scheme_ids: list of permission scheme IDs or names
        :return:
        """
        query = urljoin(NEW_REST_API_BASE_URL, 'system/user')
        data = {"action": "update", "id": id, "username": username, "email": email, "description": description,
                "permission_scheme_ids": permission_scheme_ids,
                "two_factor_auth_enabled": two_factor_auth_enabled, "can_access_passwords": can_access_passwords}
        return self.json_query(query, method='POST', data=data)

    def configure_vsphere_orchestration(self, user, password, vcenter_ip, name="vSphere", aggr_cluster="default",
                                        create_labels=True, vsphere_cluster=None, nuage_enabled=False, port=443):
        query = urljoin(NEW_REST_API_BASE_URL, 'orchestration')
        if not vsphere_cluster:
            vsphere_cluster = list()
        data = {"orchestration_type": "vSphere", "name": name, "cluster_id": aggr_cluster, "configuration":
            {"admin_user": user, "admin_password": password, "auth_host": vcenter_ip, "auth_port": port,
             "nuage_integration_enabled": nuage_enabled, "vsphere_clusters": vsphere_cluster,
             "metadata_labels": create_labels}}
        return self.json_query(query, method="POST", data=data)

    def get_orchestrations(self):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'orchestration'))["objects"]

    def create_segmentation_rule(self, section, action, source=None, destination=None, ports=None, port_ranges=None,
                                 exclude_ports=None, ip_protocols=None, ruleset=None, ruleset_name=None, enabled=True,
                                 ruleset_id=None, comments="", state="created", exclude_port_ranges=None):
        """

        :param section: allow, alert, block, override_allow, override_alert, override_block
        :param action: allow, alert, block, block_and_alert
        :param source: for any- leave empty
        :param destination: for any- leave empty
        :param ports:
        :param port_ranges:
        :param exclude_ports:
        :param ip_protocols: list of protocols
        :param ruleset:
        :param ruleset_name:
        :param enabled:
        :param ruleset_id:
        :param comments:
        :param state:
        :param exclude_port_ranges:
        :return:
        """
        if source is None:
            source = dict()
        if destination is None:
            destination = dict()
        if ports is None:
            ports = list()
        if port_ranges is None:
            port_ranges = list()
        if exclude_ports is None:
            exclude_ports = list()
        if exclude_port_ranges is None:
            exclude_port_ranges = list()
        if ip_protocols is None:
            ip_protocols = ["TCP"]
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/sections/{}/rules'.format(section))
        data = {"rule": {"section_position": section.lower(), "action": action.lower(), "source": source,
                         "destination": destination, "ports": ports, "port_ranges": port_ranges,
                         "exclude_ports": exclude_ports, "exclude_port_ranges": exclude_port_ranges,
                         "ip_protocols": ip_protocols, "comments": comments, "enabled": enabled, "state": state}}
        if ruleset:
            data["rule"]["ruleset"] = ruleset
            data["rule"]["ruleset_name"] = ruleset_name
        else:
            data["rule"]["ruleset_id"] = ruleset_id

        return self.json_query(query, method="POST", data=data)

    def bulk_create_segmentation_rules(self, rules_to_upload: List[Dict[str, any]]):
        """
        Creates multiple segmentation rules in a single api call.
        :param rules_to_upload: list of rule dictionaries (unlike `create_segmentation_rule`, in each rule the key
        "section" needs to be changed to "section_position" with a value in UPPER case, and a the key-value pair:
        `"ordering": "0.0"` needs to be added to every rule)
        :return:
        """
        query = urljoin(NEW_REST_API_BASE_URL, "visibility/policy/rules/bulk")
        return self.json_query(query, method="POST", data={"added": rules_to_upload})

    def publish_segmentation_policy(self, comments, reset_hit_count: bool = False, ruleset: str = None):
        """
        Publishes segmentation policy.
        :param comments: REQUIRED - The comment written in the published revision
        :param reset_hit_count: This parameter is used for v35+, any previous version will ignore this
        :param ruleset: The ruleset to publish, leave empty for all rulesets
        :return:
        """
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/revisions')
        data = {"action": "publish", "comments": comments, "reset_hit_count": reset_hit_count}
        if ruleset:
            data["ruleset"] = ruleset
        return self.json_query(query, method="POST", data=data)

    def create_fim_policy(self, title, files, hash_type="SHA256", affected_label_ids=None, affected_asset_ids=None,
                          enabled=True, description=""):
        query = urljoin(NEW_REST_API_BASE_URL, 'fim/templates')
        if affected_asset_ids is None:
            affected_asset_ids = list()
        data = {"templates": [{"title": title, "description": description, "files": files, "hash_type": hash_type,
                               "affected_label_ids": affected_label_ids, "affected_asset_ids": affected_asset_ids,
                               "enabled": enabled}]}
        return self.json_query(query, method="POST", data=data)

    def publish_fim_policy(self):
        query = urljoin(NEW_REST_API_BASE_URL, 'fim/revisions/publish')
        data = {"id": "publish"}
        return self.json_query(query, method="POST", data=data)

    def add_dynamic_criteria_to_label(self, key, value, criteria_to_add):
        label = self.list_visibility_labels(key=key, value=value, dynamic_criteria_limit=DYNAMIC_CRITERIA_LIMIT)
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/{}'.format(label["objects"][0]["id"]))

        if len(label["objects"]) > 1:
            raise Exception('Search result for key: "{}" and value: "{}" returned more than one label (returned {}),'
                            ' please change the filter'.format(key, value, len(label["objects"])))
        if len(label["objects"]) == 0:
            raise Exception('No label was found for key: "{}" and value: "{}", '
                            'please change the filter'.format(key, value))

        # Current explicitly added assets
        explicitly_added_assets = label["objects"][0].get("equal_criteria")
        # Current dynamic criteria
        current_dynamic_criteria = label["objects"][0].get("dynamic_criteria")
        new_criteria = explicitly_added_assets + current_dynamic_criteria + criteria_to_add
        return self.json_query(query, method="PUT", data={"key": key, "value": value, "criteria": new_criteria})

    def update_visibility_label(self, label):
        """
        Update the label in Centra with label_id = label['_id'] with the content of the label passed as argument.
        This allows editing the label's key, value, dynamic and static criterias.
        :param label: The new desired state of the label object.
        :return: The new label object as returned from Centra API
        """
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/{}'.format(label['_id']))
        data = dict()
        data["key"] = label['key']
        data["value"] = label['value']
        data["criteria"] = label['equal_criteria'] + label["dynamic_criteria"]
        self.logger.debug("Updating criteria for label with label id {}".format(label['_id']))
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
            "negate_args": None  # fixme is it needed?
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
            collector_ids = [collector_ids]
        data = {
            "action": "restart",
            "component_ids": collector_ids,
            "negate_args": None  # fixme is it needed?
        }
        query = urljoin(NEW_REST_API_BASE_URL, 'agent_aggregators')
        return self.json_query(query, method='POST', data=data)

    def get_network_log_connections(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'connections'), params=filt)

    def set_blacklist(self, bl_type, key, tags=None):
        assert bl_type in ('ip', 'file'), "Type must be `ip` or `file`"
        params = {'type': 'ip'}
        if not tags:
            tags = list()
        data = {bl_type: [{"key": key, "tags": tags}]}
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'blacklist'), method='POST', params=params, data=data)

    def get_label_groups(self, **filt):
        """
        Gets all existing label groups.
        Can add filters with params such as key, value, labels, matching assets ...
        :param filt: dict of params to filter by, default is asset_status
        :return: {objects: [list of label groups dicts]}
        """
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/label-groups'), params=filt)

    def create_label_groups(self, key: str, value: str,
                            include_labels: Dict[str, List[Dict[str, List[str]]]],
                            exclude_labels: Optional[Dict[str, List[Dict[str, List[str]]]]] = None):
        """
        Creates a new label group.
        :param key: Key of label group
        :param value: Value of label group
        :param include_labels: {"or_labels": [{"and_labels": labels_criteria}]}
                                *labels_criteria = a list of label IDs
        :param exclude_labels: {"or_labels": [{"and_labels": labels_criteria}]}
                                *labels_criteria = a list of label IDs
        :return:
        """
        exclude_labels = exclude_labels if exclude_labels is not None else {}
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/label-groups'),
                               data={"label_group": {"key": key, "value": value, "include_labels": include_labels,
                                                     "exclude_labels": exclude_labels}}, method="POST")

    def update_label_groups(self, id: str, key: str = None, value: str = None,
                            include_labels: Dict[str, List[Dict[str, List[str]]]] = None,
                            exclude_labels: Dict[str, List[Dict[str, List[str]]]] = None):
        """
        Updates an existing label group
        :param id: label group's ID
        :param key: label group's key
        :param value: label group's value
        :param include_labels: {"or_labels": [{"and_labels": labels_criteria}]}
        :param exclude_labels: {"or_labels": [{"and_labels": labels_criteria}]}
                               *labels_criteria = a list of label IDs
        :return:
        """
        data = {"id": id}
        if key:
            data["key"] = key
        if value:
            data["value"] = value
        if include_labels:
            data["include_labels"] = include_labels
        if exclude_labels:
            data["exclude_labels"] = exclude_labels
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, f'visibility/label-groups/{id}'),
                               data=data, method="PUT")

    def publish_label_groups(self):
        """ Publishes label groups created / updated"""
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, f'visibility/label-groups'), data={}, method="PUT")

    def get_segmentation_rules(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/rules'), params=filt)

    def update_segmentation_rule(self, updated_rule):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/rules/{}'.format(updated_rule['id'])),
                               method='PUT', data=updated_rule)

    def disable_enable_segmentation_rule(self, rule_id: str, action: str, origin: str = "SEGMENTATION_RULES"):
        """
        Disables or Enables a single rule.
        :param rule_id: ID of the rule
        :param action: takes either "disable" or "enable"
        :param origin: origination of the action
        :return:
        """
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, f'visibility/policy/rules/{rule_id}'),
                               method='POST', data={"origin": origin, "action": action})

    def get_asset_policy_json(self, asset_id):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'assets/{}/policy'.format(asset_id)))

    def start_policy_export_job(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/rules/export'),
                               params=filt)["export_task_status_id"]

    def get_policy_export_job_status(self, task_id):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'export_csv_task_status'), params={"task_id": task_id})

    def get_policy_export_csv(self, exported_csv_file_id):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'exported_csv_files/{}'.format(exported_csv_file_id)))

    def configure_ad_orchestration(self, login_username, login_password, domain_name, servers, base_dn, name="AD",
                                   aggr_cluster="default", use_ssl=False, orchestration_full_report_interval=1800):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'orchestration'), method="POST",
                               data={"orchestration_type": "ActiveDirectory", "name": name, "cluster_id": aggr_cluster,
                                     "configuration": {
                                         "domain_name": domain_name, "login_username": login_username,
                                         "login_password": login_password, "base_dn": base_dn,
                                         "servers": servers, "use_ssl": use_ssl,
                                         "orchestration_full_report_interval": orchestration_full_report_interval}
                                     }
                               )

    def create_ad_user_group(self, title, orchestrations_groups):
        """
        :param orchestrations_groups: list of lists, each list containing an AD orchestration id and a list of
        group SIDs.
        For example: {"title": "Server Administrators",
                      "orchestrations_groups": [{"orchestration_id": "de82be05-3d18-47e2-a40b-b42951964146",
                        "groups": ["S-1-5-21-1940306394-560177949-1329077876-1109"]}]}
        """
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/user-groups'), method="POST",
                               data={"title": title, "orchestrations_groups": orchestrations_groups})

    def generate_saved_map(self, map_name: str, start_time: datetime, end_time: datetime,
                           include_filter: Dict[str, Union[str, int, List]] = None,
                           exclude_filter: Dict[str, Union[str, int, List]] = None, time_resolution: bool = False,
                           include_flow_hit_count: bool = False, include_incident_marks: bool = False,
                           map_type: int = 0, include_processes: bool = True) -> Dict[str, Any]:
        """
        Generate a Reveal Saved Map in Centra.
        :param map_name: Name for the map
        :param start_time: Map flows start time
        :param end_time: Map flows end time
        :param include_filter: Flows matching this filter will be included in the map todo improve documentation
        :param exclude_filter: Flows matching this filter will be excluded from the map todo improve documentation
        :param time_resolution: Whether to include exact flows time in the map creation
        :param include_flow_hit_count: Whether to include flows hit count in the map
        :param include_incident_marks: Whether to include incidents data on map flows
        :param map_type: 0 - public map, 1 - Admins only map
        :param include_processes: Whether to include processes in the map creation. This option is deprecated starting
        of v31.7, and processes will be included in any saved map.
        :return: The saved map object of the newly created map as it is returned form the API
        """
        include_filter = include_filter if include_filter is not None else {}
        exclude_filter = exclude_filter if exclude_filter is not None else {}
        data = {
            "name": map_name,
            "start_time_filter": datetime_to_timestamp(start_time),
            "end_time_filter": datetime_to_timestamp(end_time),
            "include_flow_hit_count": include_flow_hit_count,
            "include_incident_marks": include_incident_marks,
            "include_processes": include_processes,
            "time_resolution": time_resolution,
            "map_type": map_type,
            "filters": {"include": include_filter, "exclude": exclude_filter}
        }
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/saved-maps')
        return self.json_query(query, method='POST', data=data)["saved_map"]

    def delete_saved_map(self, map_id: str) -> None:
        """Delete a saved map by its map id"""
        query = urljoin(NEW_REST_API_BASE_URL, f'visibility/saved-maps/{map_id}')
        return self.json_query(query, method='DELETE')

    def list_saved_maps(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/saved-maps'), params=filt)["objects"]

    def bulk_create_labels(self, labels):
        """
        Bulk create labels.
        :param labels: a list of label dict objects to create, each in the form: {"key": "keyA", "value": "valueA",
        "criteria": [criteria_objectA, criteria_objectB].
        :return: True if any change was done, False otherwise
        """
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/labels'), method='POST',
                               data={"labels": labels})

    def update_visibility_label_by_label_id(self, label_id, new_key, new_value, new_criteria):
        """
        Update the label with label_id, and set it's properties to the values passed as argument.

        :param label: The new desired state of the label object.
        :return: The new label object as returned from Centra API
        :param label_id: The label_id of the Centra label to update
        :param new_key: new key to set
        :param new_value: new value to set
        :param new_criteria: new criteria to set
        :return:
        """
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/labels/{}'.format(label_id))
        data = dict()
        data["key"] = new_key
        data["value"] = new_value
        data["criteria"] = new_criteria
        return self.json_query(query, method='PUT', data=data)

    def publish_user_group_revision(self):
        query = urljoin(NEW_REST_API_BASE_URL, 'visibility/user-groups/revisions')
        return self.json_query(query, method='POST', data={"id": "revisions"})

    def list_user_groups(self, **filt):
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/user-groups'), params=filt)["objects"]

    def configure_application_label_key(self, label_key: str):
        """
        Configures the application label key which the auto label suggestion will use (only in v32+)
        :param label_key: The key of the label used for labeling applications in the environment
        :return:
        """
        query = urljoin(NEW_REST_API_BASE_URL, 'system-configuration?view=system')
        return self.json_query(query, method="PUT", data={"reveal": {"application_label_key": label_key}})

    def generate_map_graph(self, map_id: str, start_time: str, end_time: str, group_by: List[str] = None,
                           include_filter: Dict[str, Union[str, List, Dict]] = None,
                           exclude_filter: Dict[str, Union[str, List, Dict]] = None,
                           graph_state: Dict[str, Dict[str, str]] = None, force_creation: bool = False,
                           overlays: Dict[str, Dict] = None) -> List[Dict[str, Any]]:
        """
        Generate a graph (=map view) for a saved map. If graph_state was provided, a map view in this state will be
        requested.
        :param map_id: The id of the map to generate the graph for
        :param start_time: Network flows start time, in milliseconds since epoch
        :param end_time: Network flows end time, in milliseconds since epoch
        :param group_by: List of label keys to group the map by
        :param include_filter: An include filter
        :param exclude_filter: An exclude filter
        :param graph_state: A state of objects on the map. This can be used to request for a view with expanded objects.
        :param force_creation: If true, graph creation will be forced even if Centra detects that the graph
        generation might time out because it includes too many entities. Specifying yes might cause the request to
        time out.
        :param overlays: Map overlays to apply
        :raises GraphMaxFlowsReached: If the graph contains too many nodes and force_creation=True was not provided
        :return: A graph as it is returned from Centra API
        """
        graph_state = graph_state if graph_state is not None else {}
        overlays = overlays if overlays is not None else {}
        include_filter = include_filter if include_filter is not None else {}
        exclude_filter = exclude_filter if exclude_filter is not None else {}
        params = dict(saved_map_id=map_id, start_time=start_time, end_time=end_time)
        if group_by:
            params["group_by"] = ','.join(group_by)
        data = dict(filters={"include": include_filter, "exclude": exclude_filter}, state=graph_state,
                    force=force_creation, overlays=overlays)
        response = self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/graph'), params=params, data=data)
        if response.get("max_flows_reached"):
            raise GraphMaxFlowsReached("There are too many visible nodes on the graph. To force graph creation, "
                                       "provide the argument force_creation=True")
        if response.get("graph_expired"):
            raise GraphExpired("The graph request failed. This probably means there are too many visible nodes on the "
                               "graph, and that you should change the filter to reduce the number of flows")
        return response["objects"]

    def generate_map_permalink_for_flows_export(self, map_id: str, start_time: str, end_time: str,
                                                group_by: List[str] = None,
                                                graph: Dict[str, Dict[str, str]] = None,
                                                include_filter: Dict[str, Union[str, List, Dict]] = None,
                                                exclude_filter: Dict[str, Union[str, List, Dict]] = None) -> str:
        """
        Generate a permalink for a saved map state. This permalink is valid for the use of exporting the map to CSV,
        but not completely valid to preserve map views for users, because the filters are not kept intact when
        opening the permalink in Explore.
        :param map_id: The id of the map to generate the graph for
        :param start_time: Network flows start time, in milliseconds since epoch
        :param end_time: Network flows end time, in milliseconds since epoch
        :param group_by: List of label keys to group the map by
        :param graph: The state of objects on the map (expanded, collapsed)
        :param include_filter: An include filter
        :param exclude_filter: An exclude filter
        :return: Permalink id
        """
        graph = graph if graph is not None else {}
        include_filter = include_filter if include_filter is not None else {}
        exclude_filter = exclude_filter if exclude_filter is not None else {}
        data = dict(saved_map_id=map_id, start_time=start_time, end_time=end_time, state=graph,
                    filters={"include": include_filter, "exclude": exclude_filter})
        if group_by:
            data["group_by"] = ','.join(group_by)
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'permalink'), data=data, method='POST')

    def request_map_export_job(self, permalink_id: str) -> str:
        """
        Request Centra to initiate a "map export to CSV" task based on the provided map permalink id.
        :param permalink_id: The id of the map permalink (frozen view) to export the CSV data from
        :return: A task id. This id can be used to follow the job export status
        """
        params = {"link_id": permalink_id}
        response = self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/graph/export'), params=params)
        return response["export_task_status_id"]

    def get_map_export_job_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get the status of a "map export to CSV" task. The status contains the current state of the job (see dictionary
        below), and exported_csv_file_id which later can be used to download the flows data when the job is ready.
        :param task_id: The id of the task to query
        :return: A dict containing the tasks status and data.
        task_state_number_to_status_string = {
            0: "CREATED",
            1: "IN_PROGRESS",
            2: "FILE_READY",
            3: "RESOLVED",
            4: "ERROR",
            5: "CANCELED"
        }
        """
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'export_csv_task_status'), params={"task_id": task_id})

    def download_map_export_csv(self, exported_csv_file_id: str) -> str:
        """
        Download a flows from a completed "map export to csv" job.
        :param exported_csv_file_id: The id of the ready exported file to download
        :return: The flows data as string
        """
        export_bytes = self.json_query(urljoin(NEW_REST_API_BASE_URL, f'exported_csv_files/{exported_csv_file_id}'),
                                       return_json=False)
        return export_bytes.decode("utf-8")

    def set_enforcement_state(self, component_ids: list, state: str):
        """
        Takes a list of asset IDs and changes their enforcement mode to Reveal only, monitoring, and enforcement
        :param component_ids: List of asset IDs *IMPORTANT* add "AG-" before the asset ID
        i.e. asset ID = "123-456", component_ids accepts "AG-123-456"
        :param state: sets to one of 3 states- "RevealOnly", "Monitoring", "Enforcing"
        :return:
        """
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'agents-v2/enforcement-state'), method="POST",
                               data={"component_ids": component_ids, "state": state})

    def get_policy_revisions(self, from_time: datetime, to_time: datetime) -> List[Dict[str, Union[str, int]]]:
        """Return all the Centra policy revisions published between the given dates, sorted by descending
        revision number"""
        return self.json_query(urljoin(NEW_REST_API_BASE_URL, 'visibility/policy/revisions'), method="GET",
                               params={"from_time": datetime_to_timestamp(from_time),
                                       "to_time": datetime_to_timestamp(to_time),
                                       "sort": "-revision_number"})["objects"]

    def create_segmentation_rule_from_dict(self, rule_dict) -> Dict:
        """ Create a segmentation rule in Centra, provided the rule object dictionary """
        query = urljoin(NEW_REST_API_BASE_URL, f'visibility/policy/sections/{rule_dict["section"]}/rules')
        return self.json_query(query, method="POST", data=rule_dict)

    def list_system_events(self, raw_result=False, **filt):
        """
        Lists the system events from the UI->administration->system->log
        :param raw_result:
        :param filt: OPTIONAL, can have the following filters:
        event_source (i.e. "management") - Takes component name
        status (i.e. "ERROR") - Possible error statuses: ERROR, WARNING, INFO, COMPLETED
        from_time (i.e. 1607598562000) - Takes unix timestamp * 1000 (3 zeros at the end, unknown why)
        to_time (i.e. 1607598561000) - Takes unix timestamp * 1000 (3 zeros at the end, unknown why)
        :return:
        """
        raw = self.json_query(urljoin(NEW_REST_API_BASE_URL, 'system-events'), params=filt)
        return raw if raw_result else raw['objects']
