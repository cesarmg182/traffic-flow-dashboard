"""
Contains common functions to interact with the GC api
"""

import sys
import logging
import calendar
import string
import secrets
import json
import yaml
import re
import subprocess

from hashlib import sha3_512
from contextlib import contextmanager
from datetime import datetime
from ipaddress import IPv4Network, AddressValueError
from typing import Dict, Any, Generator
from pathlib import Path

# from pathlib import Path
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization

from api.guardicore import RESTManagementAPI, ManagementAPIError

DEFAULT_LOGGER_FORMAT = "%(asctime)s:%(levelname)s: %(message)s"
DEFAULT_LOGGING_LEVEL = logging.INFO

AMBIGUOUS_CHARS = ['l', 'I']
DEFAULT_PASSWORD_CHARS = string.ascii_letters + string.digits
for char in AMBIGUOUS_CHARS:
    DEFAULT_PASSWORD_CHARS = DEFAULT_PASSWORD_CHARS.replace(char, '')

# IP address with / without CIDR regex
IP_REGEX = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" \
           r"(/([0-9]|[1-2][0-9]|3[0-2]))?$"


POLICY_ACTIONS_MAP = {
    "allowed by policy": "Allowed By Policy",
    "alerted by policy": "Alerted By Policy",
    "blocked by policy": "Blocked By Policy",
    "no matching policy": "No Matching Policy"}

CONNECTION_TYPES_MAP = {
    "blocked": "Blocked",
    "redirected to deception": "Redirected to Deception",
    "established": "Established",
    "failed": "Failed",
    "violated segmentation policy": "Violated Segmentation Policy",
    "associated with incident": "Associated With Incident"
}

INTERNET_FILTER_MAP = {
    "from internet": "From Internet",
    "to internet": "To Internet"
}


logger = logging.getLogger("guardicore." + __name__)


def validate_python_version(minimum_major_version: int = 3, minimum_minor_version: int = 6):
    """Validate minimum python version requirements are met"""
    ver_info = sys.version_info
    try:
        assert ver_info.major >= minimum_major_version
        assert ver_info.minor >= minimum_minor_version
    except (AssertionError, Exception):
        logger.error(f"Incompatible python version detect. The script is intended to run using python version"
                     f" {minimum_major_version}.{minimum_minor_version} or newer")
        logger.info("If you run the script from a machine that has both python 2 and python 3, running the script with "
                    "python3 instead of python might solve this issue")


@contextmanager
def get_gc_api(management_address: str, auth_username: str, auth_password: str, management_port: int = 443,
               allow_2fa_auth=True):
    """
    A contextmanager that yields a Centra API connection object (RESTManagementAPI).
    An attempt to log out from Centra API will be preformed when the object is API connection is
    no longer needed (when leaving context).
    :raises AssertionError: if the provided management address contains 'https'
    """
    try:
        logger.debug(f"Connecting to Centra API at '{management_address}' over port {management_port}, using the "
                     f"username {auth_username}")
        if "https" in management_address:
            raise AssertionError(f"The provided management address {management_address} contains 'https', which should "
                                 f"not be provided. Please provide only the ip (i.e. 172.16.100.1) or fqdn "
                                 f"(i.e centra.example.com) of the management server, without https:// or any trailing "
                                 f"slashes")
        gc_api = RESTManagementAPI(management_host=management_address, allow_2fa_auth=allow_2fa_auth,
                                   username=auth_username, password=auth_password,
                                   port=management_port)
        yield gc_api
    finally:
        try:
            logger.debug(f"Trying to logout properly from Centra API")
            gc_api.auto_reconnect = False
            gc_api.logout()
        except NameError:
            pass
        except ManagementAPIError as error:
            logger.debug(f"Could not logout properly from Centra API. {repr(error)}")


def datetime_to_timestamp(dt: datetime) -> int:
    """
    Convert a datetime object to timestamp in ms since epoch (which is the format used on Centra API).
    :param dt: datetime timestamp
    :return: dt as milliseconds since epoch
    """
    return int(calendar.timegm(dt.timetuple()) * 1000 + dt.microsecond / 1000)


def remove_empty_values(data):
    """Remove None, empty lists and empty string values from lists, tuples, sets and dicts recursively"""
    if isinstance(data, (list, tuple, set)):
        return type(data)(remove_empty_values(x) for x in data if x not in (None, [], "", [None]))
    elif isinstance(data, dict):
        return type(data)((remove_empty_values(k), remove_empty_values(v)) for k, v in data.items()
                          if v not in (None, [], "", [None]))
    else:
        return data


def validate_password_complexity(password: str) -> bool:
    """Check if the password has at least one number, one upper case letter and one lower case letter"""
    if re.search('[0-9]', password) is None:
        return False
    if re.search('[A-Z]', password) is None:
        return False
    if re.search('[a-z]', password) is None:
        return False
    return True


def generate_password(length: int = 16, base_chars: str = DEFAULT_PASSWORD_CHARS, add_symbol: bool = False) -> str:
    """
    Generates a password while verifying that the password complexity is sufficient.
    :param length: The length of the password
    :param base_chars: base chars from which the password will be constructed
    :param add_symbol: adds a symbol as a suffix (according to the requirements of the password)
    :return: the generated password
    """
    password = ''.join(secrets.choice(base_chars) for _ in range(length))
    while not validate_password_complexity(password):
        password = ''.join(secrets.choice(base_chars) for _ in range(length))
    if add_symbol:
        password = f'{password}*'
    return password


def write_object_to_json(obj: object, export_path: Path) -> None:
    """Write an object to json"""
    with export_path.open('w') as f:
        json.dump(obj, f, indent=2, separators=(',', ': '))


def str_to_bool(s: str) -> bool:
    """
    Return a "true" or "false" string as boolean, case insensitive.
    :raises TypeError: if the string.lower() is not true or false
    """
    if s.lower() == "true":
        return True
    elif s.lower() == "false":
        return False
    raise TypeError(f"{s} cannot be converted to boolean. Please provide True or False")


def write_ts_to_file(ts, export_path):
    """
    converts a Terrascript object to a string and performs final replacements (like name_workaround -> name)
    in the dumped string before writing it down to a json file
    :param ts: The Terrascript object
    :param export_path: The path to save the json file in
    :return: None
    """
    try:
        with open(export_path, 'w') as f:
            ts_as_string = ts.dump()
            # W/A terrascript naming issues
            ts_as_string = ts_as_string.replace("name_workaround", "name")
            ts_as_string = ts_as_string.replace("network_interface2", "network_interface")
            ts_as_string = ts_as_string.replace("disk2", "disk")
            f.write(ts_as_string)
    except IOError as error:
        print(f"{error}")
        exit(1)


def write_object_to_yaml(o, export_path):
    try:
        with open(export_path, 'w') as f:
            yaml.dump(o, f, allow_unicode=True, default_flow_style=False)
    except IOError as error:
        print(f"{error.message}")
        exit(-1)


def read_yaml_file(file_path: str) -> Dict[Any, Any]:
    """
    Read the content of a yaml file
    """
    try:
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    except IOError as error:
        print(f"{error.message}")
        exit(1)


def string_to_sha3_512(string_to_hash):
    m = sha3_512()
    m.update(string_to_hash.encode())
    return m.hexdigest()


def subprocess_run_command(cmd: str, validate_success: bool = False) -> None:
    """
    Run a shell command synchronously, printing the output to stdout.
    :param cmd: The command to run
    :param validate_success: Whether to raise CalledProcessError if the process returned a non-zero return code
    """
    logger.info("----------------------------------------")
    logger.info(cmd)
    logger.info(f"Start time: {datetime.now()}")
    logger.info("----------------------------------------")
    subprocess.run(cmd.split(), check=validate_success)
    logger.info(f"End time: {datetime.now()}")


def subprocess_run_asynchronous_command(cmd: str) -> subprocess.Popen:
    """
    Run a shell command asynchronously, printing the output to stdout.
    :param cmd: The command to run
    """
    logger.info("----------------------------------------")
    logger.info("Running command asynchronously:")
    logger.info(cmd)
    logger.info(f"Start time: {datetime.now()}")
    logger.info("----------------------------------------")
    return subprocess.Popen(cmd.split())


# def generate_ssh_key_pair(private_key_path, public_key_path):
#     private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
#     private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
#                                                 encryption_algorithm=serialization.NoEncryption(),
#                                                 format=serialization.PrivateFormat.TraditionalOpenSSL)
#     with Path(private_key_path).open('w') as private_key_file:
#         private_key_file.write(private_key_pem.decode("utf-8"))
#     public_key = private_key.public_key()
#     public_key_openssh = public_key.public_bytes(encoding=serialization.Encoding.OpenSSH,
#                                                  format=serialization.PublicFormat.OpenSSH)
#     public_key_str = public_key_openssh.decode("utf-8")
#     with Path(public_key_path).open('w') as public_key_file:
#         public_key_file.write(public_key_openssh.decode("utf-8"))
#     return public_key_str

# todo - move all SC tools to use common.logger.Logger() instead of this function
def initiate_logger(logger_name: str = None, verbose: bool = False, log_file_path: str = "") -> logging.Logger:
    """
    NOTE ---- Do not use this function anymore - use common.logger.Logger() instead ----
    Initiate a logger
    :param logger_name: The loggers name
    :param verbose: Whether to log debug information
    :param log_file_path: If specified, log also to a file in log_file_path. If log_file_path contains '*' sign,
    replace it with the current time
    :return: A logger object
    """
    script_logger = logging.getLogger(logger_name)
    formatter = logging.Formatter(DEFAULT_LOGGER_FORMAT)
    if verbose:
        log_level = logging.DEBUG
    else:
        log_level = DEFAULT_LOGGING_LEVEL
    logging.basicConfig(format=DEFAULT_LOGGER_FORMAT, level=log_level)
    if log_file_path:
        log_file_path = log_file_path.replace("*", datetime.now().strftime("%Y-%m-%d-%H.%M.%S"))
        fh = logging.FileHandler(Path(log_file_path))
        fh.setLevel(log_level)
        fh.setFormatter(formatter)
        script_logger.addHandler(fh)
    return script_logger


try:
    import xlrd
    import mmap

    def xlsx_dict_reader(sheet: xlrd.sheet.Sheet) -> Generator[Dict[str, str], Any, None]:
        """ Return a DictReader like generator from an xlsx sheet """
        def item(i, j):
            return sheet.cell_value(0, j), sheet.cell_value(i, j)

        return (dict(item(i, j) for j in range(sheet.ncols)) for i in range(1, sheet.nrows))

except ImportError:
    xlsx_dict_reader = None
