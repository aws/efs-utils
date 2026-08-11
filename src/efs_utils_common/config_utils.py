#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import logging
import os
import sys
from logging.handlers import RotatingFileHandler

try:
    from configparser import ConfigParser, NoOptionError, NoSectionError
except ImportError:
    import ConfigParser
    from ConfigParser import NoOptionError, NoSectionError

from efs_utils_common.constants import (
    CONFIG_FILE,
    CONFIG_SECTION,
    DEFAULT_URL_REQUEST_TIMEOUT_SEC,
    LOG_DIR,
    LOG_FILE,
    MOUNT_TYPE_EFS,
    MOUNT_TYPE_S3FILES,
    S3FILES_CONFIG_FILE,
    URL_REQUEST_TIMEOUT_ITEM,
)
from efs_utils_common.context import MountContext


def get_config_file_path():
    context = MountContext()

    if context.config_file_path is not None:
        return context.config_file_path

    if context.mount_type == MOUNT_TYPE_S3FILES:
        return S3FILES_CONFIG_FILE
    elif context.mount_type == MOUNT_TYPE_EFS:
        return CONFIG_FILE

    raise ValueError("Unable to determine config file path")


def get_boolean_config_item_value(
    config, config_section, config_item, default_value, emit_warning_message=True
):
    warning_message = None
    if not config.has_section(config_section):
        warning_message = (
            "Warning: config file does not have section %s." % config_section
        )
    elif not config.has_option(config_section, config_item):
        warning_message = (
            "Warning: config file does not have %s item in section %s."
            % (config_item, config_section)
        )

    if warning_message:
        if emit_warning_message:
            sys.stdout.write(
                "%s. You should be able to find a new config file in the same folder as current config file %s. "
                "Consider update the new config file to latest config file. Use the default value [%s = %s]."
                % (warning_message, get_config_file_path(), config_item, default_value)
            )
        return default_value
    return config.getboolean(config_section, config_item)


def is_ocsp_enabled(config, options):
    if "ocsp" in options:
        return True
    elif "noocsp" in options:
        return False
    else:
        return get_boolean_config_item_value(
            config, CONFIG_SECTION, "stunnel_check_cert_validity", default_value=False
        )


def get_int_value_from_config_file(config, config_name, default_config_value):
    val = default_config_value
    try:
        value_from_config = config.get(CONFIG_SECTION, config_name)
        try:
            if int(value_from_config) > 0:
                val = int(value_from_config)
            else:
                logging.debug(
                    '%s value in config file "%s" is lower than 1. Defaulting to %d.',
                    config_name,
                    get_config_file_path(),
                    default_config_value,
                )
        except ValueError:
            logging.debug(
                'Bad %s, "%s", in config file "%s". Defaulting to %d.',
                config_name,
                value_from_config,
                get_config_file_path(),
                default_config_value,
            )
    except NoOptionError:
        logging.debug(
            'No %s value in config file "%s". Defaulting to %d.',
            config_name,
            get_config_file_path(),
            default_config_value,
        )

    return val


def read_config(config_file=CONFIG_FILE):
    try:
        p = ConfigParser.SafeConfigParser()
    except AttributeError:
        p = ConfigParser()
    p.read(config_file)
    return p


# Retrieve and parse the logging level from the config file.
def get_log_level_from_config(config):
    raw_level = config.get(CONFIG_SECTION, "logging_level")
    levels = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }
    level = levels.get(raw_level.lower())
    level_error = False

    if not level:
        # delay logging error about malformed log level until after logging is configured
        level_error = True
        level = logging.INFO

    return (level, raw_level, level_error)


# Convert the log level provided in the config into a log level string
# that is understandable by efs-proxy
def get_efs_proxy_log_level(config):
    level, raw_level, level_error = get_log_level_from_config(config)
    if level_error:
        return "info"

    # Efs-proxy does not have a CRITICAL log level
    if level == logging.CRITICAL:
        return "error"

    return raw_level.lower()


def bootstrap_logging(config, log_dir=LOG_DIR):
    level, raw_level, level_error = get_log_level_from_config(config)

    max_bytes = config.getint(CONFIG_SECTION, "logging_max_bytes")
    file_count = config.getint(CONFIG_SECTION, "logging_file_count")

    handler = RotatingFileHandler(
        os.path.join(log_dir, LOG_FILE), maxBytes=max_bytes, backupCount=file_count
    )
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S %Z",
        )
    )

    logger = logging.getLogger()
    logger.setLevel(level)
    logger.addHandler(handler)

    if level_error:
        logging.error(
            'Malformed logging level "%s", setting logging level to %s',
            raw_level,
            level,
        )


def get_url_request_timeout(config, config_section=CONFIG_SECTION):
    """Read the URL request timeout from config, falling back to DEFAULT_URL_REQUEST_TIMEOUT_SEC.

    Reads the 'url_request_timeout_sec' option from the given config section.
    If the option is not set, returns the default. If the value is invalid
    (non-numeric), logs a warning and returns the default.
    """
    try:
        timeout = config.getfloat(config_section, URL_REQUEST_TIMEOUT_ITEM)
        if timeout <= 0:
            logging.warning(
                "Invalid value for '%s' in config section [%s]: %s "
                "(must be positive), falling back to %ss",
                URL_REQUEST_TIMEOUT_ITEM,
                config_section,
                timeout,
                DEFAULT_URL_REQUEST_TIMEOUT_SEC,
            )
            return DEFAULT_URL_REQUEST_TIMEOUT_SEC
        if timeout != DEFAULT_URL_REQUEST_TIMEOUT_SEC:
            logging.debug(
                "Using configured %s=%s from section [%s]",
                URL_REQUEST_TIMEOUT_ITEM,
                timeout,
                config_section,
            )
        return timeout
    except (NoOptionError, NoSectionError):
        return DEFAULT_URL_REQUEST_TIMEOUT_SEC
    except ValueError:
        logging.warning(
            "Invalid (non-numeric) value for '%s' in config section [%s], "
            "falling back to %ss",
            URL_REQUEST_TIMEOUT_ITEM,
            config_section,
            DEFAULT_URL_REQUEST_TIMEOUT_SEC,
        )
        return DEFAULT_URL_REQUEST_TIMEOUT_SEC
