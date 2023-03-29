#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A script for gathering data from various RHEL-like errata databses
"""

import argparse
import logging
import urllib.request
import json
import sys
import math
import datetime
import requests

LOGGER = logging.getLogger("gather_data")
"""
logging: Logger instance
"""
LOG_LEVEL = None
"""
logging: Logger level
"""
__version__ = "0.1.0"
"""
str: Program version
"""


def _get_date(timestamp):
    """
    Returns the datetime object from a string

    :param timestamp: Timestamp/string
    :type timestamp: str/int
    """
    if isinstance(timestamp, int):
        # UNIX timestamp
        try:
            _res = datetime.datetime.fromtimestamp(timestamp/1000).date()
        except ZeroDivisionError:
            _res = False
    else:
        # ISO 8601 short
        try:
            _res = datetime.datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ').date()
        except ValueError as err:
            if "does not match format" in str(err).lower():
                LOGGER.debug("Invalid format, going on")

        # ISO 8601 long
        try:
            _res = datetime.datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ').date()
        except ValueError as err:
            if "does not match format" in str(err).lower():
                LOGGER.debug("Invalid format, going on")
    return _res


def _get_erratum(errata, erratum_name, distribution=None):
    """
    Returns a single erratum from a list

    :param errata: List of errata
    :type errata: list
    :param erratum_name: Erratum name

    :type erratum_name: str
    :param distribution: Linux distribution (rockylinux, almalinux)
    :type distribution: str
    """
    _name = _replace_erratum_prefix(erratum_name, distribution)
    LOGGER.debug("Trying to find '%s' as '%s'", erratum_name, _name)
    if distribution == 'rockylinux':
        _res = [x for x in errata if x['name'] == _name]
    elif distribution == 'almalinux':
        _res = [x for x in errata if x['updateinfo_id'] == _name]
    else:
        _res = False
    return _res


def _replace_erratum_prefix(erratum_name, distribution='rhel'):
    """
    Replaces a distribution-specific erratum prefix

    :param erratum_name: Erratum name
    :type erratum_type: str
    :param distribution: Distribution name (rhel, rockylinux, almalinux)
    :type distribution: str
    """
    LOGGER.debug(
        "Converting '%s' for distribution '%s'",
        erratum_name,
        distribution
    )
    if distribution == "rhel":
        _err = f"RHSA-{erratum_name[5:]}"
    elif distribution == "rockylinux":
        _err = f"RLSA-{erratum_name[5:]}"
    elif distribution == "almalinux":
        _err = f"ALSA-{erratum_name[5:]}"
    else:
        _err = False
    return _err


def calculate_deltas(rhel_file, rockylinux_file, almalinux_file, release):
    """
    Calculates delta between distributions

    :param rhel_file: RHEL errata cache filename
    :type rhel_file: str
    :param rockylinux_file: Rocky Linux errata cache filename
    :type rockylinux_file: str
    :param almalinux_file: AlmaLinux errata cache filename
    :type almalinux_file: str
    :param release: distrubution release
    :type release: int
    """
    try:
        # load files
        with open(rhel_file, encoding="utf-8") as _file:
            _json = _file.read()
        rhel_errata = json.loads(_json)

        with open(rockylinux_file, encoding="utf-8") as _file:
            _json = _file.read()
        rockylinux_errata = json.loads(_json)

        with open(almalinux_file, encoding="utf-8") as _file:
            _json = _file.read()
        almalinux_errata = json.loads(_json)

        # scan RHEL errata
        _data = []
        for _erratum in rhel_errata:
            _entry = {}
            _rheldate = _get_date(_erratum['portal_publication_date'])
            LOGGER.debug(
                "Checking errata '%s' (%s) from %s...",
                _erratum['id'],
                _erratum['portal_synopsis'],
                _rheldate.strftime('%Y-%m-%d')
            )
            _entry['rhel_name'] = _erratum['id']
            _entry['rhel_date'] = _rheldate.strftime('%Y-%m-%d')

            # check for matching Rocky Linux erratum
            _rocky = _get_erratum(rockylinux_errata, _erratum['id'], 'rockylinux')
            if _rocky:
                _rockydate = _get_date(_rocky[0]['publishedAt'])
                LOGGER.debug(
                    "Found matching Rocky Linux erratum '%s' (%s) from %s...",
                    _rocky[0]['name'],
                    _rocky[0]['synopsis'],
                    _rockydate
                )
                _entry['rockylinux_name'] = _rocky[0]['name']
                _entry['rockylinux_date'] = _rockydate.strftime('%Y-%m-%d')
                _entry['rockylinux_drift'] = (_rockydate - _rheldate).days
            else:
                LOGGER.info(
                    "Found no matching Rocky Linux erratum for '%s' (%s)",
                    _erratum['id'],
                    _erratum['portal_synopsis']
                )
                _entry['rockylinux_name'] = None
                _entry['rockylinux_date'] = None
                _entry['rockylinux_drift'] = None

            # check for matching AlmaLinux erratum
            _alma = _get_erratum(almalinux_errata, _erratum['id'], 'almalinux')
            if _alma:
                _almadate = _get_date(_alma[0]['issued_date']['$date'])
                LOGGER.debug(
                    "Found matching AlmaLinux erratum '%s' (%s) from %s...",
                    _alma[0]['updateinfo_id'],
                    _alma[0]['title'],
                    _almadate
                )
                _entry['almalinux_name'] = _alma[0]['updateinfo_id']
                _entry['almalinux_date'] = _almadate.strftime('%Y-%m-%d')
                _entry['almalinux_drift'] = (_almadate - _rheldate).days
            else:
                LOGGER.info(
                    "Found no matching AlmaLinux erratum for '%s' (%s)",
                    _erratum['id'],
                    _erratum['portal_synopsis']
                )
                _entry['almalinux_name'] = None
                _entry['almalinux_date'] = None
                _entry['almalinux_drift'] = None

            # add dataset to list
            _data.append(_entry)

        # store all the differences
        _output = f"downspeeds-{release}.json"
        with open(_output, 'w', encoding="utf-8") as _f:
            json.dump(_data, _f)
        LOGGER.info("Stored differences in '%s'", _output)

    except PermissionError:
        LOGGER.error("Cache files can't be accessed - check permissions")
    except FileNotFoundError:
        LOGGER.error("At least one cached file not found")


def gather_rhel(release, options):
    """
    Gathers RHEL database information

    :param release: Target release
    :type release: int
    """
    _url = fr"https://access.redhat.com/hydra/rest/search/kcs?q=*:*&start=0&fq=portal_advisory_type:(%22Security%20Advisory%22)%20AND%20documentKind:(%22Errata%22)&fq=portal_product_filter:Red\%20Hat\%20Enterprise\%20Linux|*|{release}|*&facet.mincount=1&rows=5000&fl=id,portal_severity,portal_product_names,portal_publication_date,portal_synopsis,view_uri,allTitle&sort=portal_publication_date%20desc&p=1"
    _file = f"rhel-{release}.json"

    if options.use_cache and check_rhel_file(_file):
        pass
    else:
        # download file
        _errata = []
        LOGGER.debug("Gathering errata from '%s'", _url)
        try:
            # gather all errata
            _limit = 5000
            _hits = json.loads(requests.get(f"{_url}").text)
            _pages = math.ceil(_hits['response']['numFound']/_limit)
            LOGGER.debug("Found %s errata in %s page(s)", _hits['response']['numFound'], _pages)
            _errata.extend(_hits['response']['docs'])
            # write to disk
            LOGGER.debug("Writing %s gathered errata to cache file", len(_errata))
            with open(_file, 'w', encoding="utf-8") as _f:
                json.dump(_errata, _f)
        except PermissionError:
            LOGGER.error("Cache file can't be accessed - check permissions")
            sys.exit(1)
        except urllib.error.URLError:
            LOGGER.error("URL not found or accessible, check internet connection")


def check_rhel_file(file):
    """
    Checks whether an RHEL cache file is valid

    :param file: Target file name
    :type file: str
    """
    LOGGER.debug("Checking integrity for RHEL errata cache file '%s'", file)
    try:
        # load file
        with open(file, encoding="utf-8") as _file:
            _json = _file.read()
        parsed_json = json.loads(_json)

        # check for results
        if len(parsed_json) < 1:
            LOGGER.error("Cached file for RHEL contains no errata, re-downloading")
            return False

        # check for required fields
        for _field in ['id', 'portal_publication_date', 'portal_synopsis']:
            if _field not in parsed_json[0].keys():
                LOGGER.error("Cached file for RHEL is invalid, re-downloading")
                return False
    except json.decoder.JSONDecodeError:
        LOGGER.error("Cached file for RHEL empty or invalid, re-downloading")
        return False
    except PermissionError:
        LOGGER.error("Cache file can't be accessed - check permissions")
        sys.exit(1)
    except FileNotFoundError:
        LOGGER.error("Cached file for RHEL not found, re-downloading")
        return False
    LOGGER.info("Using valid cached RHEL database file")
    return True


def gather_almalinux(release, options):
    """
    Gathers AlmaLinux database information

    :param release: Target release
    :type release: int
    """
    _url = f"https://errata.almalinux.org/{release}/errata.json"
    _file = f"almalinux-{release}.json"

    if options.use_cache and check_almalinux_file(_file):
        pass
    else:
        # download file
        LOGGER.debug("Downloading file '%s' to '%s'", _url, _file)
        try:
            urllib.request.urlretrieve(_url, _file)
        except PermissionError:
            LOGGER.error("File can't be written - check permissions")
            sys.exit(1)
        except urllib.error.URLError:
            LOGGER.error("URL not found or accessible, check internet connection")


def check_almalinux_file(file):
    """
    Checks whether an AlmaLinux cache file is valid

    :param file: Target file name
    :type file: str
    """
    LOGGER.debug("Checking integrity for AlmaLinux errata cache file '%s'", file)
    try:
        # load file
        with open(file, encoding="utf-8") as _file:
            _json = _file.read()
        parsed_json = json.loads(_json)

        # check for results
        if len(parsed_json) < 1:
            LOGGER.error("Cached file for AlmaLinux contains no errata, re-downloading")
            return False

        # check for required fields
        for _field in ['updateinfo_id', 'issued_date', 'title']:
            if _field not in parsed_json[0].keys():
                LOGGER.error("Cached file for AlmaLinux is invalid, re-downloading")
                return False
    except json.decoder.JSONDecodeError:
        LOGGER.error("Cached file for AlmaLinux empty or invalid, re-downloading")
        return False
    except PermissionError:
        LOGGER.error("Cache file can't be accessed - check permissions")
        sys.exit(1)
    except FileNotFoundError:
        LOGGER.error("Cached file for AlmaLinux not found, re-downloading")
        return False
    LOGGER.info("Using valid cached AlmaLinux database file")
    return True


def gather_rockylinux(release, options):
    """
    Gathers Rocky Linux database information

    :param release: Target release
    :type release: int
    """
    _url = f"http://errata.rockylinux.org/api/v2/advisories?filters.product=Rocky%20Linux%20{release}&filters.type=TYPE_SECURITY&filters.fetchRelated=false"
    _file = f"rockylinux-{release}.json"

    if options.use_cache and check_rockylinux_file(_file):
        pass
    else:
        # download file
        _errata = []
        LOGGER.debug("Gathering errata from '%s'", _url)
        try:
            # gather all errata
            _limit = 100
            _hits = json.loads(requests.get(f"{_url}&page=0&limit={_limit}").text)
            _pages = math.ceil(_hits['total']/_limit)
            LOGGER.debug("Found %s errata in %s page(s)", _hits['total'], _pages)
            i = 0
            while i < _pages:
                LOGGER.debug("Loading errata #%s", i+1)
                _hits = json.loads(requests.get(f"{_url}&page={i}&limit={_limit}").text)
                _errata.extend(_hits['advisories'])
                i=i+1
            # write to disk
            LOGGER.debug("Writing %s gathered errata to cache file", len(_errata))
            with open(_file, 'w', encoding="utf-8") as _f:
                json.dump(_errata, _f)
        except PermissionError:
            LOGGER.error("Cache file can't be accessed - check permissions")
            sys.exit(1)
        except urllib.error.URLError:
            LOGGER.error("URL not found or accessible, check internet connection")


def check_rockylinux_file(file):
    """
    Checks whether an Rocky Linux cache file is valid

    :param file: Target file name
    :type file: str
    """
    LOGGER.debug("Checking integrity for Rocky Linux errata cache file '%s'", file)
    try:
        # load file
        with open(file, encoding="utf-8") as _file:
            _json = _file.read()
        parsed_json = json.loads(_json)

        # check for results
        if len(parsed_json) < 1:
            LOGGER.error("Cached file for Rocky Linux contains no errata, re-downloading")
            return False

        # check for required fields
        for _field in ['name', 'publishedAt', 'synopsis']:
            if _field not in parsed_json[0].keys():
                LOGGER.error("Cached file for Rocky Linux is invalid, re-downloading")
                return False
    except json.decoder.JSONDecodeError:
        LOGGER.error("Cached file for Rocky Linux empty or invalid, re-downloading")
        return False
    except PermissionError:
        LOGGER.error("Cache file can't be accessed - check permissions")
        sys.exit(1)
    except FileNotFoundError:
        LOGGER.error("Cached file for Rocky Linux not found, re-downloading")
        return False
    LOGGER.info("Using valid cached Rocky Linux database file")
    return True


def main(options, args):
    """
    Main function, starts the logic based on parameters
    """
    LOGGER.debug("Options: %s", options)
    LOGGER.debug("Arguments: %s", args)

    LOGGER.info("Gathering data...")
    gather_rhel(options.target_release, options)
    gather_almalinux(options.target_release, options)
    gather_rockylinux(options.target_release, options)

    LOGGER.debug("Analyzing data...")
    calculate_deltas(
        f"rhel-{options.target_release}.json",
        f"rockylinux-{options.target_release}.json",
        f"almalinux-{options.target_release}.json",
        options.target_release
    )


def parse_options(args=None):
    """
    Parses options and arguments
    """
    desc = """%(prog)s gathers data from the RHSA database
and various RHEL-downstream errata databases and exports them for comparison.
    """
    epilog = """Check-out the website for more details:
     http://github.com/stdevel/rhel-downspeeds"""
    parser = argparse.ArgumentParser(description=desc, epilog=epilog)
    parser.add_argument("--version", action="version", version=__version__)

    # define option groups
    gen_opts = parser.add_argument_group("generic arguments")
    data_opts = parser.add_argument_group("dataset arguments")

    # GENERIC ARGUMENTS
    # -d / --debug
    gen_opts.add_argument(
        "-d",
        "--debug",
        dest="generic_debug",
        default=False,
        action="store_true",
        help="enable debugging outputs (default: no)",
    )
    # -c / --use-cache
    gen_opts.add_argument(
        "-c",
        "--use-cache",
        dest="use_cache",
        default=False,
        action="store_true",
        help="uses cached files instead of gathering data (useful for debugging, default: no)"
    )

    # DATASET ARGUMENTS
    # -r / --release
    data_opts.add_argument(
        "-r",
        "--release",
        dest="target_release",
        default=9,
        choices=[8,9],
        type=int,
        action="store",
        help="defines the target RHELease (default: 9)"
    )

    # parse options and arguments
    options = parser.parse_args()
    return (options, args)


def cli():
    """
    This functions initializes the CLI interface
    """
    global LOG_LEVEL
    (options, args) = parse_options()

    # set logging level
    logging.basicConfig()
    if options.generic_debug:
        LOG_LEVEL = logging.DEBUG
    else:
        LOG_LEVEL = logging.INFO
    LOGGER.setLevel(LOG_LEVEL)

    main(options, args)


if __name__ == "__main__":
    cli()
