#!/usr/bin/python

# Copyright 2017 Cyber Defense Institute, Inc. 
# A modified version of amcache.py
# https://github.com/williballenthin/python-registry/blob/master/samples/amcache.py

#    This file is part of python-registry.
#
#   Copyright 2015 Will Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>Exe
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import sys
import logging
import datetime
from collections import namedtuple
import argparse
import unicodecsv
from Registry import Registry
from Registry.RegistryParse import parse_windows_timestamp as _parse_windows_timestamp
from parserutility import utility
import os
import re
import time

g_logger = logging.getLogger("amcache")
Field = namedtuple("Field", ["name", "getter", "collname"])

def make_value_getter(value_name):
    """ return a function that fetches the value from the registry key """
    def _value_getter(key):
        try:
            return key.value(value_name).value()
        except Registry.RegistryValueNotFoundException:
            return None
    return _value_getter

def make_windows_timestamp_value_getter(value_name):
    """
    return a function that fetches the value from the registry key
      as a Windows timestamp.
    """
    f = make_value_getter(value_name)
    def _value_getter(key):
        try:
            return parse_windows_timestamp(f(key) or 0)
        except ValueError:
            g_logger.debug("value error: " + str(key))
            return datetime.datetime.min
    return _value_getter

def parse_unix_timestamp(qword):
    if (qword) == 0:
        return ""
    try:
        return datetime.datetime.fromtimestamp(qword)
    except ValueError:
        return ""

def parse_windows_timestamp(qword):
    try:
        return utility().get_timestamp_str(qword)
    except ValueError:
        return ""
    except OSError:
        return ""

def make_unix_timestamp_value_getter(value_name):
    """
    return a function that fetches the value from the registry key
      as a UNIX timestamp.
    """
    f = make_value_getter(value_name)
    def _value_getter(key):
        try:
            return parse_unix_timestamp(f(key) or 0)
        except ValueError:
            g_logger.debug("value error: " + str(key))
            return ""
    return _value_getter

UNIX_TIMESTAMP_ZERO = parse_unix_timestamp(0)
WINDOWS_TIMESTAMP_ZERO = parse_windows_timestamp(0)

def make_timezone_getter():
    return utility().get_timezone_str()

def make_trimming_timestamp(timestamp):
    ## adjust to local time
    timezone = make_timezone_getter()
    diff_seconds = time.timezone
    diff_abs = abs(diff_seconds)
    delta = datetime.timedelta(seconds=diff_abs)
    localtime = timestamp + delta
    trimed_timestamp = localtime.strftime('%Y/%m/%d %H:%M:%S')
    ms = "%03d"%(timestamp.microsecond / 1000.0)
    return trimed_timestamp + "." + ms

def make_date_from_string(value_name):
    f = make_value_getter(value_name)
    def _value_getter(key):
        try:
            ## adjust to local time
            timezone = make_timezone_getter()
            value_date = datetime.datetime.strptime(f(key), '%m/%d/%Y %H:%M:%S')
            diff_seconds = time.timezone
            diff_abs = abs(diff_seconds)
            delta = datetime.timedelta(seconds=diff_abs)
            localtime = value_date + delta
            return localtime.strftime('%Y/%m/%d %H:%M:%S')
        except ValueError:
            g_logger.debug("value error : " + str(key))
            return ""
        except TypeError:
            g_logger.debug("type error : " + str(key))
            return ""
    return _value_getter

# via: http://www.swiftforensics.com/2013/12/amcachehve-in-windows-8-goldmine-for.html
#Product Name    UNICODE string
#==============================================================================
#0   Product Name    UNICODE string
#1   Company Name    UNICODE string
#2   File version number only    UNICODE string
#3   Language code (1033 for en-US)  DWORD
#4   SwitchBackContext   QWORD
#5   File Version    UNICODE string
#6   File Size (in bytes)    DWORD
#7   PE Header field - SizeOfImage   DWORD
#8   Hash of PE Header (unknown algorithm)   UNICODE string
#9   PE Header field - Checksum  DWORD
#a   Unknown QWORD
#b   Unknown QWORD
#c   File Description    UNICODE string
#d   Unknown, maybe Major & Minor OS version DWORD
#f   Linker (Compile time) Timestamp DWORD - Unix time
#10  Unknown DWORD
#11  Last Modified Timestamp FILETIME
#12  Created Timestamp   FILETIME
#15  Full path to file   UNICODE string
#16  Unknown DWORD
#17  Last Modified Timestamp 2   FILETIME
#100 Program ID  UNICODE string
#101 SHA1 hash of file

# note: order here implicitly orders CSV column ordering cause I'm lazy
FIELDS = [
    Field("path", make_value_getter("15"), "File Path"),
    Field("source_key_timestamp", lambda key: make_trimming_timestamp(key.timestamp()), "Source Key Timestamp"),
    Field("created_timestamp", make_windows_timestamp_value_getter("12"), "Created Timestamp"),
    Field("modified_timestamp", make_windows_timestamp_value_getter("11"), "Modified Timestamp"),
    Field("modified_timestamp2", make_windows_timestamp_value_getter("17"), "Modified Timestamp2"),
    Field("linker_timestamp", make_unix_timestamp_value_getter("f"), "Linker Timestamp"),
    Field("timezone", lambda key: make_timezone_getter(), "Time Zone"),
    Field("sha1", make_value_getter("101"), "SHA1 Hash"),
    Field("size", make_value_getter("6"), "File Size"),
    Field("file_description", make_value_getter("c"), "File Description"),
    Field("product", make_value_getter("0"), "Product Name"),
    Field("company", make_value_getter("1"), "Company Name"),
    Field("pe_sizeofimage", make_value_getter("7"), "Size of Image"),
    Field("version_number", make_value_getter("2"), "Version Number"),
    Field("version", make_value_getter("5"), "Version"),
    Field("language", make_value_getter("3"), "Language Code"),
    Field("header_hash", make_value_getter("8"), "Hash of PE Header"),
    Field("pe_checksum", make_value_getter("9"), "PE Checksum"),
    Field("id", make_value_getter("100"), "Program ID"),
    Field("switchbackcontext", make_value_getter("4"), "Switch Back Context"),
]

# via: https://binaryforay.blogspot.jp/2017/10/amcache-still-rules-everything-around.html
# note: The time informations (like source key timestamp, install date...) is adjusted to the local time of the analysis PC.
#       These NOT adjusted to the local time of the target PC, may be it deferent timezone.
FIELDS_INVENTORY_APP = [
    Field("program_id", make_value_getter("ProgramId"), "Program ID"),
    Field("app_source_key_timestamp", lambda key: make_trimming_timestamp(key.timestamp()), "App Source Key Timestamp"),
    Field("program_instance_id", make_value_getter("ProgramInstanceId"), "Program Instance Id"),
    Field("app_name", make_value_getter("Name"), "App Name"),
    Field("app_version", make_value_getter("Version"), "App Version"),
    Field("app_publisher", make_value_getter("Publisher"), "App Publisher"),
    Field("app_language_code", make_value_getter("Language"), "App Language"),
    Field("app_source", make_value_getter("Source"), "App Source"),
    Field("type", make_value_getter("Type"), "Type"),
    Field("store_app_type", make_value_getter("StoreAppType"), "Store App Type"),
    Field("msi_package_code", make_value_getter("MsiPackageCode"), "Msi Package Code"),
    Field("msi_product_code", make_value_getter("MsiProductCode"), "Msi Product Code"),
    Field("hidden_arp", make_value_getter("HiddenArp"), "Hidden Arp"),
    Field("inbox_modern_app", make_value_getter("InboxModernApp"), "Inbox Modern App"),
    Field("os_version", make_value_getter("OSVersionAtInstallTime"), "OS Version At Install Time"),
    Field("install_date", make_date_from_string("InstallDate"),"Install Date"),
    Field("package_full_name", make_value_getter("PackageFullName"),"Package Full Name"),
    Field("manifest_path", make_value_getter("ManifestPath"),"Manifest Path"),
    Field("bundle_manifest_path", make_value_getter("BundleManifestPath"),"Bundle Manifest Path"),
    Field("rootdir_path", make_value_getter("RootDirPath"),"RootDir Path"),
    Field("uninstall_string", make_value_getter("UninstallString"),"Uninstall String"),
    Field("registry_key_path", make_value_getter("RegistryKeyPath"),"Registry Key Path"),
]

FIELDS_INVENTORY_FILE = [
    Field("program_id", make_value_getter("ProgramId"),"Program ID"),
    Field("file_source_key_timestamp", lambda key: make_trimming_timestamp(key.timestamp()), "File Source Key Timestamp"),
    Field("file_id", make_value_getter("FileId"),"File ID (SHA-1)"),
    Field("lower_case_log_path", make_value_getter("LowerCaseLongPath"),"File Path"),
    Field("long_path_hash", make_value_getter("LongPathHash"),"Long Path Hash"),
    Field("file_name", make_value_getter("Name"),"File Name"),
    Field("file_publisher", make_value_getter("Publisher"),"File Publisher"),
    Field("file_version", make_value_getter("Version"),"File Version"),
    Field("bin_file_version", make_value_getter("BinFileVersion"),"Bin File Version"),
    Field("binary_type", make_value_getter("BinaryType"),"Binary Type"),
    Field("product_name", make_value_getter("ProductName"),"Product Name"),
    Field("product_version", make_value_getter("ProductVersion"),"Product Version"),
    Field("link_date", make_date_from_string("LinkDate"),"Link Date"),
    Field("bin_product_version", make_value_getter("BinProductVersion"),"Bin Product Version"),
    Field("file_size", make_value_getter("Size"),"File Size"),
    Field("file_language", make_value_getter("Language"),"File Language"),
    Field("is_pefile", make_value_getter("IsPeFile"),"Is PeFile"),
    Field("is_os_component", make_value_getter("IsOsComponent"),"Is Os Component"),
]

FIELDS_UPDATE1709_DATASTORE = FIELDS_INVENTORY_APP + FIELDS_INVENTORY_FILE[1:] + [Field("timezone", lambda key: make_timezone_getter(), "Time Zone")]

# Please change the order of this array when you want to replace the display column of output csv
FIELDS_UPDATE1709 = [
    Field("lower_case_log_path", make_value_getter("LowerCaseLongPath"),"File Path"),
    Field("file_id", make_value_getter("FileId"),"File ID (SHA1)"),
    Field("file_size", make_value_getter("Size"),"File Size"),
    Field("link_date", make_date_from_string("LinkDate"),"Link Date"),
    Field("app_source_key_timestamp", lambda key: make_trimming_timestamp(key.timestamp()), "App Source Key Timestamp"),
    Field("file_source_key_timestamp", lambda key: make_trimming_timestamp(key.timestamp()), "File Source Key Timestamp"),
    Field("install_date", make_date_from_string("InstallDate"),"Install Date"),
    Field("timezone", lambda key: make_timezone_getter(), "Time Zone"),
    Field("app_name", make_value_getter("Name"), "App Name"),
    Field("product_name", make_value_getter("ProductName"),"Product Name"),
    Field("app_version", make_value_getter("Version"), "App Version"),
    Field("app_publisher", make_value_getter("Publisher"), "App Publisher"),
    Field("app_language_code", make_value_getter("Language"), "App Language"),
    Field("app_source", make_value_getter("Source"), "App Source"),
    Field("type", make_value_getter("Type"), "Type"),
    Field("store_app_type", make_value_getter("StoreAppType"), "Store App Type"),
    Field("msi_package_code", make_value_getter("MsiPackageCode"), "Msi Package Code"),
    Field("msi_product_code", make_value_getter("MsiProductCode"), "Msi Product Code"),
    Field("hidden_arp", make_value_getter("HiddenArp"), "Hidden Arp"),
    Field("inbox_modern_app", make_value_getter("InboxModernApp"), "Inbox Modern App"),
    Field("os_version", make_value_getter("OSVersionAtInstallTime"), "OS Version At Install Time"),
    Field("package_full_name", make_value_getter("PackageFullName"),"Package Full Name"),
    Field("manifest_path", make_value_getter("ManifestPath"),"Manifest Path"),
    Field("bundle_manifest_path", make_value_getter("BundleManifestPath"),"Bundle Manifest Path"),
    Field("rootdir_path", make_value_getter("RootDirPath"),"RootDir Path"),
    Field("uninstall_string", make_value_getter("UninstallString"),"Uninstall String"),
    Field("registry_key_path", make_value_getter("RegistryKeyPath"),"Registry Key Path"),
    Field("long_path_hash", make_value_getter("LongPathHash"),"Long Path Hash"),
    Field("file_name", make_value_getter("Name"),"File Name"),
    Field("file_publisher", make_value_getter("Publisher"),"File Publisher"),
    Field("file_version", make_value_getter("Version"),"File Version"),
    Field("bin_file_version", make_value_getter("BinFileVersion"),"Bin File Version"),
    Field("binary_type", make_value_getter("BinaryType"),"Binary Type"),
    Field("product_version", make_value_getter("ProductVersion"),"Product Version"),
    Field("bin_product_version", make_value_getter("BinProductVersion"),"Bin Product Version"),
    Field("file_language", make_value_getter("Language"),"File Language"),
    Field("is_pefile", make_value_getter("IsPeFile"),"Is PeFile"),
    Field("is_os_component", make_value_getter("IsOsComponent"),"Is Os Component"),
    Field("program_id", make_value_getter("ProgramId"), "Program ID"),
    Field("program_instance_id", make_value_getter("ProgramInstanceId"), "Program Instance Id"),
]

ExecutionEntry = namedtuple("ExecutionEntry", [e.name for e in FIELDS])
ExecutionEntryInventoryApp = namedtuple("ExecutionEntryInventoryApp", [e.name for e in FIELDS_INVENTORY_APP])
ExecutionEntryInventoryFile = namedtuple("ExecutionEntryInventoryFile", [e.name for e in FIELDS_INVENTORY_FILE])
ExecutionEntryUpdate1709 = namedtuple("ExecutionEntrypdate1709", [e.name for e in FIELDS_UPDATE1709_DATASTORE])

def parse_execution_entry(key, fields):
    if fields == FIELDS:
        return ExecutionEntry(**dict((e.name, e.getter(key)) for e in fields))
    elif fields == FIELDS_INVENTORY_APP:
        return ExecutionEntryInventoryApp(**dict((e.name, e.getter(key)) for e in fields))
    elif fields == FIELDS_INVENTORY_FILE:
        return ExecutionEntryInventoryFile(**dict((e.name, e.getter(key)) for e in fields))

class NotAnAmcacheHive(Exception):
    pass

def parse_execution_entries(registry, area, fields):
    try:
        volumes = registry.open(area)
    except Registry.RegistryKeyNotFoundException:
        raise NotAnAmcacheHive()

    ret = []

    if fields == FIELDS:
        for volumekey in volumes.subkeys():
            for filekey in volumekey.subkeys():
                ret.append(parse_execution_entry(filekey, fields))
    else:
        for volumekey in volumes.subkeys():
            ret.append(parse_execution_entry(volumekey, fields))
    return ret

TimelineEntry = namedtuple("TimelineEntry", ["timestamp", "type", "entry"])

def searchHiveFiles(fol):
    hivefiles = []
    for root, dirs, files in os.walk(fol):
        for ff in files:
            if not re.search(r'\.hve$', ff):
                continue
            hivefiles.append(os.path.join(root, ff))
    return hivefiles

def standardOutput(ee, file, pf, header_flag, fields):
    w = unicodecsv.writer(pf, delimiter="\t", lineterminator="\n", encoding="utf-8", quoting=unicodecsv.QUOTE_ALL)
    computer_name = utility().get_computer_name(file)
    if header_flag:
        w.writerow(["Computer Name"]+[e.collname for e in fields])
    for e in ee:
        w.writerow([computer_name]+[getattr(e, i.name) for i in fields])

def mergeRegistoryInfomation(inventoryapp, inventoryfile):
    find_app = []
    find_file = []
    merged = []

    for app_data in inventoryapp:
        for file_data in inventoryfile:
            if app_data.program_id == file_data.program_id:
                merged.append(ExecutionEntryUpdate1709(*(app_data+file_data[1:]+(utility().get_timezone_str(),))))
                find_app.append(app_data)
                find_file.append(file_data)

    leftovers_app = list(set(inventoryapp) - set(find_app))
    leftovers_file = list(set(inventoryfile) - set(find_file))

    for file_data in leftovers_file:
        merged.append(ExecutionEntryUpdate1709(*(("",)*22+file_data[1:]+(utility().get_timezone_str(),))))

    for app_data in leftovers_app:
        merged.append(ExecutionEntryUpdate1709(*(app_data+("",)*17+(utility().get_timezone_str(),))))

    return merged

def parseHive(file, outputdirectory, args, result_flag):
    r = Registry.Registry(file)
    entries = []
    entries_app = []
    entries_file = []

    # for old hive construction
    try:
        entries = parse_execution_entries(r, "Root\\File", FIELDS)
    except NotAnAmcacheHive:
        g_logger.info("Root\\File key not found")
        pass

    if len(entries) != 0:
        with open(os.path.join(outputdirectory,"amcache_output.csv"), "ab") as pf:
            header = not (args.noheader or result_flag["old"])
            standardOutput(entries, file, pf, header, FIELDS)
        result_flag["old"] = True

    # for new windows10 hive construction
    try:
        entries_app = parse_execution_entries(r, "Root\\InventoryApplication", FIELDS_INVENTORY_APP)
        entries_file = parse_execution_entries(r, "Root\\InventoryApplicationFile", FIELDS_INVENTORY_FILE)
        entries_update1709 = mergeRegistoryInfomation(entries_app, entries_file)
    except NotAnAmcacheHive:
        g_logger.info("Root\\InventoryApplication or Root\\InventoryApplicationFile  key not found")
        pass

    if len(entries_app) != 0 and len(entries_file) != 0:
        with open(os.path.join(outputdirectory,"amcache_inventory_output.csv"), "ab") as pf:
            header = not (args.noheader_inventory or result_flag["new"])
            standardOutput(entries_update1709, file, pf, header, FIELDS_UPDATE1709)
        result_flag["new"] = True

def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(
        description="Parse program execution entries from the Amcache.hve Registry hive")
    parser.add_argument('dir')
    parser.add_argument('--output', '-o', help='-o <output directory>',
                        required=True)
    parser.add_argument("-v", action="store_true", dest="verbose",
                        help="Enable verbose output")
    parser.add_argument("--noheader", action="store_true", dest="noheader",
                        help="Output without header (old_style)")
    parser.add_argument("--noheader-inventory", action="store_true", dest="noheader_inventory",
                        help="Output without header (new_style)")
    args = parser.parse_args(argv[1:])

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if sys.platform == "win32":
        import os, msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    inputdirectory=args.dir
    outputdirectory=args.output

    result_flag = {"old": False, "new": False}

    hivefiles = searchHiveFiles(inputdirectory)
    for file in hivefiles:
        parseHive(file, outputdirectory, args, result_flag)
    if len(hivefiles) <= 0:
        print("Doesn't exist Amcache.hve files")
        sys.exit(1)
    else:
        if result_flag["old"]:
            print("Saved: {}\\amcache_output.csv".format(outputdirectory))
        if result_flag["new"]:
            print("Saved: {}\\amcache_inventory_output.csv".format(outputdirectory))

if __name__ == "__main__":
    main(argv=sys.argv)
