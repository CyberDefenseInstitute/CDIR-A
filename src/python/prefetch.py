#!/usr/bin/python
# -*- coding: utf-8 -*-

# A parser for prefetch(.pf) file
# Copyright 2017 Shingo Eda <eda@cyberdefense.jp>
# Cyber Defense Institute, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import binascii
import re
import time
import sys
import csv
import os
import argparse
import struct
import ctypes
import shutil
import codecs
from parserutility import utility

if os.name!="nt":
    from ctypes import c_size_t, c_int, c_void_p, cdll, c_ubyte, cast, POINTER, byref

parser = argparse.ArgumentParser(description="How to use prefetch.py")
parser.add_argument('--output', '-o', help='-o <output directory>', required=True)
parser.add_argument('input')
parser.add_argument("--noheader", action="store_true", dest="noheader", help="Output without header")
args = parser.parse_args()

in_dir = args.input
out_dir = args.output

prefetch_column_order = {
    "computer_name": ["Computer Name", 0],
    "exe_file_path": ["Exe Path", 1],
    "run_count": ["Run Count", 2],
    "date_time_1": ["Date Time1", 3],
    "date_time_2": ["Date Time2", 4],
    "date_time_3": ["Date Time3", 5],
    "date_time_4": ["Date Time4", 6],
    "date_time_5": ["Date Time5", 7],
    "date_time_6": ["Date Time6", 8],
    "date_time_7": ["Date Time7", 9],
    "date_time_8": ["Date Time8", 10],
    "time_zone": ["Time Zone", 11],
    "prefetch_file": ["Prefetch Name", 12],
    "hash": ["Hash", 13],
    "volume_path": ["Volume Path", 14]
}
column_num = len(prefetch_column_order)

prefetch_list_order = {
    "computer_name": ["Computer Name", 0],
    "prefetch_file": ["Prefetch Name", 1],
    "reference_file_path": ["File List", 2],
    "file_ext": ["File Ext", 3]
}

list_column_num = len(prefetch_list_order)


def main():
    try:
        RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx
    except AttributeError:
        print
        "Notice: Windows 8 or above version needs to parse Windows 10 prefetch."
    exists_flag = searchDIR(in_dir)
    if exists_flag:
        print
        "Saved: %s\\prefetch_output.csv" % out_dir
        print
        "Saved: %s\\prefetch_output_list.csv" % out_dir
    else:
        print
        "Doesn't exist prefetch(.pf) files"
        sys.exit(1)


def searchDIR(in_dir):
    fileindex = 0
    exists_flag = False
    for root, dirs, files in os.walk(in_dir):
        for filename in files:
            if not re.search(r'\.pf$', filename):
                continue
            exists_flag = True
            pf_filepath = os.path.join(root, filename)
            chkheader(pf_filepath, root, filename, fileindex)
            fileindex += 1
    remove_dcpdir()
    return exists_flag


def chkheader(pf_filepath, root, filename, fileindex):
    with open(pf_filepath, "rb") as pf:
        header_version = binascii.hexlify(pf.read(1))
        if header_version == "17" or header_version == "1a" or header_version == "1e":
            parse_pf_win7and8(root, pf, filename, header_version, fileindex)
        if header_version == "4d":
            try:
                if os.name=="nt":
                    RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx
            except AttributeError:
                return
            parse_pf_win10(root, filename, header_version, fileindex)
        else:
            pass


def remove_dcpdir():
    for root, dirs, files in os.walk(in_dir):
        for dir in dirs:
            if dir == "dcp":
                shutil.rmtree(os.path.join(root,dir))


def parse_pf_win7and8(root, pf, filename, header_version, fileindex):
    parsepf(root, pf, filename, header_version, fileindex)


def parse_pf_win10(root, filename, header_version, fileindex):
    pf_filepath = os.path.join(root, filename)
    decomp(root, filename, pf_filepath)
    dcp_dir = os.path.join(root, "dcp")
    pf_filepath = os.path.join(dcp_dir, filename)
    with open(pf_filepath, "rb") as pf:
        header_version = binascii.hexlify(pf.read(1))
        parsepf(root, pf, filename, header_version, fileindex)


def tohex(val, nbits):
    return hex((val + (1 << nbits)) % (1 << nbits))


def get_exename(pfname):
    break_line = pfname.rfind("-")
    return pfname[:(break_line)]


def get_prefetch_header():
    prefetch_header = [""] * column_num
    for column in prefetch_column_order.values():
        prefetch_header[column[1]] = column[0]
    return prefetch_header


def get_prefetch_list_header():
    prefetch_list_header = [""] * list_column_num
    for column in prefetch_list_order.values():
        prefetch_list_header[column[1]] = column[0]
    return prefetch_list_header


def write_output_file(output_filename, contents, fileindex):
    with open(os.path.join(out_dir, output_filename), "a") as output_file:
        output_line = csv.writer(output_file, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL)
        if fileindex == 0 and not args.noheader:
            if output_filename == "prefetch_output.csv":
                output_line.writerow(get_prefetch_header())
            else:
                output_line.writerow(get_prefetch_list_header())
        output_line.writerows(contents)


def get_file_extension(filename):
    split_path = filename.split(os.sep)
    file = split_path[-1].split('.')
    if len(file) >= 2:
        return file[-1]
    else:
        return 'no extension'


def refine_prefetch_list(computer_name, prefetch_file, file_list):
    prefetch_file_list = []
    for file_path in file_list:
        prefetch_list_record_field = [''] * list_column_num
        prefetch_list_record_field[prefetch_list_order["computer_name"][1]] = computer_name
        prefetch_list_record_field[prefetch_list_order["prefetch_file"][1]] = prefetch_file
        prefetch_list_record_field[prefetch_list_order["reference_file_path"][1]] = file_path
        prefetch_list_record_field[prefetch_list_order["file_ext"][1]] = get_file_extension(file_path)
        prefetch_file_list.append(prefetch_list_record_field)
    return prefetch_file_list

def _ptr(buf, off=0):
    if isinstance(buf, bytearray): buf = (c_ubyte * (len(buf) - off)).from_buffer(buf, off)
    return cast(buf, c_void_p)

# decompress for windows 10 prefetch
def decomp(root, filename, pf_filepath):
    newdir = os.path.join(root, "dcp")
    if not os.path.exists(newdir):
        os.mkdir(newdir)

    # --> reference (https://gist.github.com/dfirfpi/113ff71274a97b489dfd)
    # Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
    NULL = ctypes.POINTER(ctypes.c_uint)()
    SIZE_T = ctypes.c_uint
    DWORD = ctypes.c_uint32
    USHORT = ctypes.c_uint16
    UCHAR = ctypes.c_ubyte
    ULONG = ctypes.c_uint32

    if os.name=="nt":
        RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx

        RtlGetCompressionWorkSpaceSize = \
            ctypes.windll.ntdll.RtlGetCompressionWorkSpaceSize

    with open(pf_filepath, 'rb') as fin:
        header = fin.read(8)
        compressed = fin.read()

        signature, decompressed_size = struct.unpack('<LL', header)
        calgo = (signature & 0x0F000000) >> 24
        crcck = (signature & 0xF0000000) >> 28
        magic = signature & 0x00FFFFFF
        if magic != 0x004d414d:
            sys.exit('Wrong signature... wrong file?')

        if crcck:
            # I could have used RtlComputeCrc32.
            file_crc = struct.unpack('<L', compressed[:4])[0]
            crc = binascii.crc32(header)
            crc = binascii.crc32(struct.pack('<L', 0), crc)
            compressed = compressed[4:]
            crc = binascii.crc32(compressed, crc)
            if crc != file_crc:
                sys.exit('Wrong file CRC {0:x} - {1:x}!'.format(crc, file_crc))

        compressed_size = len(compressed)

        if os.name=="nt":

            ntCompressBufferWorkSpaceSize = ULONG()
            ntCompressFragmentWorkSpaceSize = ULONG()

            ntstatus = RtlGetCompressionWorkSpaceSize(USHORT(calgo),
                                                    ctypes.byref(ntCompressBufferWorkSpaceSize),
                                                    ctypes.byref(ntCompressFragmentWorkSpaceSize))

            if ntstatus:
                sys.exit('Cannot get workspace size, err: {}'.format(
                    tohex(ntstatus, 32)))

            ntCompressed = (UCHAR * compressed_size).from_buffer_copy(compressed)
            ntDecompressed = (UCHAR * decompressed_size)()
            ntFinalUncompressedSize = ULONG()
            ntWorkspace = (UCHAR * ntCompressFragmentWorkSpaceSize.value)()

            ntstatus = RtlDecompressBufferEx(
                USHORT(calgo),
                ctypes.byref(ntDecompressed),
                ULONG(decompressed_size),
                ctypes.byref(ntCompressed),
                ULONG(compressed_size),
                ctypes.byref(ntFinalUncompressedSize),
                ctypes.byref(ntWorkspace))

        else:
            XpressHuffman=4
            script_path=os.path.dirname(os.path.abspath(__file__))
            so=cdll.LoadLibrary(os.path.join(script_path, "libMSCompression.so"))
            # currently errchk is null
            so.restype=c_int
            so.argtypes=[c_int, c_void_p, c_size_t, c_void_p, POINTER(c_size_t)]
            output_buf = bytearray(decompressed_size)
            result=so.ms_decompress(XpressHuffman, _ptr(compressed), c_size_t(compressed_size), _ptr(output_buf), byref(c_size_t(decompressed_size)))
            ntDecompressed=output_buf
    # <-- reference

    # create decompressed file
    with open(os.path.join(newdir, filename), 'wb') as decomp_file:
        decomp_file.write(bytearray(ntDecompressed))


def parsepf(root, pf, filename, header_version, fileindex):
    output_prefetch = []
    output_list = []

    # prefetch_record_field create
    prefetch_record_field = [""] * column_num

    # convert sjis -> utf-8 for output
    filename_cp932 = filename.decode('cp932')
    filename = filename_cp932.encode('utf-8')

    # search NULL in executable name
    pf.seek(16)
    i = 0
    while i < 60:
        if utility().hextoint(pf.read(2)) == 0:
            break
        i += 2

    # extract executable name as UTF-16 from offset 16 to NULL
    pf.seek(16)
    exename_hex = binascii.hexlify(pf.read(i))
    exename_uni_str = codecs.decode(exename_hex, 'hex_codec').decode('utf-16')
    exename_utf_str = exename_uni_str.encode('utf-8')

    # list for comparing to exe path
    exename_list = []

    # parse filename list
    pf.seek(100)
    filename_list_offset = utility().hextoint(pf.read(4))
    filename_list_size = utility().hextoint(pf.read(4))
    pf.seek(filename_list_offset)

    # loop from "filename_list_offset" to "filename_list_end_offset"
    current_offset = filename_list_offset
    filename_list_end_offset = filename_list_offset + filename_list_size
    filename_length = 0

    while current_offset < filename_list_end_offset:
        # search NULL(boundary) in filename list
        read = pf.read(2)
        if len(read) == 0:
            # Unexpected end of prefetch file. This file is damaged in the middle.
            prefetch_file_list = refine_prefetch_list(utility().get_computer_name(root), filename, output_list)
            write_output_file("prefetch_list_output.csv", prefetch_file_list, fileindex)
            return
        else:
            if utility().hextoint(read) == 0:
                pf.seek(current_offset)
                filename_hex = binascii.hexlify(pf.read(filename_length))
                filename_uni_str = codecs.decode(filename_hex, 'hex_codec').decode('utf-16')
                filename_utf_str = filename_uni_str.encode('utf-8')
                if exename_utf_str in filename_utf_str:
                    exename_list.append(filename_utf_str)
                output_list.append(filename_utf_str)
                current_offset = current_offset + filename_length + 2
                pf.seek(current_offset)
                filename_length = 0
            else:
                filename_length += 2

    # time zone
    prefetch_record_field[prefetch_column_order["time_zone"][1]] = \
        utility().get_timezone_str()

    # computer name
    prefetch_record_field[prefetch_column_order["computer_name"][1]] = \
        utility().get_computer_name(root)

    # prefetch filename
    prefetch_record_field[prefetch_column_order["prefetch_file"][1]] = filename

    # prefetch hash
    pf.seek(76)
    hash_bin = pf.read(4)
    hash_hex = re.split('(..)', binascii.hexlify(hash_bin))[1::2]
    list.reverse(hash_hex)
    hash_value = "".join(hash_hex)
    prefetch_record_field[prefetch_column_order["hash"][1]] = hash_value

    # exe path
    if not len(exename_list) == 0:
        prefetch_record_field[prefetch_column_order["exe_file_path"][1]] = exename_list[0]
    else:
        # fill by file name if file path is nothing
        prefetch_record_field[prefetch_column_order["exe_file_path"][1]] = get_exename(filename)

    # run count(Win7)
    if header_version == "17":
        pf.seek(152)
        prefetch_record_field[prefetch_column_order["run_count"][1]] = utility().hextoint(pf.read(4))

    # run count(Win8 or Win10)
    if header_version == "1a" or header_version == "1e":
        pf.seek(208)
        prefetch_record_field[prefetch_column_order["run_count"][1]] = utility().hextoint(pf.read(4))

    # volume information/number
    pf.seek(108)
    vl_info_offset = utility().hextoint(pf.read(4))
    vl_num = utility().hextoint(pf.read(4))

    # seek volume infomation
    pf.seek(vl_info_offset)
    try:
        vl_devicepath_offset = utility().hextoint(pf.read(4))
    except ValueError:
        pass

    # volume length
    pf.seek(vl_info_offset + 4)
    vl_len = utility().hextoint(pf.read(4))
    pf.seek(vl_info_offset + vl_devicepath_offset)
    vol1 = []
    vol2 = []
    for a in re.split('(..)', binascii.hexlify(pf.read(vl_len * 2)))[1::2]:
        if a != "00":
            vol1.append(a)
            vol2 = binascii.a2b_hex("".join(vol1))

    if vl_num >= 2:
        prefetch_record_field[prefetch_column_order["volume_path"][1]] = "Multiple"
        # remove volume path from exe file path with match
        prefetch_record_field[prefetch_column_order["exe_file_path"][1]] = \
            re.sub(r"\\VOLUME{[0-9a-z_./?-]+\}|\\DEVICE\\HARDDISKVOLUME\d+", \
                   "", prefetch_record_field[prefetch_column_order["exe_file_path"][1]])
    else:
        prefetch_record_field[prefetch_column_order["volume_path"][1]] = vol2
        # remove volume path from exe file path with replace
        prefetch_record_field[prefetch_column_order["exe_file_path"][1]] = \
            prefetch_record_field[prefetch_column_order["exe_file_path"][1]].replace(vol2, "")

    # last run information(Win7)
    if header_version == "17":
        pf.seek(128)
        time = utility().get_timestamp_str(utility().hextoint(pf.read(8)))
        prefetch_record_field[prefetch_column_order["date_time_1"][1]] = time

    # run time information(Win8 or Win10)
    if header_version == "1a" or header_version == "1e":
        lastrun_location = 128
        while lastrun_location < 193:
            pf.seek(lastrun_location)
            try:
                time = utility().get_timestamp_str(
                    utility().hextoint(pf.read(8)))
                prefetch_record_field[
                    prefetch_column_order["date_time_" + str((lastrun_location - 128) / 8 + 1)][1]] = time
            except ValueError:
                pass
            lastrun_location = lastrun_location + 8

    output_prefetch.append(prefetch_record_field)

    prefetch_file_list = refine_prefetch_list(utility().get_computer_name(root), filename, output_list)

    # open/close output csv file
    write_output_file("prefetch_output.csv", output_prefetch, fileindex)
    write_output_file("prefetch_list_output.csv", prefetch_file_list, fileindex)

if __name__ == '__main__':
    main()
