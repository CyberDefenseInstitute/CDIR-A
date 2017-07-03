import time
import datetime
import re
import binascii
import os

class utility(object):
    def get_timezone_str(self):
        diff_seconds = time.timezone
        diff_abs = abs(diff_seconds)
        delta = datetime.timedelta(seconds=diff_abs)
        delta_array = str(delta).split(":")
        diff_str = delta_array[0].zfill(2) + ":" + delta_array[1]
        if diff_seconds <= 0:
            diff_str = "+" + diff_str
        else:
            diff_str = "-" + diff_str
        return diff_str

    def get_computer_name(self, path):
        split_path = path.split(os.sep)
        for dir in reversed(split_path):
            if not dir or dir == split_path[-1] or re.match(r'Registry|Prefetch', dir):
                continue
            else:
                parent_folder_name = dir
                break
        break_line = parent_folder_name.rfind("_")
        return parent_folder_name[:(break_line)]

    def get_timestamp_str(self, ts):
        s = (ts / 10000000.0) - 11644473600
        lt = time.ctime(s)
        ddt = time.strftime('%Y/%m/%d %H:%M:%S', time.strptime(lt))
        ms = str("%.3f"%(s)).split(".")[1]
        return ddt + "." + ms

    def hextoint(self, hex):
        hex_array = re.split('(..)', binascii.hexlify(hex))[1::2]
        list.reverse(hex_array)
        return int(("".join(hex_array)),16)
