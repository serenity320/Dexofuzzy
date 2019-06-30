# -*- coding: UTF-8 -*-
#
# Copyright (C) 2019 ESTsecurity
#
# This file is part of dexofuzzy.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
'''

'''
# Default packages
import argparse
import hashlib
import inspect
import logging
import os
import sys
import zipfile
from contextlib import closing
from traceback import format_exc

# Internal packages
from dexofuzzy.extract_opcode import ExtractOpcode

# 3rd-party packages
if sys.platform == 'win32':
    import dexofuzzy.bin as ssdeep
else:
    import ssdeep


class GenerateDexofuzzy:
    def __init__(self, log_dir="./"):
        log_dir = os.path.join(os.getcwd(), log_dir)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        self.logger = logging.getLogger(__name__)
        logging.basicConfig(filename="dexofuzzy.log",
                            level=logging.INFO,
                            format="%(asctime)s %(levelname)-8s %(message)s",
                            datefmt="%m-%d %H:%M")

    def get_dexofuzzy_compare(self, dexofuzzy_1, dexofuzzy_2):
        try:
            return ssdeep.compare(dexofuzzy_1, dexofuzzy_2)

        except Exception:
            self.logger.error("Unable to get dexofuzzy compare")
            self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3], format_exc()))

            return None

    def generate_dexofuzzy(self, file_path):
        try:
            method_fuzzy_list = self.__extract_method_fuzzy_list(file_path)
            if method_fuzzy_list:
                feature = ""
                for method_fuzzy in method_fuzzy_list:
                    feature += method_fuzzy.split(":")[1]

                if feature:
                    result = {}
                    result["code_hash"] = hashlib.sha256(
                                        feature.encode("UTF-8")).hexdigest()
                    result["dexofuzzy"] = ssdeep.hash(feature,
                                                      encoding="UTF-8")
                    result["methodfuzzy"] = method_fuzzy_list

                    return result
                
                else:
                    file = os.path.basename(file_path)
                    self.logger.error("No extracted opcode data: %s" % file)
                    self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3], format_exc()))
                    print("Unable to generate dexofuzzy : %s" % file)
                    
                    return None

            else:
                file = os.path.basename(file_path)
                self.logger.error("No extracted opcode data: %s" % file)
                self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3],format_exc()))
                print("Unable to generate dexofuzzy : %s" % file)
                
                return None

            return None

        except Exception:
            file = os.path.basename(file_path)
            self.logger.error("Unable to generate dexofuzzy : %s" % file)
            self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3], format_exc()))
            print("Unable to generate dexofuzzy : %s" % file)

            return None

    def __extract_method_fuzzy_list(self, file_path):
        try:
            method_fuzzy_list = []
            for dex_data in self.__extract_dex(file_path):
                if dex_data is None:
                    file = os.path.basename(file_path)
                    self.logger.error(
                            "Unable to extract dex binary data : %s" % file)
                    self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3], format_exc()))

                    continue

                extractOpcode = ExtractOpcode()
                opcodes = extractOpcode.analyze_dex(dex_data)

                for opcode in opcodes:
                    method_fuzzy_list.append(
                                        ssdeep.hash(opcode, encoding="UTF-8"))
            return method_fuzzy_list

        except Exception:
            file = os.path.basename(file_path)
            self.logger.error(
                            "Unable to extract method fuzzy list : %s" % file)
            self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3], format_exc()))

            return None

    def __extract_dex(self, file_path):
        try:
            dex_list = []
            with closing(zipfile.ZipFile(file_path)) as ZipData:
                for info in ZipData.infolist():
                    if(info.filename.startswith("classes") and
                       info.filename.endswith(".dex")):
                        dex_list.append(info.filename)

                for dex_name in sorted(dex_list):
                    with ZipData.open(dex_name) as dex:
                        yield dex.read()

        except Exception:
            file = os.path.basename(file_path)
            self.logger.error("Unable to extract dex : %s" % file)
            self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3], format_exc()))

            yield None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("<file_apk>", type=argparse.FileType("r"),
                        help="the apkfile to extract dexofuzzy.")

    if len(sys.argv) == 1:
        parser.print_help()

    else:
        generateDexofuzzy = GenerateDexofuzzy()
        result = generateDexofuzzy.generate_dexofuzzy(sys.argv[1])
        print(result)
