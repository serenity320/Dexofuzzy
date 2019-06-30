# -*- coding: utf-8 -*-
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
import csv
import hashlib
import inspect
import json
import logging
import os
import sys
import time
from traceback import format_exc

# Internal packages
from dexofuzzy.generate_dexofuzzy import GenerateDexofuzzy
from dexofuzzy import __version__

# 3rd-party packages


class Dexofuzzy:
    def __init__(self, log_dir="./"):
        log_dir = os.path.join(os.getcwd(), log_dir)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        self.logger = logging.getLogger(__name__)
        logging.basicConfig(filename=os.path.join(log_dir, "dexofuzzy.log"),
                            level=logging.INFO,
                            format="%(asctime)s %(levelname)-8s %(message)s",
                            datefmt="%m-%d %H:%M")

        self.dexofuzzy_list = []

    def get_sha256(self, file_path):
        if not os.path.exists(file_path):
            file = os.path.basename(file_path)
            self.logger.error("File not found : %s" % file)
            self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3], format_exc()))
            print("File not found : %s" % file)

            return None

        try:
            with open(file_path, "rb") as fd:
                data = fd.read()
            sha256 = hashlib.sha256(data).hexdigest()

            return sha256

        except Exception:
            file = os.path.basename(file_path)
            self.logger.error("Unable to get sha256 : %s" % file)
            self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3], format_exc()))
            print("Unable to get sha256 : %s" % file)

            return None

    def get_file_size(self, file_path):
        try:
            statinfo = os.stat(file_path)
            file_size = int(statinfo.st_size)

            return str(file_size)

        except Exception:
            file = os.path.basename(file_path)
            self.logger.error("Unable to get file size : %s" % file)
            self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3], format_exc()))
            print("Unable to get file size : %s" % file)

            return None

    def search_sample_dir(self, sample_dir):
        if os.path.isdir(sample_dir) is False:
            return None

        sample_path = os.path.join(os.getcwd(), sample_dir)

        generateDexoFuzzy = GenerateDexofuzzy()

        for root, __, files in os.walk(sample_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    report = generateDexoFuzzy.generate_dexofuzzy(file_path)
                    if report is not None:
                        result = {}
                        file_sha256 = self.get_sha256(file_path)
                        result["file_name"] = file
                        result["file_sha256"] = file_sha256
                        result["file_size"] = self.get_file_size(file_path)
                        result["code_hash"] = report["code_hash"]
                        result["dexofuzzy"] = report["dexofuzzy"]
                        result["methodfuzzy"] = report["methodfuzzy"]

                        yield result

                    else:
                        yield None

                except Exception:
                    self.logger.error(
                                    "Unable to search sample dir : %s" % file)
                    self.logger.error(
                            "%s : %s" % (inspect.stack()[0][3], format_exc()))
                    print("Unable to search sample dir : %s" % file)

                    continue

        return None

    def search_sample_file(self, sample_file):
        if os.path.isfile(sample_file) is False:
            return None

        generateDexoFuzzy = GenerateDexofuzzy()
        report = generateDexoFuzzy.generate_dexofuzzy(sample_file)
        if report is not None:
            result = {}
            file_sha256 = self.get_sha256(sample_file)
            result["file_name"] = sample_file
            result["file_sha256"] = file_sha256
            result["file_size"] = self.get_file_size(sample_file)
            result["code_hash"] = report["code_hash"]
            result["dexofuzzy"] = report["dexofuzzy"]
            result["methodfuzzy"] = report["methodfuzzy"]

            return result

        else:
            return None

    def output_dexofuzzy(self, args, result):
        if args.output_dexofuzzy:
            print(result["file_name"] + ", " +
                  result["file_sha256"] + ", " +
                  result["file_size"] + ", " +
                  result["code_hash"] + ", " +
                  result["dexofuzzy"])

        if args.methodfuzzy:
            print("FileName : " + result["file_name"])
            for methodfuzzy in result["methodfuzzy"]:
                print(methodfuzzy)

        if args.csv or args.json:
            self.dexofuzzy_list.append(result)

    def run(self, argv):
        parser = argparse.ArgumentParser(
            description=("Dexofuzzy - Dalvik EXecutable Opcode Fuzzyhash v%s"
                         % __version__),
            add_help=True)
        parser.add_argument(
            "-o", "--output-dexofuzzy", action="store_true",
            help="extract the dexofuzzy of the sample")
        parser.add_argument(
            "-m", "--methodfuzzy", action="store_true",
            help="extract the fuzzyhash based on method of the sample")
        parser.add_argument(
            "-f", "--sample-file", help="the sample to extract dexofuzzy")
        parser.add_argument(
            "-d", "--sample-dir",
            help="the directory of samples to extract dexofuzzy")
        parser.add_argument("-c", "--csv", help="output as CSV format")
        parser.add_argument("-j", "--json", help="output as json format")

        if len(argv) == 1:
            parser.print_help()
            return None

        args = parser.parse_args()

        start = time.time()
        if args.sample_dir:
            for result in self.search_sample_dir(args.sample_dir):
                if result is not None:
                    self.output_dexofuzzy(args, result)

        if args.sample_file:
            result = self.search_sample_file(args.sample_file)
            if result is not None:
                self.output_dexofuzzy(args, result)

        end = time.time()
        print("Running Time : %s" % str((end - start)))

        if args.csv:
            with open(args.csv, "w", newline="") as fd:
                fieldnames = ["file_name", "file_sha256", "file_size",
                              "code_hash", "dexofuzzy"]
                writer = csv.DictWriter(fd, fieldnames=fieldnames)
                writer.writeheader()
                for output in self.dexofuzzy_list:
                    row = {}
                    row["file_name"] = output["file_name"]
                    row["file_sha256"] = output["file_sha256"]
                    row["file_size"] = output["file_size"]
                    row["code_hash"] = output["code_hash"]
                    row["dexofuzzy"] = output["dexofuzzy"]
                    writer.writerow(row)

        if args.json:
            with open(args.json, "w") as fd:
                json.dump(self.dexofuzzy_list, fd)


def main():
    dexofuzzy = Dexofuzzy()
    dexofuzzy.run(sys.argv)


if __name__ == '__main__':
    main()
