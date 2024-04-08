# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""
Check runtime of testfiles.
"""

import sys
import time
import logging
import argparse
from pathlib import Path

import capa.main

logger = logging.getLogger("capa.tests.data")

THRESHOLD = 60 * 3
TARGET_EXTS = (".exe_", ".dll_", ".elf_", ".sys_", ".raw32", ".raw64")  # TODO add , ".BinExport"
IGNORED_DIRS = ("aarch64",)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", help="Paths of added/modified files")
    args = parser.parse_args(args=argv)

    test_failed = False
    for file in args.files:
        file = Path(file)
        # Skip ignored directories
        if any((ignored_dir in file.parts) for ignored_dir in IGNORED_DIRS):
            continue

        if not file.name.endswith(TARGET_EXTS):
            continue

        time0 = time.time()
        capa_ret = capa.main.main(["-q", "-v", "-d", str(file)])
        diff = time.time() - time0

        if capa_ret:
            logger.info("capa failed on file %s", file)
            test_failed = True

        if diff > THRESHOLD:
            logger.info("capa ran for %s seconds, please provide a different sample so we can test more quickly", diff)
            test_failed = True
        else:
            logger.info("all good, capa ran for %s seconds", diff)

    if test_failed:
        return 1
    else:
        logger.info("test files look good!")
        return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
