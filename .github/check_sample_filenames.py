"""
Check testfiles data directory for consistent naming.

Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""

import os
import sys
import string
import hashlib
import logging
import os.path
import argparse

logger = logging.getLogger("capa.tests.data")

IGNORED_EXTS = (".md", ".txt", ".git", ".gitattributes", ".gitignore", ".gitmodules", ".json")
VALID_EXTS = (".exe_", ".dll_", ".elf_", ".sys_", ".raw32", ".raw64", ".aspx_", ".cs_", ".py_")
IGNORED_DIRS = (".git", ".github", "sigs")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("testfiles", type=str, help="Path to tests/data")
    args = parser.parse_args(args=argv)

    test_failed = test_data_filenames(args)
    if test_failed:
        return 1
    else:
        logger.info("test files look good!")
        return 0


def test_data_filenames(args):
    test_failed = False
    for root, dirs, files in os.walk(args.testfiles):
        # Skip ignored directories
        if any((ignored_dir in root) for ignored_dir in IGNORED_DIRS):
            continue

        for filename in files:
            if filename.endswith(IGNORED_EXTS):
                continue

            path = os.path.join(root, filename)

            if not filename.endswith(VALID_EXTS):
                logger.error("invalid file extension: %s", path)
                test_failed = True
                continue

            name, ext = os.path.splitext(filename)
            if all(c in string.hexdigits for c in name):
                try:
                    hashes = get_file_hashes(path)
                except IOError:
                    continue

                # MD5 file name
                if len(name) == 32:
                    if hashes["md5"] != name:
                        logger.error("invalid file name: %s, MD5 hash: %s", path, hashes["md5"])
                        test_failed = True
                # SHA256 file name
                elif len(name) == 64:
                    if hashes["sha256"] != name:
                        logger.error("invalid file name: %s, SHA256 hash: %s", path, hashes["sha256"])
                        test_failed = True
                else:
                    logger.error("invalid file name: %s, should be MD5 or SHA256 hash", path)
                    test_failed = True

    return test_failed


def get_file_hashes(path):
    with open(path, "rb") as f:
        buf = f.read()

    md5 = hashlib.md5()
    md5.update(buf)

    sha256 = hashlib.sha256()
    sha256.update(buf)

    return {"md5": md5.hexdigest().lower(), "sha256": sha256.hexdigest().lower()}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
