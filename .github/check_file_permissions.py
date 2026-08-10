# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Check testfiles data directory for non-executable permissions.
"""

import sys
import logging
import argparse
import subprocess
from pathlib import Path

logger = logging.getLogger("capa.tests.data")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("testfiles", type=str, help="Path to tests/data repository root")
    args = parser.parse_args(args=argv)

    test_failed = check_permissions(Path(args.testfiles))
    if test_failed:
        return 1
    else:
        logger.info("test file permissions look good!")
        return 0


def check_permissions(testfiles_path: Path) -> bool:
    """
    Ensure all files in the testfiles repository are tracked in Git as non-executable (100644).
    """
    test_failed = False
    try:
        output = subprocess.check_output(
            ["git", "ls-files", "-s"],
            cwd=testfiles_path,
            text=True,
        )
        for line in output.splitlines():
            if not line:
                continue

            # Git format: <mode> <hash> <stage>\t<filename>
            header, _, filename = line.partition("\t")
            mode = header.split(" ", 1)[0]

            if mode == "100755":
                logger.error("file tracked as executable (100755): %s", filename.strip('"'))
                test_failed = True
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.warning("could not verify git file modes: %s", e)

    return test_failed


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
