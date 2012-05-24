# Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""This script creates a flat zip archive."""
import os.path
import sys
import zipfile


def _CreateFlatArchive(input_files, output_file):
  """Creates a flat Zip archive of a given set of files.

  Creates or overwrites output_file with a zip archive containing input_files.
  The input files all reside at the root of the zip archive.

  Args:
    input_files: a list (or other iterable) of input file paths.
    output_files: the path to the output file.
  """
  zip_file = zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED)
  for input_file in input_files:
    zip_file.write(input_file, os.path.basename(input_file))
  zip_file.close()


def main():
  if len(sys.argv) < 3:
    print "Usage: %s output_file input_file [input_file...]" % sys.argv[0]
    return 1

  _CreateFlatArchive(sys.argv[2:], sys.argv[1])
  return 0

if __name__ == '__main__':
  sys.exit(main())
