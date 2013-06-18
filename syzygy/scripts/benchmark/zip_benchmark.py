# Copyright 2012 Google Inc. All Rights Reserved.
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
"""A utility script that packs the benchmark eggs and an associated bat file
into a zip archive to make the benchmark script easy to transport and use."""
import contextlib
import cStringIO
import datetime
import glob
import logging
import optparse
import os.path
import sys
import zipfile

# This is generally not present in the depot_tools Python installation.
# pylint: disable=F0401
import pkg_resources


_YEAR = datetime.datetime.now().year


# Glob patterns for the eggs we bake in to the zip archive.
_EGG_PATTERNS = [
  'Benchmark_Chrome-*.egg',
  'ETW-*.egg',
  'ETW_Db-*.egg',
  'setuptools-*.egg',
]


_SCRIPT_TEMPLATE = """\
@echo off
rem = \"\"\"
:: Copyright %d Google Inc.""" % _YEAR + """
::
:: Licensed under the Apache License, Version 2.0 (the \"License\");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an \"AS IS\" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.

python -x "%%~f0" %%*
exit /b %%ERRORLEVEL%%
goto endofPython \"\"\"

import sys
import os

# Prepend the eggs we need to our python path.
_EGGS = [
%(eggs)s
  ]
dir = os.path.dirname(__file__)
sys.path[0:0] = [os.path.join(dir, egg) for egg in _EGGS]

# And run the main program.
import %(module)s
sys.exit(%(module)s.main())

rem = \"\"\"
:endofPython \"\"\"
"""


_SCRIPT_TEMPLATES = [
    ('benchmark.bat',  _SCRIPT_TEMPLATE, 'benchmark'),
    ('grinder.bat', _SCRIPT_TEMPLATE, 'grinder'),
    ('instrument.bat', _SCRIPT_TEMPLATE, 'instrument'),
    ('optimize.bat', _SCRIPT_TEMPLATE, 'optimize'),
    ('profile.bat', _SCRIPT_TEMPLATE, 'profile'),
    ]


_LOGGER = logging.getLogger(__name__)


def _FindEggs(root_dir):
  eggs = []
  for pattern in _EGG_PATTERNS:
    file_spec = os.path.join(root_dir, pattern)
    new_eggs = glob.glob(file_spec)
    if not new_eggs:
      raise RuntimeError('Found no egg for "%s".' % file_spec)

    def SortEggs(e1, e2):
      d1 = pkg_resources.Distribution.from_filename(e1)
      d2 = pkg_resources.Distribution.from_filename(e2)
      return cmp(d1.version, d2.version)

    # Pick the most recent egg version by sorting them by reverse version.
    new_eggs = sorted(new_eggs, SortEggs, reverse=True)
    eggs.append(new_eggs[0])

  return eggs


def _WriteBatFile(root_dir, file_name, template, module, eggs):
  eggs = '\n'.join(['    %r,' % os.path.basename(egg) for egg in eggs])
  output = template % { 'eggs': eggs, 'module': module }

  path = os.path.join(root_dir, file_name)
  with open(path, 'wb') as f:
    f.write(output)
  return path


def _CreateFlatArchive(input_files, output_file):
  """Creates a flat Zip archive of a given set of files.

  Creates or overwrites output_file with a zip archive containing input_files.
  The input files all reside at the root of the zip archive.

  Args:
    input_files: a list (or other iterable) of input file paths.
    output_file: the path to the output file.
  """
  # Create a StringIO for the output.
  temp_file = cStringIO.StringIO()

  zzip = zipfile.ZipFile(temp_file, 'w', zipfile.ZIP_DEFLATED)
  with contextlib.closing(zzip):
    for input_file in input_files:
      zzip.write(input_file, os.path.basename(input_file))

  output = temp_file.getvalue()

  # Don't replace an existing output file with identical contents.
  if (os.path.exists(output_file) and
      open(output_file, 'rb').read() == output):
    return

  with open(output_file, 'wb') as f:
    f.write(output)


def _ParseArgs():
  parser = optparse.OptionParser()
  parser.add_option('', '--root-dir', dest='root_dir',
                    help='Root directory where built eggs are to be found.')
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true',
                    help='Enable verbose logging.')

  opts, args = parser.parse_args()

  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig()

  if args:
    parser.error('This script takes no arguments')
  if not opts.root_dir:
    parser.error('You must provide a root directory')
  # We strip the root-dir param of trailing quotes as a workaround for:
  # http://code.google.com/p/gyp/issues/detail?id=272
  opts.root_dir = os.path.abspath(opts.root_dir.rstrip('"\''))
  return opts


def main():
  """Main function, parses args and performs zipping."""
  opts = _ParseArgs()

  files_to_archive = []
  egg_files = _FindEggs(opts.root_dir)
  for bat_file, template, module in _SCRIPT_TEMPLATES:
    src_path = _WriteBatFile(opts.root_dir, bat_file, template,
                             module, egg_files)
    files_to_archive.append(src_path)

  files_to_archive.extend(egg_files)

  _CreateFlatArchive(files_to_archive,
                     os.path.join(opts.root_dir, 'benchmark.zip'))


if __name__ == '__main__':
  sys.exit(main())
