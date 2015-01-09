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
"""A utility script for building arbitrary ZIP files."""

import contextlib
import cStringIO
import logging
import optparse
import os.path
import sys
import zipfile


_LOGGER = logging.getLogger(os.path.basename(__file__))


def _CreateZipArchive(input_dict, output_file):
  """Creates a Zip archive of a given set of files.

  Creates or overwrites output_file with a zip archive containing files
  from input_dict.

  Example input_dict:

  { '': { None: [ 'README', 'LICENSE', 'special/binary.dll' ]},
    'libs': { None: [ 'special/binary.lib' ]},
    'include': { 'src': [ 'src/special/magic.h', 'src/special/potion.h' ]}
  }

  Output zip structure:

  /
    README
    LICENSE
    special/
      binary.dll
      binary.lib
    include/
      special/
        magic.h
        potion.h

  Args:
    input_dict: a dict of destination root paths (relative to the root of the
        zip archive) mapping to dicts of source root paths mapping to lists of
        files under the source root to be copied to the destination root. If the
        source root is None the files will be stored with their basename at the
        destination root. Otherwise, the destination path relative to the
        destination root will be equal to the source path relative to the source
        root.
    output_file: the path to the output file.
  """
  # Create a StringIO for the output.
  temp_file = cStringIO.StringIO()

  _LOGGER.info('Creating zip archive "%s".', output_file)

  zzip = zipfile.ZipFile(temp_file, 'w', zipfile.ZIP_DEFLATED)
  with contextlib.closing(zzip):
    for subdir, subdir_roots in input_dict.iteritems():
      for subdir_root, files in subdir_roots.iteritems():
        for path in files:
          if subdir_root is None:
            rel_path = os.path.basename(path)
          else:
            rel_path = os.path.relpath(path, subdir_root)
          zip_path = os.path.join(subdir, rel_path)
          _LOGGER.info('Zipping "%s" to path "%s".', path, zip_path)
          zzip.write(path, zip_path)

  output = temp_file.getvalue()

  # Don't replace an existing output file with identical contents.
  if (os.path.exists(output_file) and
      open(output_file, 'rb').read() == output):
    _LOGGER.info('Archive unchanged, not rewriting.')
    return

  with open(output_file, 'wb') as f:
    _LOGGER.info('Writing archive "%s".', output_file)
    f.write(output)


def _SwitchSubdir(dummy_option, dummy_option_string, value, parser):
  """A callback used by the option parser.

  Switches the currently active ZIP archive path, and appends any outstanding
  positional arguments to the list of files for the previously active
  ZIP archive path.
  """
  # When this is called by the '--files' callback there is no value passed
  # to the option. Thus, we use a value of '', which indicates the root
  # directory.
  if not value:
    value = ''

  # Extend the previously active sub-directory file list with those
  # arguments that have been parsed since it was set.
  files = parser.values.files
  if isinstance(parser.values.subdir, basestring):
    destroot = parser.values.subdir
    srcroot = None
  else:
    destroot = parser.values.subdir[0]
    srcroot = parser.values.subdir[1]

  subdir = files.setdefault(destroot, {})
  subdir_root = subdir.setdefault(srcroot, [])
  subdir_root.extend(parser.largs)

  # Remove these arguments from the list of processed arguments.
  del parser.largs[:len(parser.largs)]

  # Update the currently active sub-directory. Further arguments that are
  # parsed will append to this sub-directory's file list.
  parser.values.subdir = value


_USAGE = """%prog [options] --output OUTPUT --files ... --subdir ...

Example:

  %prog --output foo.zip --files a.txt --subdir bar b.txt

The example will create an archive containing the following files:

  /a.txt
  /bar/b.txt
"""


def _ParseArgs():
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('-o', '--output', dest='output', default=None,
                    help='Specifies the output file.')
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true',
                    help='Enable verbose logging.')
  parser.add_option('-f', '--files', action='callback', callback=_SwitchSubdir,
                    dest='files', default={},
                    help='Specify file list. All arguments following this '
                         'will be treated as files to add to the archive in '
                         'the root directory.')
  parser.add_option('-s', '--subdir', action='callback', callback=_SwitchSubdir,
                    type='string', nargs=1, dest='subdir', default='',
                    help='Specify a subdirectory of files. All arguments '
                         'following this will be treated as files to add to '
                         'the archive in the specified sub-directory.')
  parser.add_option('--subtree', action='callback', callback=_SwitchSubdir,
                    type='string', nargs=2, dest='subdir', default='',
                    help='Specify a subdirectory of files and a source root. '
                         'All arguments following this will be treated as '
                         'files to add to the archive in the specified '
                         'sub-directory. Their destination path, relative to '
                         'the subdirectory, will be equivalent to their source '
                         'path, relative to the source root.')

  # We append a trailing '--files' so that any trailing positional arguments
  # get inserted into the appropriate dict entry by the _SwitchSubdir
  # callback.
  argv = sys.argv[1:]
  argv.append('--files')
  opts, dummy_args = parser.parse_args(argv)

  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig()

  return opts


def Main():
  """Main function, parses args and performs zipping."""
  opts = _ParseArgs()
  if not opts.output:
    _LOGGER.error('--output must be specified.')
    return 1
  _CreateZipArchive(opts.files, opts.output)
  return 0


if __name__ == '__main__':
  sys.exit(Main())
