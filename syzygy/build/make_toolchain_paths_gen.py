# Copyright 2013 Google Inc. All Rights Reserved.
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

"""Utility for extracting build environment paths from the current environment
and exporting them to a generated .cc file.
"""

import json
import logging
import optparse
import os
import re
import sys


_LOGGER = logging.getLogger(os.path.basename(__file__))
_TOOLS = { 'LINKER': 'link.exe', 'COMPILER': 'cl.exe' }


class Error(Exception):
  """Base class for all exceptions thrown by this module."""
  pass


def _AllToolsAreInPath(path):
  """Returns true if all tools are found in the given path."""
  for basename in _TOOLS.itervalues():
    tool_path = os.path.join(path, basename)
    if not os.path.isfile(tool_path):
      return False
  return True


def _ParseOptions():
  """Parses command-line options."""
  parser = optparse.OptionParser(usage='%prog OPTIONS')
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true', default=False,
                    help='Enable verbose logging.')
  parser.add_option('-i', '--input', dest='input',
                    help='Path to the input template.')
  parser.add_option('-o', '--output', dest='output',
                    help='Path to the output.')
  parser.add_option('-d', '--vs-install-dir', dest='vs_install_dir',
                    help='Path to the Visual Studio installation directory.')
  (opts, args) = parser.parse_args()
  if args:
    parser.error('Unexpected arguments.')

  if not opts.input:
    parser.error('Must specify --input.')
  if not opts.output:
    parser.error('Must specify --output.')
  if not opts.vs_install_dir:
    parser.error('Must specify --vs-install-dir')

  if not os.path.isfile(opts.input):
    parser.error('Input does not exist: %s' % opts.input)
  if not os.path.isdir(opts.vs_install_dir):
    parser.error('VS install directory does not exist: %s' %
                     opts.vs_install_dir)

  return opts


def _FindVisualStudioPaths(vs_install_dir):
  """Finds any paths in PATH that are children of the Visual Studio install
  directory.
  """
  _LOGGER.info('Looking for VS-related paths.')
  vs_path = vs_install_dir.lower()
  vs_paths = []
  for path in os.environ.get('PATH', '').split(';'):
    path = os.path.abspath(path)
    if path.lower().startswith(vs_path):
      _LOGGER.info('Found related path: %s', path)
      vs_paths.append(path)

  return vs_paths


def _FindToolPath(paths):
  """Given a collection of paths, looks for the path containing all of the
  tools defines in _TOOLS.
  """
  _LOGGER.info('Looking for path containing tools.')
  tool_path = None
  for path in paths:
    if _AllToolsAreInPath(path):
      tool_path = path
      break
  if not tool_path:
    raise Error('Tools not found in any active path.')
  _LOGGER.info('Found tools in: %s', tool_path)

  return tool_path


def _GetToolchainVars(vs_install_dir):
  """Calculates a dictionary of variables representing toolchain related paths.
  """

  # Get the paths of interest.
  vs_paths = _FindVisualStudioPaths(vs_install_dir)
  tool_path = _FindToolPath(vs_paths)

  # Finally, build the variables.
  vars = {}
  for name, basename in _TOOLS.iteritems():
    key = name + '_PATH'
    value = os.path.join(tool_path, basename)
    vars[key] = value
  vars['TOOLCHAIN_PATHS'] = ';'.join(vs_paths)

  return vars


def _RewriteFile(input, output, vars):
  """Rewrites the contents of |input|, doing variable expansion with |vars|, and
  writing the results to |output|. Variables are expanded using C/C++ string
  escaping.
  """
  _LOGGER.info('Reading input file: %s', input)
  with open(input, 'rb') as input_file:
    contents = input_file.read()

  _LOGGER.info('Performing variable expansion.')
  f = lambda m: json.dumps(vars.get(m.group(1), ''))[1:-1]
  new_contents = re.sub('\$\{([^}]+)\}', f, contents)

  _LOGGER.info('Writing output file: %s', output)
  output_dir = os.path.dirname(output)
  if not os.path.exists(output_dir):
    os.makedirs(output_dir)
  with open(output, 'wb') as output_file:
    output_file.write(new_contents)


def main():
  try:
    opts = _ParseOptions()
    log_level = logging.INFO if opts.verbose else logging.ERROR
    logging.basicConfig(level=log_level)
    vars = _GetToolchainVars(opts.vs_install_dir)
    _RewriteFile(opts.input, opts.output, vars)
    return 0
  except Error, e:
    _LOGGER.error(e)
    return 1


if __name__ == '__main__':
  sys.exit(main())
