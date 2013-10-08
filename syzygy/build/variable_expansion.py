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

"""Utility for performing variable expansion in a text file.

An input template is provided on the command line. Strings of the form
${KEY_NAME} in the input will be replaced with the corresponding value for the
key provided on the command-line.

If the variable has an encoding prefix of the form ${PREFIX:KEY_NAME}, the
encoding prefix will be applied prior to emitting the variable. Currently
supported prefixes are:

  A: Treat the value as a path and make it absolute.
  C: C-escape the value.

Prefixes may be combined, and their order is not important.
"""

import json
import logging
import optparse
import os
import re
import sys


_LOGGER = logging.getLogger(os.path.basename(__file__))


class Error(Exception):
  """Base class for all exceptions thrown by this module."""
  pass


def _ParseOptions():
  """Parses command-line options."""
  parser = optparse.OptionParser(usage='%prog OPTIONS KEY=VALUE ...')
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true', default=False,
                    help='Enable verbose logging.')
  parser.add_option('-i', '--input', dest='input',
                    help='Path to the input template.')
  parser.add_option('-o', '--output', dest='output',
                    help='Path to the output.')
  (opts, args) = parser.parse_args()

  opts.verbose = True
  log_level = logging.INFO if opts.verbose else logging.ERROR
  logging.basicConfig(level=log_level)

  if not args:
    parser.error('Must specify at least one key-value pair.')

  if not opts.input:
    parser.error('Must specify --input.')
  if not opts.output:
    parser.error('Must specify --output.')

  if not os.path.isfile(opts.input):
    parser.error('Input does not exist: %s' % opts.input)

  # Parse the arguments as key-value pairs and populate a dictionary with them.
  vars = {}
  for arg in args:
    kv = arg.split('=', 1)
    if len(kv) != 2:
      parser.error('Invalid key-value pair: %s' % kv)
    k, v = kv
    vars[k] = v

  return opts, vars


def _GetVar(vars, key_match):
  """Looks up a variable (in the first group of the RE match |key_match|) and
  returns its value. If the variable has a prefix specifying encoding then the
  encodings are first applied before returning the value.
  """

  # Get the key.
  key = key_match.group(1)

  # Extract the encoding if one is specified.
  enc = ''
  m = re.match('^([^:]+):(.*)$', key)
  if m:
    enc = m.group(1).lower()
    key = m.group(2)

  # Raise an error for keys that don't exist.
  if key not in vars:
    raise Error('The value "%s" is not defined.' % key)

  # Get the value and apply any encodings.
  value = vars[key]
  if 'a' in enc:  # Absolute path encoding.
    _LOGGER.info('Converting "%s" to absolute path.', key)
    value = os.path.abspath(value)
  if 'c' in enc:  # C-style escaping.
    _LOGGER.info('C-escaping "%s" value.', key)
    value = json.dumps(value)[1:-1]

  return value


def _RewriteFile(input, output, vars):
  """Rewrites the contents of |input|, doing variable expansion with |vars|, and
  writing the results to |output|.
  """
  _LOGGER.info('Reading input file: %s', input)
  with open(input, 'rb') as input_file:
    contents = input_file.read()

  _LOGGER.info('Performing variable expansion.')
  f = lambda k: _GetVar(vars, k)
  new_contents = re.sub('\$\{([^}]+)\}', f, contents)

  if new_contents == contents:
    _LOGGER.warning('Contents are unchanged.')

  _LOGGER.info('Writing output file: %s', output)
  output_dir = os.path.dirname(os.path.abspath(output))
  if not os.path.exists(output_dir):
    os.makedirs(output_dir)
  with open(output, 'wb') as output_file:
    output_file.write(new_contents)


def main():
  try:
    opts, vars = _ParseOptions()
    _RewriteFile(opts.input, opts.output, vars)
    return 0
  except Error, e:
    _LOGGER.error(e)
    return 1


if __name__ == '__main__':
  sys.exit(main())
