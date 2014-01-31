#!python
# Copyright 2014 Google Inc. All Rights Reserved.
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
'''
Template replacement script. Reads key/value pairs from argument files,
and substitutes $(key) strings in the input file to create the output file.
The output file is only rewritten if the contents will be different from
the existing contents.
'''
import exceptions
import optparse
import os
import re
import string
import sys


_USAGE = 'usage: %prog [option] [key files]\n' + __doc__


_LINE_RE = re.compile('^'
    '(?P<key>\w+)=(?P<value>.*)|'         # key=value
    '(?P<comment>\s*(?:#.*)?)'            # WS or comment
  '$')


class Error(exceptions.Exception):
  pass


def ReadKeyFile(key_file, values):
  '''Reads the key/value pairs from key_file, and adds them to the values dict.
  '''
  f = open(key_file, 'r')
  for line in f:
    line = line.rstrip('\n\r')
    m = _LINE_RE.match(line)
    if not m:
      raise Error('Syntax error in file "%s", line "%s"' % (key_file, line))

    matches = m.groupdict()
    if matches['key']:
      values[matches['key']] = matches['value']


def GetOptionParser():
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('-i', '--input', dest='input',
      help='Input template file name')
  parser.add_option('-o', '--output', dest='output',
      help='Output file name')

  return parser


def Main():
  parser = GetOptionParser()
  (opts, args) = parser.parse_args()
  if not opts.input:
    parser.error('you must provide an input file')
  if not opts.output:
    parser.error('you must provide an output file')

  values = dict()
  for key_file in args:
    ReadKeyFile(key_file, values)

  # Slurp the input file.
  input = open(opts.input, 'r').read()

  # Do the replacements.
  template = string.Template(input)
  output = template.substitute(values)

  # If there is an existing version of the file, check its contents.
  # If they are identical, we return early not rewriting the file.
  if os.path.isfile(opts.output):
    contents = open(opts.output, 'r').read()
    if output == contents:
      return 0

  # And write the output.
  open(opts.output, 'w').write(output)

  return 0


if __name__ == '__main__':
  sys.exit(Main())
