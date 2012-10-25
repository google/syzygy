#!python
# Copyright 2012 Google Inc. All Rights Reserved.
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
"""Outputs the current date and time information as a key-value file
appropriate for use with template_replace.py.
"""

import datetime
import optparse
import os
import sys


def _ParseArguments():
  parser = optparse.OptionParser()
  parser.add_option('-o', '--output', dest='output', default=None,
                    help='The file to write to. If not specified outputs to '
                         'stdout.')
  (opts, dummy_args) = parser.parse_args()
  if opts.output:
    opts.output = os.path.abspath(opts.output)
  return opts


def main():
  opts = _ParseArguments()
  now = datetime.datetime.utcnow()
  output = sys.stdout
  if opts.output:
    output = open(opts.output, 'wb')

  output.write(now.strftime('DATE=%Y/%m/%d\n'))
  output.write(now.strftime('TIME=%H:%M:%S UTC\n'))


if __name__ == '__main__':
  sys.exit(main())
