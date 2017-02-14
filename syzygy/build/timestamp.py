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
import logging
import optparse
import os
import re
import sys


# Use the GIT helper functions from 'lastchange.py'.
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import lastchange


_LOGGER = logging.getLogger(os.path.basename(__file__))


def _ParseArguments():
  parser = optparse.OptionParser()
  parser.add_option('-o', '--output', dest='output', default=None,
                    help='The file to write to. If not specified outputs to '
                         'stdout.')
  parser.add_option("-s", "--source-dir", metavar="DIR",
                    help="use repository in the given directory")
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true', default=False,
                    help='Enable verbose logging.')
  (opts, dummy_args) = parser.parse_args()
  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.ERROR)
  if opts.output:
    opts.output = os.path.abspath(opts.output)
  return opts


def main():
  opts = _ParseArguments()

  t = None
  if not lastchange.IsOfficialBuild():
    _LOGGER.info('Official build, reporting git time.')
    if opts.source_dir:
      src_dir = opts.source_dir
    else:
      src_dir = os.path.dirname(os.path.abspath(__file__))
    # Get the commit timestamp in seconds since UTC epoch.
    git_time = lastchange.RunGitCommand(src_dir,
        ['log', '-1', '--date=raw', '--pretty=format:%cd']).strip()
    m = re.match('(^\d+) ([+-]\d{4})$', git_time)
    if not m:
      raise RuntimeException('Unexpected "git time" output: %s' % git_time)
    seconds_utc = int(m.group(1))
    t = datetime.datetime.utcfromtimestamp(seconds_utc)
  else:
    _LOGGER.info('Developer build, reporting fake time.')
    now = datetime.datetime.utcnow()
    t = datetime.datetime(2000, 1, 1, 0, 0, 0, 0, now.tzinfo)

  contents = """# This file was automatically generated by timestamp.py.
DATE=%s
TIME=%s
""" % (t.strftime('%Y/%m/%d'), t.strftime('%H:%M:%S UTC'))

  if opts.output:
    lastchange.WriteIfChanged(opts.output, contents)
  else:
    sys.stdout.write(contents)


if __name__ == '__main__':
  sys.exit(main())