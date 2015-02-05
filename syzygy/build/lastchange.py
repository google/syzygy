#!/usr/bin/env python
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

"""
lastchange.py -- Revision fetching utility.

The helper functions defined in this utility are also used by timestamp.py.
"""

import re
import logging
import optparse
import os
import subprocess
import sys


_LOGGER = logging.getLogger(os.path.basename(__file__))


class VersionInfo(object):
  def __init__(self, url, revision):
    self.url = url
    self.revision = revision


def IsOfficialBuild():
  """
  Determines if this is an official Syzygy release build.
  """
  return (os.getenv('BUILDBOT_MASTERNAME') == 'client.syzygy' and
      os.getenv('BUILDBOT_BUILDERNAME') == 'Syzygy Official')


def RunGitCommandImpl(directory, command):
  """
  Launches a git subcommand using Popen. Raises OSError exceptions.

  Returns:
    A process object or None.
  """
  command = ['git'] + command
  # Force shell usage under cygwin. This is a workaround for
  # mysterious loss of cwd while invoking cygwin's git.
  # We can't just pass shell=True to Popen, as under win32 this will
  # cause CMD to be used, while we explicitly want a cygwin shell.
  if sys.platform == 'cygwin':
    command = ['sh', '-c', ' '.join(command)]
  _LOGGER.info('Running command: %s', command)
  proc = subprocess.Popen(command,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          cwd=directory,
                          shell=(sys.platform=='win32'))
  return proc


def RunGitCommand(directory, command):
  """
  Runs a git command, and returns its output as a string. Raises a RuntimeError
  exception if the command does not complete successfully, and propagates
  OSError exceptions from RunGitCommandImpl.
  """
  proc = RunGitCommandImpl(directory, command)
  output = proc.communicate()[0].strip()
  if proc.returncode == 0 and output:
    return output
  raise RuntimeError('Returned non-zero: %s' % command)


def FetchGitRevisionImpl(directory):
  """
  Fetch the Git hash for a given directory. Propagates RuntimeError and OSError
  exceptions.

  Returns:
    A string containing the revision.
  """
  # The buildbots need to be able support requests to build specific revisions,
  # and the LASTCHANGE file needs to always be updated in this case.
  if IsOfficialBuild():
    _LOGGER.info('Official build, reporting revision of HEAD.')
    rev = RunGitCommand(directory, ['rev-parse', 'HEAD'])
    return rev

  _LOGGER.info('Developer build, reporting fake revision.')
  return '0' * 40


def FetchGitRevision(directory):
  """
  Fetch the Git hash for a given directory.

  This reports the revision of HEAD only for official builds hosted on the
  Syzygy master. Otherwise, this returns a fake revision to reduce build churn
  associated with 'gclient runhooks'. Errors are swallowed.

  Returns:
    A VersionInfo object or None on error.
  """
  try:
    rev = FetchGitRevisionImpl(directory)
    if not re.match('^[a-fA-F0-9]{40}$', rev):
      return None
  except (OSError, RuntimeError) as e:
    _LOGGER.error(e)
    return None
  if rev:
    return VersionInfo('git', rev)
  return None


def WriteIfChanged(file_name, contents):
  """
  Writes the specified contents to the specified file_name
  iff the contents are different than the current contents.
  """
  try:
    old_contents = open(file_name, 'r').read()
  except EnvironmentError:
    pass
  else:
    if contents == old_contents:
      _LOGGER.info('Contents unchanged, not writing file: %s', file_name)
      return
    os.unlink(file_name)
  _LOGGER.info('Contents changes, writing file: %s', file_name)
  open(file_name, 'w').write(contents)


def main(argv=None):
  if argv is None:
    argv = sys.argv

  parser = optparse.OptionParser(usage="lastchange.py [options]")
  parser.add_option("-o", "--output", metavar="FILE",
                    help="write last change to FILE")
  parser.add_option("--revision-only", action='store_true',
                    help="just print the revision number")
  parser.add_option("-s", "--source-dir", metavar="DIR",
                    help="use repository in the given directory")
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true', default=False,
                    help='Enable verbose logging.')
  opts, args = parser.parse_args(argv[1:])

  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.ERROR)

  out_file = opts.output

  while len(args) and out_file is None:
    if out_file is None:
      out_file = args.pop(0)
  if args:
    sys.stderr.write('Unexpected arguments: %r\n\n' % args)
    parser.print_help()
    sys.exit(2)

  if opts.source_dir:
    src_dir = opts.source_dir
  else:
    src_dir = os.path.dirname(os.path.abspath(__file__))

  version_info = FetchGitRevision(src_dir)

  if version_info.revision == None:
    version_info.revision = '0'

  if opts.revision_only:
    print version_info.revision
  else:
    contents = """# This file was automatically generated by lastchange.py.
LASTCHANGE=%s
LASTCHANGE_FULL=%s
""" % (version_info.revision[:7], version_info.revision)
    if out_file:
      WriteIfChanged(out_file, contents)
    else:
      sys.stdout.write(contents)

  return 0


if __name__ == '__main__':
  sys.exit(main())
