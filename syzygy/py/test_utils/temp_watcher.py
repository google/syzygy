#!python
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

"""Utilities and script for running processes with a scoped temporary directory.

This file defines a Popen-derived object that redirects TMP/TEMP to a temporary
directory  and checks the contents at the end of the subprocess. If the
directory is not empty it can print warning or errors as need be. It can also
optionally clean up the temporary directory.

This file may also be run as a script for directly launching processes with a
monitored temporary directory.
"""

import io
import logging
import optparse
import os
import shutil
import subprocess
import sys
import tempfile


_LOGGER = logging.getLogger(os.path.basename(__file__))


def _GetFiles(rootdirpath):
  """Gets the files and directories in rootdirpath, recursively.

  Args:
    rootdirpath: The root directory to traverse.

  Returns:
    A list of files in the tree, with paths relative to rootdirpath.
  """
  files = []
  for dirpath, dirnames, filenames in os.walk(rootdirpath):
    for dirname in dirnames:
      subdirpath = os.path.join(dirpath, dirname)
      relsubdirpath = os.path.relpath(subdirpath, dirpath)
      files.append(relsubdirpath)

    for filename in filenames:
      filepath = os.path.join(dirpath, filename)
      relfilepath = os.path.relpath(filepath, dirpath)
      files.append(relfilepath)

  return sorted(files)


class Popen(subprocess.Popen):
  """A subprocess.Popen object that redirects the temporary directory.

  Properties:
    orphaned_files: Returns a list of orphaned files (empty if there are none)
        once the process has terminated. If the process is still running this
        returns None.
    origreturncode: The return code of the subprocess. 'returncode' has been
        overridden to also consider the state of the temporary directory.
  """

  def __init__(self, *args, **kwargs):
    """Initializes a subprocess.

    Args:
      cleanup: If True will automatically clean up the temporary directory
          when the executable has finished running.
      env: The environment to use in executing the subprocess. If TMP or TEMP
          are specified in this, they will be overridden.
      fail: If True will return non-zero status if the temporary directory
          is not empty after the child process terminates. Otherwise it will
          simply log a warning.
    """
    self._cleanup = kwargs.pop('cleanup', False)
    self._fail = kwargs.pop('fail', False)
    self._orphaned_files = None
    self._origreturncode = None
    self._newreturncode = None

    # Set up the environment for the subprocess.
    env = kwargs.pop('env', os.environ)
    self._temp = tempfile.mkdtemp(prefix='temp_watcher_')
    env['TMP'] = self._temp
    env['TEMP'] = self._temp
    _LOGGER.info('Redirected temporary directory to "%s".', self._temp)

    # Launch the subprocess.
    kwargs['env'] = env
    _LOGGER.debug('Running command [%s]', *args)
    subprocess.Popen.__init__(self, *args, **kwargs)

  def _Log(self, *args, **kwargs):
    """Logs a message to as an error or a warning depending on _fail.
    """
    if self._fail:
      _LOGGER.error(*args, **kwargs)
    else:
      _LOGGER.warn(*args, **kwargs)

  def _OnProcessFinished(self, returncode):
    """Checks the temp directory for orphans and logs as appropriate.

    Cleans up _stdout_pipe and _stdout. If _cleanup is True, also cleans up
    the temporary directory. Should only be called after the child process
    has terminated. Sets _newreturncode.
    """
    # This can be called multiple times (if the user calls wait or poll
    # repeatedly), so we guard against running more than once. If the orphaned
    # files are already populated, we've already run this.
    if self._orphaned_files != None:
      return

    # Get the orphaned files and log as necessary.
    self._orphaned_files = _GetFiles(self._temp)
    count = len(self._orphaned_files)
    if count:
      self._Log('Encountered %d orphaned files/directories.', count)
      for path in self._orphaned_files:
        _LOGGER.info('Found orphan "%s".', path)

    # Do any cleanup if necessary.
    if self._cleanup:
      _LOGGER.info('Cleaning up temporary directory "%s".', self._temp)
      shutil.rmtree(self._temp)
    else:
      _LOGGER.info('Leaving temporary directory "%s".', self._temp)
    self._temp = None

    # Set the new return code.
    if returncode != 0:
      self._newreturncode = returncode
    elif self._fail and self._orphaned_files:
      self._newreturncode = -1
    else:
      self._newreturncode = 0

  def __del__(self):
    """Destructor."""
    self.wait()

  @property
  def orphaned_files(self):
    """Returns the list of orphaned files.

    This is None if the process has not yet terminated.
    """
    return self._orphaned_files

  @property
  def origreturncode(self):
    """Returns the return code of the subprocess, regardless of any orphaned
    file in the temporary directory. This is None if the process has not yet
    terminated.
    """
    return self._origreturncode

  def _set_returncode(self, returncode):
    """Sets the return code.

    Used to intercept the setting of 'returncode'. We instead store the
    value in '_origreturncode', and use this as a hook to determine that the
    process hash ended (which occurs when this is set to an integer value).
    We in turn use that trigger to calculate our combined return code as
    '_newreturncode', which takes into account the status of the temp directory.
    """
    self._origreturncode = returncode
    if type(returncode) is int:
      # This sets _newreturncode.
      self._OnProcessFinished(returncode)

  def _get_returncode(self):
    """Returns the modified return code.

    This is used to intercept calls to get the return code, instead returning
    the combined process return code / temp directory status return code
    stored in '_newreturncode'.
    """
    return self._newreturncode

  # Override the Popen returncode with our own. We use this as a hook to know
  # when the process has finished.
  returncode = property(_get_returncode, _set_returncode)


def Run(command, cleanup=False, fail=False):
  """Runs a command using a temp_watcher.Popen object.

  Args:
    command: The command to run.
    cleanup: If True will automatically clean up the temporary directory
        when the executable has finished running.
    fail: If True will return non-zero status if the temporary directory
        is not empty after the child process terminates and log an error.
        Otherwise it will simply log a warning.

  Returns:
    0 on success, non-zero on failure.
  """

  proc = Popen(command, cleanup=cleanup, fail=fail)
  proc.wait()
  return proc.returncode


def _GetOptParser():
  """Build an option parser for this class."""
  parser = optparse.OptionParser()
  parser.add_option('-f', '--fail', dest='fail', action='store_true',
                    default=False,
                    help='Fail if the temporary directory is not empty '
                         'after running the subprocess.')
  parser.add_option('-c', '--cleanup', dest='cleanup', action='store_true',
                    default=False,
                    help='Cleanup the temp directory after running the '
                         'subprocess.')
  parser.add_option('--verbose', dest='log_level', action='store_const',
                    const=logging.INFO, default=logging.WARNING,
                    help='Run the script with verbose logging.')
  return parser


def Main():
  parser = _GetOptParser()
  options, args = parser.parse_args()

  logging.basicConfig(level=options.log_level)

  if not args:
    _LOGGER.error('Must provide a subprocess command-line.')
    return -1

  return Run(args, cleanup=options.cleanup, fail=options.fail)


if __name__ == '__main__':
  sys.exit(Main())
