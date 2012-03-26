# Copyright 2012 Google Inc.
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
"""Generates a few sample trace files for the rpc_instrumented_test_dll.dll
in $(OutDir)/test_data. The trace files are output to:

  $(OutDir)/test_data/rpc_traces/trace-%d.bin.

This depends on call_trace_service.exe, call_trace_client.dll, and
$(OutDir)/test_data/rpc_instrumented_test_dll.dll having already been
built.
"""
import glob
import logging
import optparse
import os
import shutil
import subprocess
import sys
import tempfile
import time


_LOGGER = logging.getLogger(__name__)


_BUILD_DIR = 'build_dir'
_CALL_TRACE_SERVICE = 'call_trace_service'
_INSTRUMENTED_DLL = 'instrumented_dll'
_OUTPUT_DIR = 'output_dir'
_VERBOSE = 'verbose'


_INPUTS = { _CALL_TRACE_SERVICE: 'call_trace_service.exe',}
_INSTRUMENTED_DLL_ENTRY = 'DllMain'
_TRACE_FILE_COUNT = 4


def _ParseArgs():
  """Parses and validates the input arguments.

  Returns: a dictionary containing the options.
  """
  parser = optparse.OptionParser()
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true', default=False,
                    help='Enable verbose logging.')
  parser.add_option('--build-dir', dest='build_dir',
                    help='The build directory to use.')
  parser.add_option('--output-dir', dest='output_dir',
                    help='The output directory to write to.')
  parser.add_option('--instrumented-dll', dest='instrumented_dll',
                    help='The instrumented DLL to use.')
  (opts, args) = parser.parse_args()
  if not opts.output_dir:
    parser.error('You must specify --output-dir.')

  opts.output_dir = os.path.abspath(opts.output_dir)
  if not os.path.isdir(opts.output_dir):
    parser.error('Output directory does not exist: %s.' % opts.output_dir)

  optsdict = {
      _BUILD_DIR: opts.build_dir,
      _INSTRUMENTED_DLL: opts.instrumented_dll,
      _OUTPUT_DIR: opts.output_dir,
      _VERBOSE: opts.verbose }

  # Validate that all of the input files exist and get absolute paths to them.
  for name, path in _INPUTS.iteritems():
    abs_path = os.path.abspath(os.path.join(opts.build_dir, path))
    if not os.path.isfile(abs_path):
      parser.error('File not found: %s.' % abs_path)
    optsdict[name] = abs_path

  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.ERROR)

  return optsdict


class ScopedTempDir:
  """A simple scoped temporary directory class. Cleans itself up when
  deleted.

  Attributes:
    path: the path to the temporary directory.
  """

  def __init__(self, suffix='', prefix='tmp', dir=None):
    """Initializes a ScopedTempDir.

    Args:
      suffix: the suffix to be attached to the random directory name.
              Defaults to ''.
      prefix: the prefix to be attached to the random directory name.
              Defaults to 'tmp'.
      dir: the parent directory within which the temporary directory should
           be placed. If None, uses the TEMP environment variable.
    """
    self.path = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dir)

  def Delete(self):
    """Deletes the temporary directory, and all of its contents."""
    if self.path:
      _LOGGER.info('Cleaning up temporary directory "%s".', self.path)
      shutil.rmtree(self.path)
      self.path = None

  def __del__(self):
    """Destructor. Automatically calls Delete."""
    self.Delete()


def Main():
  opts = _ParseArgs()

  # Ensure the final destination directory exists as a fresh directory.
  trace_dir = opts[_OUTPUT_DIR]
  if os.path.exists(trace_dir):
    _LOGGER.info('Deleting existing destination directory "%s".', trace_dir)
    if os.path.isdir(trace_dir):
      shutil.rmtree(trace_dir)
    else:
      os.remove(trace_dir)
  os.makedirs(trace_dir)

  # Create a temporary directory where the call traces will be written
  # initially. We will later move them to the output directory, renamed to have
  # consistent names. We make this as a child directory of the output directory
  # so that it is on the same volume as the final destination.
  temp_trace_dir = ScopedTempDir(prefix='tmp_rpc_traces_',
                                 dir=opts[_OUTPUT_DIR])
  _LOGGER.info('Trace files will be written to "%s".', temp_trace_dir.path)

  # This is the destination of stdout/stderr for the various commands we run.
  stdout_dst = None
  if not opts[_VERBOSE]:
    stdout_dst = open(os.devnull, 'wb')

  # Start the call trace service as a child process. We sleep after starting
  # it to ensure that it is ready to receive data. If we're not in verbose
  # mode we direct its output to /dev/null.
  _LOGGER.info('Starting the call trace service.')
  cmd = [opts[_CALL_TRACE_SERVICE], '--verbose',
         '--trace-dir=%s' % temp_trace_dir.path, 'start']
  call_trace_service = subprocess.Popen(cmd, stdout=stdout_dst,
                                        stderr=stdout_dst)
  time.sleep(1)

  # Invoke the instrumented DLL a few times.
  for i in range(_TRACE_FILE_COUNT):
    _LOGGER.info('Loading the instrumented DLL.')
    cmd = ['rundll32', '%s,%s' % (opts[_INSTRUMENTED_DLL],
                                  _INSTRUMENTED_DLL_ENTRY)]
    popen = subprocess.Popen(cmd, cwd=opts[_BUILD_DIR])
    popen.communicate()
    if popen.returncode != 0:
      _LOGGER.error('"%s" returned with an error: %d', cmd[0], open.returncode)
      return 1

  # Stop the call trace service. We sleep a bit to give time for things to
  # settle down.
  _LOGGER.info('Stopping the call trace service.')
  time.sleep(1)
  cmd = [opts[_CALL_TRACE_SERVICE], 'stop']
  result = subprocess.call(cmd, stdout=stdout_dst, stderr=stdout_dst)
  if result != 0:
    _LOGGER.error('"%s" returned with an error: %d.', cmd[0], result)
    return 1

  # Wait for the call trace service to shutdown.
  call_trace_service.communicate()
  if call_trace_service.returncode != 0:
    _LOGGER.error('"%s" returned with an error: %d.',
                  opts[_CALL_TRACE_SERVICE], call_trace_service.returncode)
    return 1

  # Iterate through the generated trace files and move them to the final
  # output directory with trace-%d.bin names.
  count = 0
  for src in glob.glob(os.path.join(temp_trace_dir.path, '*.bin')):
    count += 1
    dst = os.path.join(trace_dir, 'trace-%d.bin' % count)
    _LOGGER.info('Moving "%s" to "%s".', src, dst)
    os.rename(src, dst)

  # Ensure that there were as many files as we expected there to be.
  if count != _TRACE_FILE_COUNT:
    _LOGGER.error('Expected %d trace files, only found %d.',
                  _TRACE_FILE_COUNT, count)
    return 1

  return 0


if __name__ == '__main__':
  sys.exit(Main())
