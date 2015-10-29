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
"""Generates a few sample trace files for an instrumented version of test_dll
in $(OutDir)/test_data. The trace files are output to:

  $(OutDir)/test_data/AGENT_NAME_HERE_traces/trace-%d.bin.

This depends on call_trace_service.exe, the agent DLL, and the instrumented
test_dll having already been built.
"""
import glob
import logging
import optparse
import os
import pywintypes
import shutil
import subprocess
import sys
import tempfile
import time
import win32api
import win32con


_LOGGER = logging.getLogger(os.path.basename(__file__))


_CALL_TRACE_SERVICE_EXE = 'call_trace_service.exe'
_INPUTS = [_CALL_TRACE_SERVICE_EXE]
_DEFAULT_ITERATIONS = 4


def _LoadDll(dll_path):
  """Tries to load, hence initializing, the given DLL.

  Args:
    dll_path: the path to the DLL to load.

  Returns:
    True on success, False on failure.
  """
  mode = (win32con.SEM_FAILCRITICALERRORS |
          win32con.SEM_NOALIGNMENTFAULTEXCEPT |
          win32con.SEM_NOGPFAULTERRORBOX |
          win32con.SEM_NOOPENFILEERRORBOX)
  old_mode = win32api.SetErrorMode(mode)
  try:
    handle = win32api.LoadLibrary(dll_path)
    if not handle:
      return False
    win32api.FreeLibrary(handle)
  except pywintypes.error as e:  # pylint: disable=E1101
    _LOGGER.error('Error: %s', e)
    return False
  finally:
    win32api.SetErrorMode(old_mode)
  return True


def _RunImage(image_path):
  """Tries to execute the given image.

  Args:
    image_path: the path to the image to run.

  Returns:
    True on success, False on failure.
  """
  return not subprocess.call([image_path])


def _LoadInstrumentedImageInNewProc(opts):
  """Loads opts.instrumented_image in a sub-process using --load-image.

  Args:
    opts: the parsed and validated arguments.

  Returns:
    True on success, False otherwise.
  """
  cmd = [sys.executable, __file__, '--build-dir', opts.build_dir,
         '--instrumented-image', opts.instrumented_image, '--load-image']
  return not subprocess.call(cmd)


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
  parser.add_option('--env', dest='env', default=[], type='string',
                    action='append',
                    help='Environment strings to set prior to execution.')
  parser.add_option('--instrumented-image', dest='instrumented_image',
                    help='The instrumented image to use.')
  parser.add_option('--iterations', dest='iterations', type="int",
                    default=_DEFAULT_ITERATIONS,
                    help='Sets the number of iterations to run.')
  parser.add_option('--load-image', dest='load_image',
                    action='store_true', default=False,
                    help='Attempt to load/run the given image.')
  parser.add_option('--output-dir', dest='output_dir',
                    help='The output directory to write to.')
  (opts, dummy_args) = parser.parse_args()

  # Set any environment variables that have been provided.
  if opts.env:
    for kv in opts.env:
      k, v = kv.split('=')
      os.environ[k] = v

  if not opts.instrumented_image:
    parser.error('You must specify --instrumented-image.')
  opts.instrumented_image = os.path.abspath(opts.instrumented_image)
  if not os.path.isfile(opts.instrumented_image):
    parser.error('Instrumented image does not exist: %s' %
        opts.instrumented_image)

  if not opts.build_dir:
    parser.error('You must specify --build-dir.')
  # We strip the build-dir param of trailing quotes as a workaround for:
  # http://code.google.com/p/gyp/issues/detail?id=272
  opts.build_dir = os.path.abspath(opts.build_dir).rstrip('"\'')
  if not os.path.isdir(opts.build_dir):
    parser.error('Build directory does not exist: %s' % opts.build_dir)

  if not opts.load_image and not opts.output_dir:
    parser.error('You must specify one of --load-image or --output-dir.')

  if opts.output_dir:
    opts.output_dir = os.path.abspath(opts.output_dir)
    if os.path.exists(opts.output_dir):
      if not os.path.isdir(opts.output_dir):
        parser.error('Output location exists and is not a directory: %s' %
            opts.output_dir)
    else:
      os.makedirs(opts.output_dir)

  # Validate that all of the input files exist.
  for path in _INPUTS:
    abs_path = os.path.join(opts.build_dir, path)
    if not os.path.isfile(abs_path):
      parser.error('File not found: %s.' % abs_path)

  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.ERROR)

  return opts


class ScopedTempDir:
  """A simple scoped temporary directory class. Cleans itself up when
  deleted.

  Attributes:
    path: the path to the temporary directory.
  """

  def __init__(self, suffix='', prefix='tmp', parent_dir=None):
    """Initializes a ScopedTempDir.

    Args:
      suffix: the suffix to be attached to the random directory name.
          Defaults to ''.
      prefix: the prefix to be attached to the random directory name.
          Defaults to 'tmp'.
      parent_dir: the parent directory within which the temporary directory
          should be placed. If None, uses the TEMP environment variable.
    """
    self.path = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=parent_dir)

  def Delete(self):
    """Deletes the temporary directory, and all of its contents."""
    if self.path:
      _LOGGER.info('Cleaning up temporary directory "%s".', self.path)
      shutil.rmtree(self.path)
      self.path = None

  def __del__(self):
    """Destructor. Automatically calls Delete."""
    self.Delete()


def _MainLoadImage(opts):
  """Main entry point for this script when executed with --load-image.

  Args:
    opts: the parsed and validated arguments.

  Returns:
    0 on success, a non-zero value on failure.
  """
  # Put the build directory in the search path so we find export_dll.dll and
  # the various instrumentation binaries.
  win32api.SetDllDirectory(opts.build_dir)
  ext = os.path.splitext(opts.instrumented_image)[1]
  if ext.lower() == '.dll':
    if _LoadDll(opts.instrumented_image):
      return 0
  else:
    if _RunImage(opts.instrumented_image):
      return 0
  return 1


def _MainGenerateTraces(opts):
  """The main entry point for this script when we are generated trace files.

  Args:
    opts: the parsed and validated arguments.

  Returns:
    0 on success, a non-zero value on failure.
  """
  # Ensure the final destination directory exists as a fresh directory.
  trace_dir = opts.output_dir
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
                                 parent_dir=opts.output_dir)
  _LOGGER.info('Trace files will be written to "%s".', temp_trace_dir.path)

  # This is the destination of stdout/stderr for the various commands we run.
  stdout_dst = None
  if not opts.verbose:
    stdout_dst = open(os.devnull, 'wb')

  # Start the call trace service as a child process. We sleep after starting
  # it to ensure that it is ready to receive data. If we're not in verbose
  # mode we direct its output to /dev/null.
  _LOGGER.info('Starting the call trace service.')
  call_trace_service_exe = os.path.join(opts.build_dir, _CALL_TRACE_SERVICE_EXE)
  instance_id_param = '--instance-id=%d' % os.getpid()
  os.environ['SYZYGY_RPC_INSTANCE_ID'] = str(os.getpid())
  cmd = [call_trace_service_exe, '--verbose', instance_id_param,
         '--trace-dir=%s' % temp_trace_dir.path, 'start']
  call_trace_service = subprocess.Popen(cmd, stdout=stdout_dst,
                                        stderr=stdout_dst)
  time.sleep(1)

  # Invoke the instrumented image a few times.
  load_image_failed = False
  image = opts.instrumented_image
  for dummy_i in xrange(opts.iterations):
    _LOGGER.info('Loading the instrumented image: %s', image)
    if not _LoadInstrumentedImageInNewProc(opts):
      _LOGGER.error('Failed to load instrumented image.')
      load_image_failed = True

  # Stop the call trace service. We sleep a bit to give time for things to
  # settle down.
  _LOGGER.info('Stopping the call trace service.')
  time.sleep(1)
  cmd = [call_trace_service_exe, instance_id_param, 'stop']
  result = subprocess.call(cmd, stdout=stdout_dst, stderr=stdout_dst)
  if result != 0:
    _LOGGER.error('"%s" returned with an error: %d.', cmd[0], result)
    return 1

  # Wait for the call trace service to shutdown.
  call_trace_service.communicate()
  if call_trace_service.returncode != 0:
    _LOGGER.error('"%s" returned with an error: %d.',
                  call_trace_service_exe, call_trace_service.returncode)
    return 1

  # If the image was unable to be loaded, don't bother looking for the trace
  # files.
  if load_image_failed:
    _LOGGER.error('Failed to load instrumented image.')
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
  if count != opts.iterations:
    _LOGGER.error('Expected %d trace files, only found %d.',
                  opts.iterations, count)
    return 1

  return 0


def Main():
  """Main entry point for the script."""
  opts = _ParseArgs()

  # If --load-image is specified, use our alternate main function.
  if opts.load_image:
    return _MainLoadImage(opts)

  return _MainGenerateTraces(opts)


if __name__ == '__main__':
  sys.exit(Main())
