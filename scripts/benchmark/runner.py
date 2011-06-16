#!/usr/bin/python2.6
# Copyright 2011 Google Inc.
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
"""Utility classes and functions to run benchmarks on Chrome execution and
extract metrics from ETW traces."""

import chrome_control
import ctypes
import ctypes.wintypes
import etw
import etw_db
import etw.evntrace as evn
import event_counter
import exceptions
import glob
import logging
import os.path
import pkg_resources
import re
import shutil
import subprocess
import sys
import tempfile
import time
import win32api


# The Windows prefetch directory, this is possibly only valid on Windows XP.
_PREFETCH_DIR = os.path.join(os.environ['WINDIR'], 'Prefetch')


# Set up a file-local logger.
_LOGGER = logging.getLogger(__name__)


_XP_MAJOR_VERSION = 5


def _DeletePrefetch():
  """Deletes all files that start with Chrome.exe in the OS prefetch cache.
  """
  files = glob.glob('%s\\Chrome.exe*.pf' % _PREFETCH_DIR)
  _LOGGER.info("Deleting %d prefetch files", len(files))
  for file in files:
    os.unlink(file)


def _GetRunInSnapshotExeResourceName():
  """Return the name of the most appropriate run_in_snapshot executable for
  the system we're running on."""
  maj, min = sys.getwindowsversion()[:2]
  # 5 is XP.
  if maj == _XP_MAJOR_VERSION:
    return 'run_in_snapshot_xp.exe'
  if maj < _XP_MAJOR_VERSION:
    raise RuntimeError('Unrecognized system version.')

  # We're on Vista or better, pick the 32 or 64 bit version as appropriate.
  is_wow64 = ctypes.wintypes.BOOL()
  is_wow64_function = ctypes.windll.kernel32.IsWow64Process
  if not is_wow64_function(win32api.GetCurrentProcess(),
                           ctypes.byref(is_wow64)):
    raise Exception('IsWow64Process failed.')
  if is_wow64:
    return 'run_in_snapshot_x64.exe'

  return 'run_in_snapshot.exe'


def _GetRunInSnapshotExe():
  """Return the appropriate run_in_snapshot executable for this system."""
  name = _GetRunInSnapshotExeResourceName()
  run_in_snapshot = pkg_resources.resource_filename(__name__,
                                                    os.path.join('exe', name))

  return run_in_snapshot


class BenchmarkRunner(object):
  """A utility class to manage the running of Chrome startup time benchmarks.

  This class can run a given Chrome instance through a few different
  configurable scenarios:
    * With Chrome.dll preloading turned on or turned off.
    * Cold/Warm start. To simulate cold start, the volume containing the
      Chrome executable under test will be remounted to a new drive letter
      using the Windows shadow volume service.
    * With Windows XP OS prefetching enabled or disabled.
  """

  def __init__(self, chrome_exe, profile_dir, preload, cold_start, prefetch,
               keep_temp_dirs):
    """Initialize instance.

    Args:
        chrome_exe: path to the Chrome executable to benchmark.
        profile_dir: path to the existing profile directory for Chrome.
        preload: specifies the state of Chrome.dll preload to use for
            benchmark.
        cold_start: if True, chrome_exe will be launched from a shadow volume
            freshly minted and mounted for each iteration.
        prefetch: if False, the OS prefetch files will be deleted before and
            after each iteration.
        keep_temp_dirs: if True, the script will not clean up the temporary
            directories it creates. This is handy if you want to e.g. manually
            inspect the log files generated.
    """
    self._chrome_exe = chrome_exe
    self._profile_dir = profile_dir
    self._preload = preload
    self._cold_start = cold_start
    self._prefetch = prefetch
    self._keep_temp_dirs = keep_temp_dirs
    self._results = {}
    self._temp_dir = None

  def Run(self, iterations):
    """Runs the benchmark for a given number of iterations.

    Args:
        iterations: number of iterations to run.
    """
    self._SetUp()

    try:
      # Run the benchmark for the number of iterations specified.
      for i in range(iterations):
        _LOGGER.info("Starting iteration %d", i)
        self._PreIteration(i)
        self._RunOneIteration(i)
        self._PostIteration(i)

      # Output the results after completing all iterations.
      self._OutputResults()
    except:
      _LOGGER.exception('Failure in iteration %d', i)
    finally:
      self._TearDown()

  def _SetUp(self):
    self._old_preload = chrome_control.GetPreload()
    chrome_control.SetPreload(self._preload)
    self._temp_dir = tempfile.mkdtemp(prefix='chrome-bench')
    _LOGGER.info('Created temporary directory "%s"', self._temp_dir)

  def _TearDown(self):
    chrome_control.SetPreload(*self._old_preload)
    if self._temp_dir and not self._keep_temp_dirs:
      _LOGGER.info('Deleting temporary directory "%s"', self._temp_dir)
      shutil.rmtree(self._temp_dir, ignore_errors=True)
      self._temp_dir = None

  def _RunOneIteration(self, i):
    _LOGGER.info("Iteration: %d", i)

    if self._cold_start:
      (drive, path) = os.path.splitdrive(self._chrome_exe)
      chrome_exe = os.path.join('M:', path)
      run_in_snapshot = _GetRunInSnapshotExe()
      cmd_line = [run_in_snapshot,
                  '--volume=%s\\' % drive,
                  '--snapshot=M:',
                  '--',
                  chrome_exe,
                  '--user-data-dir=%s' % self._profile_dir]
    else:
      cmd_line = [self._chrome_exe,
                  '--user-data-dir=%s' % self._profile_dir,
                  'http://www.google.com']

    _LOGGER.info('Launching command line [%s]', cmd_line)
    subprocess.Popen(cmd_line)

    # TODO(siggi): Poll for Chrome to come into existence, then
    #     give it a fixed amount of time to do its thing before
    #     winding down.
    time.sleep(20)

    _LOGGER.info("Shutting down Chrome Profile: %s", self._profile_dir)
    chrome_control.ShutDown(self._profile_dir)

  def _PreIteration(self, i):
    self._StartLogging()
    if not self._prefetch:
      _DeletePrefetch()

  def _PostIteration(self, i):
    self._StopLogging()
    self._ProcessLogs()

    if not self._prefetch:
      _DeletePrefetch()

  def _StartLogging(self):
    # TODO(siggi): This function needs to start a second ETW log session
    #    to capture output from Chrome's TRACE_EVENT macros.
    self._kernel_file = os.path.join(self._temp_dir, 'kernel.etl')
    _LOGGER.info('Starting kernel logging to file "%s"', self._kernel_file)

    prop = etw.TraceProperties()
    prop.SetLogFileName(os.path.abspath(self._kernel_file))
    p = prop.get()
    p.contents.Wnode.ClientContext = 1  # QPC timer accuracy.
    p.contents.LogFileMode = evn.EVENT_TRACE_FILE_MODE_SEQUENTIAL
    p.contents.EnableFlags = (evn.EVENT_TRACE_FLAG_PROCESS |
                              evn.EVENT_TRACE_FLAG_THREAD |
                              evn.EVENT_TRACE_FLAG_IMAGE_LOAD |
                              evn.EVENT_TRACE_FLAG_DISK_IO |
                              evn.EVENT_TRACE_FLAG_DISK_FILE_IO |
                              evn.EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS |
                              evn.EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS)
    # TODO(siggi): It might make sense to make these dynamic, and to re-run
    #     iterations with more/larger buffers if we've lost events.
    p.contents.BufferSize = 1024  # kilobytes - that's one meg.
    p.contents.MinimumBuffers = 100
    p.contents.MaximumBuffers = 200
    p.contents.FlushTimer = 0

    self._kernel_controller = etw.TraceController()
    try:
      # We may find the NT Kernel Logger running, so attempt to stop it
      # before we create our NT Kernel Logger session. Maybe we didn't shut
      # it down after the last iteration, or maybe someone else is using it.
      # If the latter, let's hope they don't get upset with us.
      evn.ControlTrace(evn.TRACEHANDLE(),
                       evn.KERNEL_LOGGER_NAME,
                       etw.TraceProperties().get(),
                       evn.EVENT_TRACE_CONTROL_STOP)
    except exceptions.WindowsError:
      # If the log isn't running, we get a WindowsError here.
      pass

    self._kernel_controller.Start(evn.KERNEL_LOGGER_NAME, prop)

  def _StopLogging(self):
    _LOGGER.info("Stopping kernel logging.")
    prop = etw.TraceProperties()
    self._kernel_controller.Stop(prop)

    buffers_lost = prop.get().contents.LogBuffersLost
    events_lost = prop.get().contents.EventsLost
    if events_lost or buffers_lost:
      _LOGGER.warning('%d ETW buffers lost', buffers_lost)
      _LOGGER.warning('%d ETW events lost', events_lost)
      _LOGGER.warning('You may need to increase the number or size of '
                      'of buffers (see _StartLogging).')

  def _ProcessLogs(self):
    parser = etw.consumer.TraceEventSource()
    parser.OpenFileSession(self._kernel_file)

    file_db = etw_db.FileNameDatabase()
    module_db = etw_db.ModuleDatabase()
    process_db = etw_db.ProcessThreadDatabase()
    counter = event_counter.LogEventCounter(file_db, module_db, process_db)
    parser.AddHandler(file_db)
    parser.AddHandler(module_db)
    parser.AddHandler(process_db)
    parser.AddHandler(counter)
    parser.Consume()

    # TODO(siggi): Other metrics, notably:
    #   Time from launch of browser to interesting TRACE_EVENT metrics
    #     in browser and renderers.
    self._AddResult('Chrome', 'HardPageFaults', counter._hardfaults)
    self._AddResult('Chrome', 'SoftPageFaults', counter._softfaults)

    if counter._process_launch and len(counter._process_launch) >= 2:
      browser_start = counter._process_launch.pop(0)
      renderer_start = counter._process_launch.pop(0)
      self._AddResult('Chrome',
                      'RendererLaunchTime',
                      renderer_start - browser_start,
                      's')

    # We leave it to TearDown to delete any files we've created.
    self._kernel_file = None

  def _OutputResults(self):
    """Outputs the benchmark results in the format required by the
    GraphingLogProcessor class, which is:

    RESULT <graph name>: <trace name>= [<comma separated samples>] <units>

    Example:
      RESULT Chrome: RendererLaunchTime= [0.1, 0.2, 0.3] s
    """
    for (key, value) in self._results.iteritems():
      (graph_name, trace_name) = key
      (units, results) = value
      print "RESULT %s: %s= %s %s" % (graph_name, trace_name,
                                      str(results), units)

  def _AddResult(self, graph_name, trace_name, sample, units=''):
    _LOGGER.info("Adding result %s, %s, %s, %s",
                 graph_name, trace_name, str(sample), units)
    results = self._results.setdefault((graph_name, trace_name), (units, []))
    results[1].append(sample)
