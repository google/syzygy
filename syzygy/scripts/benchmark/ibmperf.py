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

"""Wrappers for the IBM Performance Inspector toolkit.

This module provides thin wrappers for the IBM Performance Inspector toolkit,
which unfortunately does not expose any interface other than the command-line.
The toolkit, as well as supporting documentation and examples, may be found
here:

  http://perfinsp.sourceforge.net/index.html

The module defines the following classes:

  Error: The exception type that is used by the module.
  IbmPerfTool: A base class containing utility functions for running
      toolkit utilities, automatically ensuring it is installed.
  HardwarePerformanceCounter: Class for controlling and querying hardware
      performance counters on a per-process basis.
"""

__author__ = "chrisha@chromium.org (Chris Hamilton)"

import logging
import os.path
import re
import subprocess
import time


DEFAULT_DIR = 'C:\\ibmperf\\bin'
_LOGGER = logging.getLogger(__name__)


class Error(Exception):
  """Exception class that is used by all classes defined in this module."""
  pass


class IbmPerfTool(object):
  """Base class wrapper for IBM Performance Inspector tools. Provides utility
  functions for accessing the toolkit, and automatically checks if it is
  installed, trying to install it if necessary."""

  def __init__(self, ibmperf_dir=DEFAULT_DIR):
    """Initializes this instance. Checks to see if the toolkit is installed
    (the running kernel has been patched), and attempts to install if not.

    Args:
      ibmperf_dir: path to the IBM Performance Inspector tools. Defaults to
          DEFAULT_DIR.

    Raises:
      Error: An error occurred trying to install the toolkit, or while
          checking if was installed.
      OSError: The toolkit was not installed at the provided path.
    """
    self._ibmperf_dir = os.path.abspath(ibmperf_dir)
    try:
      _LOGGER.info('Checking if driver installed.')
      self._Run('ddq', [])
      _LOGGER.info('Driver already installed.')
    except Error:
      # If ddq fails, it's because the driver is not installed. Try
      # to install it.
      _LOGGER.info('Installing IBM Performance Inspector driver.')
      self._Run('tinstall.cmd', [])

  def _Run(self, toolname, args, expected_returncode=0):
    """Runs the wrapped tool with the given arguments, and returns its output
    as a string. Raises an exception if the executable is non-existent or
    its return code is not as expected.

    Args:
      toolname: the name of the executable to be run.
      args: a list of arguments to pass on the command-line.
      expected_returncode: the return code the tool should return on success.
        Defaults to zero.

    Returns:
      The standard output of the command, as an array of lines.

    Raises:
      Error: The executable returned with an unexpected code.
      OSError: The executable does not exist, or some other error occurred in
          subprocess.Popen or Pipe.communicate.
    """
    tool_path = os.path.join(self._ibmperf_dir, toolname)
    cmd_line = [tool_path] + args
    _LOGGER.debug('Running command "%s".' % ' '.join(cmd_line))
    cmd = subprocess.Popen(cmd_line,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           cwd=self._ibmperf_dir)
    stdout, stderr = cmd.communicate()
    returncode = cmd.returncode
    if returncode != expected_returncode:
      _LOGGER.error('STDOUT: %s' % stdout)
      _LOGGER.error('STDERR: %s' % stderr)
      raise Error('"%s" returned code "%d".' %
          (toolname, returncode))
    return stdout.splitlines()


class PrivilegeLevel:
  """Acts as an enumeration of the privilege levels that the Performance
  Inspector toolkit can monitor."""

  # Only monitors code in Ring 0 (kernel code).
  KERNEL = 0

  # Only monitors instructions in Ring 3 (user code).
  USER = 1

  # Monitors instructions in Ring 0 and Ring 3 (both kernel and user code).
  ANY = 2

  # Maps PrivilegeLevel constants to command-line options as used by 'ptt'.
  NAMES = {KERNEL: 'priv_kernel', USER: 'priv_user', ANY: 'priv_any'}


class HardwarePerformanceCounter(IbmPerfTool):
  """Wraps ptt/mpevt, allowing access to hardware performance metrics.

  This class is intended to be used via a simple Start/Query/Stop interface.
  Not that Query must be called while the counters are running (prior to
  calling Stop), as all data is discarded upon calling Stop. Example usage:

  hpc = HardwarePerformanceCounter(ibmperf_dir="C:\\ibmperf\\bin")
  hpc.Start(['CYCLES', 'NONHALTED_CYCLES', 'TLB_MISSES'],
            PrivilegeLevel.USER)

  ... run some benchmark here ...

  chrome_results = hpc.Query('chrome')
  hpc.Stop()

  To get a list of available metrics and their descriptions, simply inspect
  the 'metrics' dict. To determine which of these are 'free' (do not occupy
  a hardware counter) and 'non-free' (require a dedicated hardware counter),
  look at the sets 'free_metrics' and 'nonfree_metrics'.

  It is possible for the utilities to stop working in the middle of a
  performance run. If this happens, the likely culprit is that the kernel
  took an in-place update, and the kernel patch created by the toolkit
  driver installation was overwritten. The only solution is to reinstall
  the driver and run the tests again.

  Attributes:
    free_metrics: A list of metrics that may be measured without occupying
        a hardware counter.
    max_counters: The maximum number of hardware counters that may be used
        simultaneously.
    metrics: A dict of valid metrics, with metric as keys and their
        descriptions as values.
    nonfree_metrics: A list of metrics that require a hardware counter.
  """

  # We wrap the command-line tools by parsing their output. This is a
  # collection of strings and regular expressions that simplify the task.
  _CYCLES = 'CYCLES'
  _DUMP_DATA = re.compile('^(?:[0-9]+\s+){4}[0-9]+(?:\s+[0-9]+)*$')
  _DUMP_HEADER = re.compile('^PID\s+TID\s+Disp\s+Intr\s+[A-Z0-9_].*$')
  _DIVIDER = re.compile('^-[\s -]*-$')
  _INT = re.compile('^[0-9]+$')
  _METRIC_NAME = re.compile('^[A-Z0-9_]+$')
  _NO_DATA = re.compile('^([0-9]+)\s+\*\*\s+No Data\s+\*\*$')
  _NO_DESCRIPTION = '(no description provided)'
  _PTT = 'ptt'
  _PTT_METRIC = re.compile('^- ([A-Z0-9_]+)$')

  def __init__(self, *args, **kwargs):
    """Initializes a HardwarePerformanceCounter object wrapping the IBM
    Performance Inspector 'ptt' tool. All arguments are passed directly
    to the IbmPerfTool base class, and any errors raised there are left
    uncaught."""
    super(HardwarePerformanceCounter, self).__init__(*args, **kwargs)
    self._GetAvailableMetrics()
    self._running_metrics = None

    # Some metrics are 'free', in the sense that they can always be
    # collected and don't use up a performance counter.
    self.free_metrics = set([self._CYCLES])
    self.non_free_metrics = set(self.metrics.keys()) - self.free_metrics

    # Some CPUs can actually handle more than this, but we currently have
    # no reliable way of detecting this.
    self.max_counters = 2

  def _GetAvailableMetrics(self):
    """Populates the internal dictionary of supported metrics, 'metrics'.
    The key is the metric name, the value is its description.

    Raises:
      Error: Upon failure of the underlying command-line utilities.
    """
    self.metrics = {}

    # Get the available metrics from ptt.
    # Metric names have the form: '- METRIC1_NAME'.
    lines = self._Run(self._PTT, [])
    for line in lines:
      line = line.strip()
      match = re.match(self._PTT_METRIC, line)
      if match:
        self.metrics[match.group(1)] = self._NO_DESCRIPTION
        continue

    # Provide a default description for CYCLES.
    self.metrics[self._CYCLES] = 'Number of CPU cycles.'

    # Get descriptions for the various metrics using 'mpevt'.
    lines = self._Run('mpevt', ['-ld'], expected_returncode=-1)
    seen_divider = False
    for line in lines:
      line = line.strip()
      if not seen_divider:
        seen_divider = re.match(self._DIVIDER, line)
      else:
        counter = re.split('\s+', line, 2)
        if (len(counter) == 3 and re.match(self._INT, counter[0]) and
            re.match(self._METRIC_NAME, counter[1]) and
            self.metrics.has_key(counter[1])):
          desc = counter[2].strip()
          if desc[-1] != '.':
            desc += '.'
          self.metrics[counter[1]] = desc

  def Start(self, metric_names, privilege_level=PrivilegeLevel.USER):
    """Starts the hardware performance counter for the given metrics. Metrics
    that are 'free' (do not require the use of a dedicated CPU counter) may
    always be specified. However, metrics that require the use of a CPU
    counter are limited in number to 'max_counters'.

    Args:
      metric_names: a list of metrics to run. These must match the names of
          metrics in 'metrics'. No more than 'max_counters' metrics may be
          specified that are present in the list 'non_free_metrics'.
      privilege_leve: the privilege level at which to monitor instructions.
        This must be one of the values from the PrivilegeLevel enumeration.

    Raises:
      Error: Upon failure of any of the command-line utilities.
    """
    for metric_name in metric_names:
      if not self.metrics.has_key(metric_name):
        raise Error('Unknown metric name "%s".' % metric_name)

    # Get the privilege level. If invalid, default to priv_user.
    priv = PrivilegeLevel.NAMES.get(privilege_level, None)
    if not priv:
      priv = PrivilegeLevel.NAMES.get(PrivilegeLevel.USER)

    _LOGGER.info('Starting counters for metrics: %s.' % metric_names)
    self._Run(self._PTT, ['term'])
    self._Run(self._PTT, ['noautoterm'])

    metric_names = list(metric_names)
    args = ['init'] + metric_names + [priv, '-force']
    output = self._Run(self._PTT, args)
    self._running_metrics = metric_names

  def Query(self, program_name):
    """Queries the running performance counters for the given program name.
    The metrics must be running (Start has been called, but not Stop).

    Args:
      program_name: the name of the executable for which to gather
         metrics. This will be split and only the executable name (without
         path or extension) will be used. For example, passing in
         'C:\\Program Files\\Google\\Chrome\\chrome.exe' is equivalent to
         passing in 'chrome'.

    Returns:
      A dict mapping the metric name to a dict of values, one per running
      instance of the specified executable at the time of the query. The nested
      dict maps process IDs to counter values. For example:

      {'CYCLES': {100: 123456, 200: 1234},
       'NONHALTED_CYCLES': {100: 100000, 200: 1000}}

    Raises:
      Error: Upon failure of the the underlying command-line utilities, or if
         Start has not been previously called.
    """
    if not self._running_metrics:
      raise Error('No metrics are running.')

    # Get the bare executable name.
    (head, tail) = os.path.split(program_name)
    (root, ext) = os.path.splitext(tail)

    _LOGGER.info('Querying performance counters for "%s": %s.' %
        (root, self._running_metrics))
    lines = self._Run(self._PTT, ['dump', '-pl', root])

    values = {}
    metrics = None

    for line in lines:
      line = line.strip()

      # Keep an eye out for the line containing the metric names. If
      # the header pattern is matched, then we are guaranteed to have at
      # least 5 items after the split.
      if not metrics:
        if re.match(self._DUMP_HEADER, line):
          columns = re.split('\s+', line)
          metrics = columns[4:]

          if set(metrics) != set(self._running_metrics):
            raise Error('Reported metrics do not match running metrics: %s.' %
                metrics)

          for metric in metrics:
            values[metric] = {}

        continue

      # Is this a PID without data? Then store zero values for the metrics.
      match = re.match(self._NO_DATA, line)
      if match:
        pid = int(match.group(1))
        for metric in metrics:
          values[metric][pid] = 0

        continue

      # Is this a PID/TID/Disp/Intr/Metrics line? Then tally the
      # running sum for the PID. We manually summarize because
      # summary lines are only produced if there is more than one
      # thread for a PID.
      if re.match(self._DUMP_DATA, line):
        data = re.split('\s+', line)
        if len(data) == len(metrics) + 4:
          pid = int(data[0])
          for i in range(len(metrics)):
            metric = metrics[i]
            count = int(data[4+i])
            values[metric][pid] = values[metric].get(pid, 0) + count

    if not metrics:
      raise Error('No results seen for metrics: %s.' % self._running_metrics)

    return values

  def Stop(self):
    """Stops the hardware performance counters. After calling this, all
    metric data is discarded and further calls to Query will fail. New metrics
    may be gathered with another call to Start.

    Raises:
      Error: Upon failure of the underlying command-line utilities."""
    if not self._running_metrics:
      raise Error('No metrics are running.')

    _LOGGER.info('Stopping metrics: %s.' % self._running_metrics)
    self._running_metrics = None
    self._Run(self._PTT, ['term'])
