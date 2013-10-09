#!/usr/bin/python2.6
# Copyright 2011 Google Inc. All Rights Reserved.
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


_LOGGER = logging.getLogger(__name__)


# The default directory where we expect the IBM Performance Inspector toolkit
# to be installed.
DEFAULT_DIR = "C:\\ibmperf\\bin"


# These are the names of the various executables we wrap.
_DDQ = "ddq"
_MPEVT = "mpevt"
_PTT = "ptt"
_TINSTALL = "tinstall.cmd"


class Error(Exception):
  """Base exception class for all exceptions raised by this module."""


class ExecutionFailed(Error):
  """Raised when a command-line tool fails."""


class InvalidMetric(Error):
  """Raised when an invalid metric is specified."""


class NotRunning(Error):
  """Raised when the toolkit is not running but should be."""


class UnexpectedOutput(Error):
  """Raised when the output of the underlying tools is not as expected."""


class IbmPerfTool(object):
  """Base class wrapper for IBM Performance Inspector tools.

  Provides utility functions for accessing the toolkit, and automatically
  checks if it is installed, trying to install it if necessary.
  """

  def __init__(self, ibmperf_dir=DEFAULT_DIR):
    """Initializes this instance.

    Checks to see if the toolkit is installed (the running kernel has been
    patched), and attempts to install if not.

    Args:
      ibmperf_dir: path to the IBM Performance Inspector tools. Defaults to
          DEFAULT_DIR.

    Raises:
      ExecutionFailed: An error occurred trying to install the toolkit, or
          while checking if it was installed.
      OSError: The toolkit was not installed at the provided path.
    """
    self._ibmperf_dir = os.path.abspath(ibmperf_dir)
    try:
      _LOGGER.info("Checking if driver installed.")
      self._Run(_DDQ, [])
      _LOGGER.info("Driver already installed.")
    except Error:
      # If ddq fails, it's because the driver is not installed. Try
      # to install it.
      _LOGGER.info("Installing IBM Performance Inspector driver.")
      self._Run(_TINSTALL, [])

  def _Popen(self, cmd_line):
    """Creates a subprocess.Popen object for the given command-line.

    Separated for easy injection of results in unittests.

    Args:
      cmd_line: The command line to execute, with the executable and each
          argument as a separate entry in a list.

    Returns:
      An instance of subprocess.Popen for the given command-line.
    """
    return subprocess.Popen(cmd_line,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            cwd=self._ibmperf_dir)

  def _Run(self, toolname, args, expected_returncode=0):
    """Runs the wrapped tool with the given arguments.

    Runs the wrapped tool with the given arguments, and returns its output
    as a string. Raises an exception if the executable is non-existent or
    its return code is not as expected.

    Args:
      toolname: the name of the executable to be run.
      args: a list of arguments to pass on the command-line.
      expected_returncode: the return code the tool should return on success.
          Defaults to zero.

    Returns:
      The standard output of the command, as a list of lines.

    Raises:
      ExecutionFailed: The executable returned with an unexpected code.
      OSError: The executable does not exist, or some other error occurred in
          subprocess.Popen or Pipe.communicate.
    """
    tool_path = os.path.join(self._ibmperf_dir, toolname)
    cmd_line = [tool_path] + args
    _LOGGER.debug("Running command '%s'.", " ".join(cmd_line))
    cmd = self._Popen(cmd_line)
    stdout, stderr = cmd.communicate()
    returncode = cmd.returncode
    if returncode != expected_returncode:
      raise ExecutionFailed("'%s' returned code '%d'.\n  STDOUT: %s\n"
                            "  STDERR: %s\n" %
                            (toolname, returncode, stdout, stderr))
    # Pylint doesn't know the type of 'stdout', so complains about a missing
    # member function. Ignore it.
    # pylint: disable=E1103
    return stdout.splitlines()


class PrivilegeLevel(object):
  """An enumeration of code privilege levels."""

  # Only monitors code in Ring 0 (kernel code).
  KERNEL = 0

  # Only monitors instructions in Ring 3 (user code).
  USER = 1

  # Monitors instructions in Ring 0 and Ring 3 (both kernel and user code).
  ANY = 2

  # Maps PrivilegeLevel constants to command-line options as used by "ptt".
  NAMES = {KERNEL: "priv_kernel", USER: "priv_user", ANY: "priv_any"}


class HardwarePerformanceCounter(IbmPerfTool):
  """Wraps ptt/mpevt, allowing access to hardware performance metrics.

  This class is intended to be used via a simple Start/Query/Stop interface.
  Not that Query must be called while the counters are running (prior to
  calling Stop), as all data is discarded upon calling Stop. Example usage:

  hpc = HardwarePerformanceCounter(ibmperf_dir="C:\\ibmperf\\bin")
  hpc.Start(["CYCLES", "NONHALTED_CYCLES", "TLB_MISSES"],
            PrivilegeLevel.USER)

  ... run some benchmark here ...

  chrome_results = hpc.Query("chrome")
  hpc.Stop()

  To get a list of available metrics and their descriptions, simply inspect
  the |metrics| dict. To determine which of these are free (do not occupy
  a hardware counter) and non-free (require a dedicated hardware counter),
  look at the sets |free_metrics| and |non_free_metrics|.

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
    metrics: A dict of valid metrics, with metric names as keys and their
        descriptions as values.
    non_free_metrics: A list of metrics that require a hardware counter.
  """

  # The CYCLES counter is a special case, as it is always available on any
  # machine.
  _CYCLES = "CYCLES"

  # If 'mpevt' is unable to provide a description for a metric we use this by
  # default.
  _NO_DESCRIPTION = "(no description provided)"

  # We wrap the command-line tools by parsing their output. This is a
  # collection of strings and regular expressions that simplifies the task.

  # We parse the output of 'ptt' to get a list of supported metrics. The output
  # is as follows:
  #
  # ***** ptt v2.0.8 for x86 ***** pid=3304/0xce8 *****
  #
  #  ptt {-? | -??}
  #  ptt {ints | noints}
  #  ptt {autoterm | noautoterm}
  #  ptt numthreads [## | default | large | max]
  #  ptt init [metric [metric] [...]]] <PrivLevel> [-force]
  #  ptt term
  #  ptt info
  #  ptt dump <ProcList> <JtnmOpt> <SortOpt> <AutoOpt> [-t sec] [-f fn] [-cpi]
  #
  #    <PrivLevel>: [priv_kernel | priv_user | priv_any]
  #     <ProcList>: [-pl {pid[,pid,...] | name[,name,...]}]
  #      <JtnmOpt>: [-jtnm | -jtnm=path[\prefix] [-allnames]]
  #      <SortOpt>: [-sm ## | -sp | -st | -sd | -si] [-a | -d]
  #      <AutoOpt>: [-s #sec] [r #sec]
  #
  #      Valid 'metric' values are:
  #      - CTR0 thru CTR1
  #      - CYCLES
  #      - NONHALTED_CYCLES
  #      - INSTR
  #      - UOPS
  #      - ALL_UOPS
  #      - BRANCH
  #      - MISPRED_BRANCH
  #      - ITLB_MISS
  #      - L2_READ_MISS
  #      - L2_READ_REFS
  #      - BRANCH_TAKEN
  #      - DATA_MEM_REFS
  #      - MISALIGN_MEM_REF
  #
  #  Enter "ptt -??" for more help.

  # This matches a line with a metric name on it, as output by 'ptt'. The
  # metric name is in the first captured group.
  _PTT_METRIC = re.compile("^- ([A-Z0-9_]+)$")

  # The output of 'ptt dump' is as follows (if there are more metrics running,
  # there are more columns reported):
  #
  # ***** ptt v2.0.8 for x86 ***** pid=1944/0x798 *****
  #
  #  PID   432 is chrome
  #  PID  3052 is chrome
  #
  # PTT Facility Per-Thread Information
  # -----------------------------------
  #
  #   PID    TID     Disp      Intr               INSTR    MISPRED_BRANCH
  #  -----  -----  --------  --------  ----------------  ----------------
  #    432   3848      1833      1837         677298430           2191266
  #    432    480        99        63         194081825            425171
  #    432   4056       244       105          57974343            404942
  #    432   3156        86        48          12158721            150688
  #    432   3540        38        32           7715634            122006
  #    432   2324        15        10           5110476             48280
  #    432   2844        18         7           2830719             41646
  #    432    192        25        13           1397386             20040
  #    432   2108        58         5            440747              5070
  #    432   2028         2         2            123323              1666
  #    432   2316         3         1            120130              1460
  #    432   3972        11         1            116428              1282
  #    432   3632         4         3             73104              2028
  #    432   2832         2         2             62340              1302
  #    432   2996         1         1             48720               959
  #    432   2300         2         1             43568              1027
  #    432    260         5         5             32896              1118
  #    432   3628         2         1             32539               634
  #                                    ----------------  ----------------
  #                                           959661329           3420585
  #
  #   3052   3304       409       514         286527847           2114053
  #   3052   3136       145        18            990444             19262
  #   3052   2620       331       188            398905              8614
  #   3052    608         2         1             49511               875
  #   3052   3984         3         4             48383              1394
  #                                    ----------------  ----------------
  #                                           288015090           2144198
  #
  # Execution ended: 1 iterations.

  # This matches a line of data in the output of 'ptt'. The individual
  # column values (integers) are in capturing groups.
  _DUMP_DATA = re.compile("""^(?:[0-9]+\s+){4}      # PID/TID/Disp/Intr.
                             [0-9]+(?:\s+[0-9]+)*$  # Metric values.""",
                          re.VERBOSE)

  # This matches the header prior to the start of data reported by 'ptt'.
  # The metric names are in capturing groups.
  _DUMP_HEADER = re.compile("""^PID\s+TID\s+Disp\s+Intr\s+  # Fixed columns.
                               [A-Z0-9_].*$                 # Metric names.""",
                            re.VERBOSE)

  # If there is no data collected for a given process, this will be output
  # instead.
  _NO_DATA = re.compile("""^([0-9]+)  # PID.
                           \s+\*\*\s+No Data\s+\*\*$""",
                        re.VERBOSE)

  # The command 'mpevt -l' has output like the following:
  #
  # ***** mpevt v2.0.8 for x86 *****
  #
  #  Id   Name
  #  ---  --------------------
  #  101  NONHALTED_CYCLES
  #  102  INSTR
  #  104  UOPS
  #  105  ALL_UOPS
  #  106  BRANCH
  #  107  MISPRED_BRANCH
  #  109  ITLB_MISS
  #  114  L2_READ_MISS
  #  115  L2_READ_REFS
  #  123  BRANCH_TAKEN
  #  124  DATA_MEM_REFS
  #  125  MISALIGN_MEM_REF

  # Matches the divider prior to the beginning of metric names and
  # descriptions.
  _DIVIDER = re.compile("^-+\s+-+$")
  _INT = re.compile("^[0-9]+$")
  _METRIC_NAME = re.compile("^[A-Z0-9_]+$")

  def __init__(self, *args, **kwargs):
    """Initializes a HardwarePerformanceCounter object.

    All arguments are passed directly to the IbmPerfTool base class, and any
    errors raised there are left uncaught.
    """
    super(HardwarePerformanceCounter, self).__init__(*args, **kwargs)
    self.metrics = {}
    self._GetAvailableMetrics()
    self._running_metrics = None

    # Some metrics are "free", in the sense that they can always be
    # collected and don't use up a performance counter.
    self.free_metrics = set([self._CYCLES])
    self.non_free_metrics = set(self.metrics) - self.free_metrics

    # Some CPUs can actually handle more than this, but we currently have
    # no reliable way of detecting this.
    self.max_counters = 2

  def _GetAvailableMetrics(self):
    """Populates the internal dictionary of supported metrics.

    This routine populates the internal dictionary of support metrics,
    |metrics|. The key is the metric name, the value is its description.

    Raises:
      ExecutionFailed: Upon failure of the underlying command-line utilities.
    """
    # Get the available metrics from ptt.
    # Metric names have the form: "- METRIC1_NAME".
    lines = self._Run(_PTT, [])
    for line in lines:
      line = line.strip()
      match = re.match(self._PTT_METRIC, line)
      if match:
        self.metrics[match.group(1)] = self._NO_DESCRIPTION
        continue

    # Provide a default description for CYCLES.
    self.metrics[self._CYCLES] = "Number of CPU cycles."

    # Get descriptions for the various metrics using "mpevt".
    lines = self._Run(_MPEVT, ["-ld"], expected_returncode=-1)
    seen_divider = False
    for line in lines:
      line = line.strip()
      if not seen_divider:
        seen_divider = re.match(self._DIVIDER, line)
      else:
        counter = re.split("\s+", line, 2)
        if (len(counter) == 3 and re.match(self._INT, counter[0]) and
            re.match(self._METRIC_NAME, counter[1]) and
            counter[1] in self.metrics):
          desc = counter[2].strip()
          if not desc.endswith("."):
            desc += "."
          self.metrics[counter[1]] = desc

  def Start(self, metric_names, privilege_level=PrivilegeLevel.USER):
    """Starts the hardware performance counter for the given metrics.

    Metrics that are free (do not require the use of a dedicated CPU counter)
    may always be specified. However, metrics that require the use of a CPU
    counter are limited in number to |max_counters|.

    Args:
      metric_names: a list of metrics to run. These must match the names of
          metrics in |metrics|. No more than |max_counters| metrics may be
          specified that are present in the list |non_free_metrics|.
      privilege_level: the privilege level at which to monitor instructions.
          This must be one of the values from the PrivilegeLevel enumeration.

    Raises:
      ExecutionFailed: Upon failure of any of the command-line utilities.
      InvalidMetric: Upon specification of an invalid metric.
    """
    for metric_name in metric_names:
      if metric_name not in self.metrics:
        raise InvalidMetric("Unknown metric name '%s'." % metric_name)

    # Get the privilege level. If invalid, default to priv_user.
    priv = PrivilegeLevel.NAMES.get(privilege_level, None)
    if not priv:
      priv = PrivilegeLevel.NAMES.get(PrivilegeLevel.USER)

    _LOGGER.info("Starting counters for metrics: %s.", metric_names)
    self._Run(_PTT, ["term"])
    self._Run(_PTT, ["noautoterm"])

    metric_names = list(metric_names)
    args = ["init"] + metric_names + [priv, "-force"]
    self._Run(_PTT, args)
    self._running_metrics = metric_names

  def Query(self, program_name):
    """Queries the running performance counters for the given program name.

    The metrics must be running (Start has been called, but not Stop).

    Args:
      program_name: the name of the executable for which to gather
          metrics. This will be split and only the executable name (without
          path or extension) will be used. For example, passing in
          "C:\Program Files\Google\Chrome\chrome.exe" is equivalent to
          passing in "chrome".

    Returns:
      A dict mapping the metric name to a dict of values, one per running
      instance of the specified executable at the time of the query. The nested
      dict maps process IDs to counter values. For example:

      {"CYCLES": {100: 123456, 200: 1234},
       "NONHALTED_CYCLES": {100: 100000, 200: 1000}}

    Raises:
      ExecutionFailed: Upon failure of the underlying command-line utilities.
      NotRunning: If Start has not been previously called.
      UnexpectedOutput: If the output of the underlying command-line utilities
          was not as expected.
    """
    if not self._running_metrics:
      raise NotRunning("No metrics are running.")

    # Get the bare executable name.
    tail = os.path.split(program_name)[1]
    root = os.path.splitext(tail)[0]

    _LOGGER.info("Querying performance counters for '%s': %s.",
                 root, self._running_metrics)
    lines = self._Run(_PTT, ["dump", "-pl", root])

    values = {}
    metrics = None

    for line in lines:
      line = line.strip()

      # Keep an eye out for the line containing the metric names. If
      # the header pattern is matched, then we are guaranteed to have at
      # least 5 items after the split.
      if not metrics:
        if re.match(self._DUMP_HEADER, line):
          columns = re.split("\s+", line)
          metrics = columns[4:]

          if set(metrics) != set(self._running_metrics):
            raise UnexpectedOutput("Reported metrics do not match running "
                                   "metrics: %s." % metrics)

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
        data = re.split("\s+", line)
        if len(data) == len(metrics) + 4:
          pid = int(data[0])
          for i, metric in enumerate(metrics):
            count = int(data[4+i])
            values[metric][pid] = values[metric].get(pid, 0) + count

    if not metrics:
      raise UnexpectedOutput("No results seen for metrics: %s." %
                             self._running_metrics)

    return values

  def Stop(self):
    """Stops the hardware performance counters.

    After calling this, all metric data is discarded and further calls to
    Query will fail. New metrics may be gathered with another call to Start.

    Raises:
      ExecutionFailed: Upon failure of the underlying command-line utilities.
      NotRunning: If Start has not been previously called.
    """
    if not self._running_metrics:
      raise NotRunning("No metrics are running.")

    _LOGGER.info("Stopping metrics: %s.", self._running_metrics)
    self._running_metrics = None
    self._Run(_PTT, ["term"])
