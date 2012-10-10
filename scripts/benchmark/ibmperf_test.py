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
"""Unittests for the ibmperf module.

If the IBM Performance Inspector tools are installed at "C:\ibmperf\bin" it
will run some tests using the actual tools. However, if the tools are not
installed it still runs a suite of tests using mocked versions of the tools.
"""

__author__ = "chrisha@chromium.org (Chris Hamilton)"

import ibmperf
import logging
import os
import random
import unittest


class MockPopen(object):
  """A mock subprocess.Popen object.

  Implements "returncode" and "communicate", the only attributes/routines
  used by the ibmperf module.

  Attributes:
    returncode: The return code of the mocked sub-process.
  """

  def __init__(self, stdout="", stderr="", returncode=0,
               raise_on_init=None, raise_on_communicate=None):
    """Initializes this mock Popen object with the given output and returncode.

    Args:
      stdout: The data to return for stdout in "communicate".
      stderr: The data to return for stderr in "communicate".
      returncode: The return code to expose via the "returncode" attribute.
      raise_on_init: If this is not None, will cause the constructor to raise
          an error. Expected to be a 2-tuple, containing (type, args), and will
          call "raise type(args)".
      raise_on_communicate: Similar to raise_on_init, but will cause the error
          to be raised on calls to "communicate".
    """
    if raise_on_init:
      raise raise_on_init[0](*raise_on_init[1])
    self._stdout = stdout
    self._stderr = stderr
    self.returncode = returncode
    self._raise_on_communicate = raise_on_communicate

  def communicate(self):
    """Simulates running the command, returning its stdout and stderr.

    Raises an exception if raise_on_communicate was specified in the
    constructor.
    """
    if self._raise_on_communicate:
      return self._raise_on_communicate[0](*self._raise_on_communicate[1])
    return (self._stdout, self._stderr)


class MockHardwarePerformanceCounter(ibmperf.HardwarePerformanceCounter):
  """A mocked ibmperf.HardwarePerformanceCounter object.

  Replaces the _Popen member function with one that returns canned results.
  """

  def __init__(self, popen_results, *args, **kwargs):
    """Initializes the mock HardwarePerformanceCounter object.

    Passes args and kwargs directly through to the
    ibmperf.HardwarePerformanceCounter initializer.

    Args:
      popen_results: A list of (type, args, kwargs) 3-tuples that will be
          returned from calls to _Popen, in order.
    """
    self._popen_results = list(popen_results)
    super(MockHardwarePerformanceCounter, self).__init__(*args, **kwargs)

  def AddPopenResult(self, result_tuple):
    """Adds the given result tuple to the queue of results to return.

    Args:
      result_tuple: A (type, args, kwargs) triplet.
    """
    self._popen_results.append(result_tuple)

  def _Popen(self, dummy_command_line):
    """Overrides _Popen from ibmperf.HardwarePerformanceCounter.

    Returns the mocked object from the head of the _popen_results queue.
    """
    object_type, args, kwargs = self._popen_results.pop(0)
    return object_type(*args, **kwargs)


# A few specific metric names.
_CYCLES = "CYCLES"
_UOPS = "UOPS"

# A list of metrics that we will simulate supporting.
_METRICS = {
    _CYCLES: None,
    "NONHALTED_CYCLES": ("Number of cycles during which the processor is not "
                         "halted (and not in Thermal Trip on Pentium Ms)"),
    "INSTR": "Number of instructions retired",
    _UOPS: "Number of uOps retired",
    "BRANCH": "Number of branch instruction retired",
    "MISPRED_BRANCH": "Number of mispredicted branch instructions retired"}

# A generic command that is successful outputs nothing and returns the default
# error code of 0.
_GENERIC_SUCCESS = (MockPopen, [], {})

# Simulates a successful run of "ddq", indicating that the toolkit is
# installed.
_DDQ_INSTALLED = _GENERIC_SUCCESS

# The simulated output of a successful call to "ptt".
_PTT_OUTPUT = "\n".join([" - %s" % _metric for _metric in _METRICS])
_PTT_SUCCESS = (MockPopen, [], {"stdout": _PTT_OUTPUT})

# The simulated output of a successful call to "mpevt -ld".
_MPEVT_OUTPUT = "Id Name Description\n-- ---- -----------"
for i, _metric in enumerate(_METRICS):
  desc = _METRICS[_metric]
  if desc:
    _MPEVT_OUTPUT += "\n%d %s %s" % (100 + i, _metric, desc)
_MPEVT_SUCCESS = (MockPopen, [], {"stdout": _MPEVT_OUTPUT, "returncode": -1})

# This is a set of MockPopen results that imitates a successful initialization
# of the toolkit.
_SUCCESSFUL_INIT = [_DDQ_INSTALLED, _PTT_SUCCESS, _MPEVT_SUCCESS]


def _CreateQueryResults(metrics):
  """Returns a set of made up results for the given metrics.

  Args:
    metrics: An iterable collection of metric names.
  """
  results = {}
  pids = [1015, 1016]
  for metric in metrics:
    pid_results = {}
    for pid in pids:
      pid_results[pid] = random.randint(100000, 1000000)
    results[metric] = pid_results
  return results


def _CreateQueryStdout(results):
  """Returns a "ptt dump" stdout for the given dict of results.

  See ibmperf.py for a full listing of sample output.

  Args:
    results: A dict of results as returned by
        ibmperf.HardwarePerformanceCounters.Query.
  """
  stdout = "***** ptt v2.0.8 for x86 ***** pid=1944/0x798 *****\n"
  stdout += "\n"
  pids = results[results.keys()[0]].keys()
  for pid in pids:
    stdout += "  PID  %d is foo\n" % pid
  stdout += "\n"
  stdout += "PTT Facility Per-Thread Information\n"
  stdout += "-----------------------------------\n"
  stdout += "\n"

  stdout += " PID TID Disp Intr"
  for metric in results:
    stdout += " %s" % metric
  stdout += "\n"

  stdout += " --- --- ---- ----"
  for metric in results:
    stdout += " %s" % ("-" * len(metric))
  stdout += "\n"

  for pid in pids:
    tid = random.randint(100, 1000)
    disp = random.randint(1, 10000)
    intr = random.randint(1, 10000)

    metric_values =  ""
    for metric in results:
      metric_values += " %d" % results[metric][pid]

    stdout += " %d %d %d %d%s\n" % (pid, tid, disp, intr, metric_values)

    stdout += "                   "
    stdout += "-".join("%s" % ("-" * len(metric)) for metric in results)
    stdout += "\n"
    stdout += "                   "
    stdout += metric_values
    stdout += "\n\n"

  stdout += "Execution ended: 1 iterations.\n"
  return stdout


class TestHardwarePerformanceCounter(unittest.TestCase):
  """Unittests for ibmperf.HardwarePerformanceCounter."""

  def setUp(self):
    # By default we create a mock HardwarePerformanceCounter object that
    # successfully initializes the toolkit.
    self._hpc = MockHardwarePerformanceCounter(
        _SUCCESSFUL_INIT)

  def _TestStart(self, metrics):
    """Utility function for starting data collection.

    Args:
      metrics: Iterable collection of metrics to be started.
    """
    self._hpc.AddPopenResult(_GENERIC_SUCCESS)  # ptt term
    self._hpc.AddPopenResult(_GENERIC_SUCCESS)  # ptt noautoterm
    self._hpc.AddPopenResult(_GENERIC_SUCCESS)  # ptt init
    self._hpc.Start(metrics)

  def _TestStop(self):
    """Utility function for stopping data collection."""
    self._hpc.AddPopenResult(_GENERIC_SUCCESS)  # ptt term
    self._hpc.Stop()

  # Pylint complains that this need not be a member function, but the
  # unittest machinery requires this.
  # pylint: disable=R0201
  def testInstallsIfNotInstalled(self):
    MockHardwarePerformanceCounter(
        [(MockPopen, [], {"returncode": -1}),  # ddq failure.
         (MockPopen, [], {"returncode": 0}),  # tinstall success.
         _PTT_SUCCESS, _MPEVT_SUCCESS])

  def testFailedInstall(self):
    self.assertRaises(ibmperf.ExecutionFailed,
        MockHardwarePerformanceCounter,
        [(MockPopen, [], {"returncode": -1}),  # ddq failure.
         (MockPopen, [], {"returncode": -1})])  # tinstall failure.

  def testHaveMetrics(self):
    self.assertEqual(set(_METRICS.keys()), set(self._hpc.metrics.keys()))

  def testQueryFailsWhenNotRunning(self):
    self.assertRaises(ibmperf.NotRunning, self._hpc.Query, "foo")

  def testStopFailsWhenNotRunning(self):
    self.assertRaises(ibmperf.NotRunning, self._hpc.Stop)

  def testStartFailsOnInvalidMetric(self):
    self.assertRaises(ibmperf.InvalidMetric,
                      self._TestStart,
                      ["INVALID_METRIC_NAME"])

  def testAllMetricsCanBeStartedIndividually(self):
    for name in self._hpc.metrics:
      self._TestStart([name])
      self._TestStop()

  def testDumpFails(self):
    self._TestStart([_CYCLES])

    # ptt returns 210 when it fails.
    self._hpc.AddPopenResult((MockPopen, [], {"returncode": 210}))
    self.assertRaises(ibmperf.ExecutionFailed,
                      MockHardwarePerformanceCounter.Query,
                      self._hpc,
                      "foo")

  def testUnexpectedDumpOutput(self):
    self._TestStart([_CYCLES])

    stdout = "This is garbage, and is not parsable."
    self._hpc.AddPopenResult((MockPopen, [], {"stdout": stdout}))
    self.assertRaises(ibmperf.UnexpectedOutput,
                      MockHardwarePerformanceCounter.Query,
                      self._hpc,
                      "foo")

  def testWrongMetricsDumped(self):
    self._TestStart([_CYCLES])

    results = _CreateQueryResults([_UOPS])
    stdout = _CreateQueryStdout(results)
    self._hpc.AddPopenResult((MockPopen, [], {"stdout": stdout}))
    self.assertRaises(ibmperf.UnexpectedOutput,
                      MockHardwarePerformanceCounter.Query,
                      self._hpc,
                      "foo")

  def _TestMetricsFully(self, metrics):
    """Collects the provided metrics for an imaginary process 'foo'.

    This helper function starts the metrics, sleeps for 2 seconds, queries them
    and finally stops them. It ensures that the reported metrics match those
    that were requested to be collected.

    Args:
      metrics: Iterable collection of metrics to be started.
    """
    self._TestStart(metrics)

    expected_results = _CreateQueryResults(metrics)
    query_stdout = _CreateQueryStdout(expected_results)

    self._hpc.AddPopenResult((MockPopen, [], {"stdout": query_stdout}))
    results = self._hpc.Query("foo")
    self.assertTrue(isinstance(results, dict))
    self.assertEqual(expected_results, results)

    self._TestStop()

  def testOneMetricFully(self):
    name = self._hpc.metrics.keys()[0]
    self._TestMetricsFully([name])

  def _GetMaximalMetrics(self):
    """Helper function that returns a set of maximal metrics.

    This returns all free metrics, plus max_counters non-free metrics.
    """
    metrics = list(self._hpc.free_metrics)
    metrics += list(self._hpc.non_free_metrics)[0:self._hpc.max_counters]
    return metrics

  def testMaximalMetricsFully(self):
    metrics = self._GetMaximalMetrics()
    self._TestMetricsFully(metrics)

  def testMaximalMetricsFullyForReal(self):
    # Only run this test if the toolkit is actually present at the
    # default path.
    if (not os.path.isdir(ibmperf.DEFAULT_DIR) or
        not os.path.exists(os.path.join(ibmperf.DEFAULT_DIR, 'ddq.exe'))):
      return

    self._hpc = ibmperf.HardwarePerformanceCounter()
    metrics = self._GetMaximalMetrics()

    self._hpc.Start(metrics)
    try:
      results = self._hpc.Query("python")
      self.assertTrue(isinstance(results, dict))
      self.assertEqual(set(metrics), set(results))
    except ibmperf.ExecutionFailed:
      # We swallow this error, as it can happen if the local machine doesn't
      # actually support per-thread metrics. Some versions of Windows don't.
      pass

    self._hpc.Stop()


if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  unittest.main()
