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
"""Unittests for the ibmperf module. Requires IBM Performance Inspector tools
to have been installed at "C:\\ibmperf\\bin"."""

__author__ = "chrisha@chromium.org (Chris Hamilton)"

import ibmperf
import time
import unittest


_CYCLES = 'CYCLES'


class TestHardwarePerformanceCounter(unittest.TestCase):
  """Unittests for ibmperf.HardwarePerformanceCounter."""

  def setUp(self):
    self._hpc = ibmperf.HardwarePerformanceCounter()

  def tearDown(self):
    pass

  def testHaveMetrics(self):
    self.assertTrue(self._hpc.metrics.has_key(_CYCLES))
    self.assertTrue(len(self._hpc.metrics) > 1)

  def testQueryFailsWhenNotRunning(self):
    self.assertRaises(ibmperf.Error, self._hpc.Query, 'foo')

  def testStopFailsWhenNotRunning(self):
    self.assertRaises(ibmperf.Error, self._hpc.Stop)

  def testStartStop(self):
    self._hpc.Start([_CYCLES])
    time.sleep(1)
    self._hpc.Stop()

  def testAllMetricsCanBeStartedIndividually(self):
    for (name, description) in self._hpc.metrics.items():
      self._hpc.Start([name])
      time.sleep(0.5)
      self._hpc.Stop()

  def _testMetricsFully(self, metrics):
    """Helper function for starting, querying and stopping a given set
    of metrics. Inspects the process running the unittests."""
    self._hpc.Start(metrics)
    time.sleep(2)

    results = self._hpc.Query('python')
    self.assertIsInstance(results, dict)
    self.assertEqual(set(metrics), set(results.keys()))
    for metric in metrics:
        self.assertIsInstance(results[metric], dict)
        self.assertTrue(len(results[metric]) > 0)

    self._hpc.Stop()

  def testCyclesAndTwoMetricsFully(self):
    # We can only run this test if there are at least 3 available metrics,
    # and CYCLES is one of them. This should be true for all hardware.
    metrics = set(self._hpc.metrics.keys())
    if len(metrics) < 3 or _CYCLES not in metrics:
      return
    metrics = metrics - set([_CYCLES])
    metrics = list(metrics)[0:2]
    metrics.append(_CYCLES)

    self._testMetricsFully(metrics)

  def testOneMetricFully(self):
    name = self._hpc.metrics.keys()[0]
    self._testMetricsFully([name])


if __name__ == '__main__':
  unittest.main()
