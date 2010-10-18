#!python
# Copyright 2010 Google Inc.
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
from etw import MofEvent, TraceEventSource
from etw import TraceController, TraceProperties, TraceProvider
import ctypes
import etw.evntrace as evn
import exceptions
import os
import tempfile
import unittest


class TraceProviderTest(unittest.TestCase):
  _TEST_PROVIDER = evn.GUID('{67644E0D-1B90-4923-9678-91102029E876}')
  _TEST_SESSION_NAME = 'TraceProviderTest'

  _LOG_EVENT_ID = evn.GUID('{7fe69228-633e-4f06-80c1-527fea23e3a7}')
  _LOG_MESSAGE = 10
  _LOG_MESSAGE_WITH_STACKTRACE = 11

  def setUp(self):
    properties = TraceProperties()
    try:
      # Shut down any session dangling from a previous run.
      evn.ControlTrace(evn.TRACEHANDLE(),
                       self._TEST_SESSION_NAME,
                       properties.get(),
                       evn.EVENT_TRACE_CONTROL_STOP)
    except exceptions.WindowsError:
      pass

    (fd, name) = self._tempfile = tempfile.mkstemp('.etl', 'TraceProviderTest')
    os.close(fd)
    self._tempfile = name

    # Start a trace session
    controller = TraceController()
    prop = TraceProperties()
    prop.SetLogFileName(self._tempfile)
    controller.Start(self._TEST_SESSION_NAME, prop)
    self._controller = controller
    controller.EnableProvider(self._TEST_PROVIDER,
                              evn.TRACE_LEVEL_INFORMATION,
                              0xFFFFFFFF)

  def tearDown(self):
    if self._controller._session:
      self._controller.Stop()
    os.unlink(self._tempfile)

  def testCreateProvider(self):
    """Test provider creation."""
    provider = TraceProvider(self._TEST_PROVIDER)

  def testLog(self):
    """Log a text message to an enabled provider"""
    provider = TraceProvider(self._TEST_PROVIDER)
    mof_event = MofEvent(1, self._LOG_EVENT_ID,
                         self._LOG_MESSAGE,
                         evn.TRACE_LEVEL_INFORMATION)
    str = 'This is an event, goddamn it'
    string_ptr = ctypes.cast(ctypes.c_char_p(str),
                             ctypes.POINTER(ctypes.c_char))
    mof_event.SetField(0, len(str) + 1, string_ptr)
    provider.Log(mof_event)

    self._controller.Stop()

    class TestConsumer(TraceEventSource):
      def ProcessEvent(self, event):
        print event

    consumer = TestConsumer()
    consumer.OpenFileSession(self._tempfile)
    consumer.Consume()


if __name__ == '__main__':
  unittest.main()
