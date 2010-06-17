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
from etw import TraceController, TraceProperties, TraceProvider
import exceptions
import etw.evntrace as evn
import os
import tempfile
import unittest


class TracePropertiesTest(unittest.TestCase):
  def setUp(self):
    self._props = TraceProperties()

  def testInit(self):
    """Test property initialization."""
    p = self._props
    self.assertEquals("", p.GetLogFileName().value)
    self.assertEquals("", p.GetLoggerName().value)

  def testSetLogFileName(self):
    """Test SetLogFileName."""
    p = self._props
    p.SetLogFileName(r'c:\foo.etl')
    self.assertEquals(r'c:\foo.etl', p.GetLogFileName().value)


class ControllerTest(unittest.TestCase):
  _TEST_SESSION_NAME = 'Test Session'
  _TEST_PROVIDER = evn.GUID('{55EC8EBB-A25D-4e0a-958D-D6E9ECB4EC5A}')

  def setUp(self):
    self._is_xp = os.sys.getwindowsversion()[0] == 5
    self._controller = TraceController()
    (file, path) = tempfile.mkstemp('.etl')
    os.close(file)
    self._temp_file = path

  def tearDown(self):
    try:
      self._controller.Stop()
    except:
      pass
    os.unlink(self._temp_file)

  def StartPrivateSession(self):
    controller = self._controller
    props = TraceProperties()
    props.SetLogFileName(self._temp_file)
    p = props.get()
    p.contents.Wnode.ClientContext = 1  # QPC timer accuracy.
    p.contents.LogFileMode = evn.EVENT_TRACE_FILE_MODE_SEQUENTIAL

    # On Vista and later, we create a private in-process log session, because
    # otherwise we'd need administrator privileges. Unfortunately we can't
    # do the same on XP and better, because the semantics of a private
    # logger session are different, and the IN_PROC flag is not supported.
    if not self._is_xp:
      # In-proc, process private log for non-admin use on Vista.
      p.contents.LogFileMode |= (evn.EVENT_TRACE_PRIVATE_IN_PROC |
           evn.EVENT_TRACE_PRIVATE_LOGGER_MODE)

    p.contents.MaximumFileSize = 100  # 100M file size.
    p.contents.FlushTimer = 1  # 1 second flush lag.
    controller.Start(self._TEST_SESSION_NAME, props)

  def testStart(self):
    """Test starting sessions."""
    self.StartPrivateSession()

    # Should raise when trying to re-open session
    self.assertRaises(exceptions.WindowsError, self.StartPrivateSession)

  def testStop(self):
    """Test stopping sessions."""
    # Should raise with no session going.
    self.assertRaises(exceptions.WindowsError, self._controller.Stop)

    # This starts the 'Test Session'
    self.testStart()

    # Should succeed.
    self._controller.Stop()

  def testEnableDisablePrivateSession(self):
    """Test enabling and disabling providers."""
    self.StartPrivateSession()
    controller = self._controller
    # For a private session we can only enable and
    # disable providers registered in our process, so
    # instantiate the test provider here.
    provider = TraceProvider(self._TEST_PROVIDER)
    self.assertEquals(evn.TRACE_LEVEL_NONE, provider.enable_level)
    self.assertEquals(0, provider.enable_flags)

    controller.EnableProvider(self._TEST_PROVIDER,
                              evn.TRACE_LEVEL_INFORMATION,
                              0xCAFEBABE)

    self.assertEquals(evn.TRACE_LEVEL_INFORMATION, provider.enable_level)
    self.assertEquals(0xCAFEBABE, provider.enable_flags)

    controller.DisableProvider(self._TEST_PROVIDER)
    self.assertEquals(evn.TRACE_LEVEL_NONE, provider.enable_level)
    self.assertEquals(0, provider.enable_flags)


if __name__ == '__main__':
  unittest.main()
