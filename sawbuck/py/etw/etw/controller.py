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
"""A Windows Event Trace controller class."""

from ctypes import addressof, byref, cast, memmove, sizeof
from ctypes import c_char, c_wchar, c_wchar_p
from ctypes import ArgumentError, pointer, POINTER
import evntrace

class TraceProperties(object):
  """A utility class to wrap usage of the EVENT_TRACE_PROPERTIES structure."""
  max_string_len = 1024;
  buf_size = (sizeof(evntrace.EVENT_TRACE_PROPERTIES) +
              2 * sizeof(c_wchar) * (max_string_len))

  def __init__(self):
    self._buf = (c_char * self.buf_size)()
    self._props = cast(pointer(self._buf),
                       POINTER(evntrace.EVENT_TRACE_PROPERTIES))
    prop = self.get()
    prop.contents.Wnode.BufferSize = self.buf_size
    prop.contents.Wnode.Flags = evntrace.WNODE_FLAG_TRACED_GUID
    prop.contents.LoggerNameOffset = sizeof(evntrace.EVENT_TRACE_PROPERTIES)
    prop.contents.LogFileNameOffset = (sizeof(evntrace.EVENT_TRACE_PROPERTIES) +
                                       sizeof(c_wchar) * self.max_string_len)

  def get(self):
    return self._props

  def GetLoggerName(self):
    """Retrieves the current logger name from the buffer."""
    props = self._props
    return c_wchar_p(addressof(props.contents) +
                     props.contents.LoggerNameOffset)

  def GetLogFileName(self):
    """Retrieves the current log file name from the buffer."""
    props = self._props
    return c_wchar_p(addressof(props.contents) +
                     props.contents.LogFileNameOffset)

  def SetLogFileName(self, logger_name):
    """Set the current log file name stored in the buffer."""
    name_len = len(logger_name) + 1
    if self.max_string_len < name_len :
      raise ArgumentError("Name too long")

    memmove(self.GetLogFileName(),
            c_wchar_p(logger_name),
            sizeof(c_wchar) * name_len)


class TraceController(object):
  """Creates and manages a trace session, enables and disables providers."""
  def __init__(self):
    """Create an idle controller."""
    self._session = evntrace.TRACEHANDLE()
    self._session_name = ""

  def __del__(self):
    self._Cleanup()

  def _GetSession(self):
    return self._session

  def _GetSessionName(self):
    return self._session

  session = property(_GetSession,
                     doc='The current session, if one in progress')
  session_name = property(_GetSessionName,
                          doc='The current session name, if one in progress')

  def Start(self, name, properties):
    """Start a new trace session.

    Args:
      name: the name of the trace session.
      properties: a TraceProperties instance with session properties.
    """
    session = evntrace.TRACEHANDLE()
    evntrace.StartTrace(byref(session), name, properties.get())

    self._Cleanup()
    self._session_name = name
    self._session = session

  def Stop(self, properties = None):
    """Stop the current trace session.

    Args:
      properties: if provided, on success contains the stopped sessions
        properties. Use this to e.g. see whether any buffers were lost.
    """
    if properties == None:
      properties = TraceProperties()

    session = self.session
    self._session = evntrace.TRACEHANDLE()
    evntrace.ControlTrace(session,
                          None,
                          properties.get(),
                          evntrace.EVENT_TRACE_CONTROL_STOP)

  def EnableProvider(self, provider, level, flags = None):
    """Enable provider at level with flags.

    Args:
      provider: a GUID naming a provider.
      level: a trace level, e.g. etw.envtrace.TRACE_LEVEL_INFORMATION.
      flags: a set of enable flags to set for the provider.
    """
    if flags == None:
      flags = 0
    evntrace.EnableTrace(True, flags, level, byref(provider), self.session)

  def DisableProvider(self, provider):
    """Disable provider.

    Args:
      provider: a GUID naming a provider.
    """
    evntrace.EnableTrace(False,
                         0,
                         evntrace.TRACE_LEVEL_NONE,
                         byref(provider),
                         self.session)

  def _Cleanup(self):
    if self.session:
      self.Stop()
