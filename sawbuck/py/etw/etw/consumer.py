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
"""Implements a trace consumer utility class."""
from ctypes import addressof, byref, cast, c_void_p, POINTER
import evntrace

class TraceConsumer(object):
  """An Event Tracing for Windows consumer base class.

  Inherit from this class, override ProcessEvent and optionally ProcessBuffer
  to implement specific event parsing.

  To use, instantiate your subclass, then call OpenRealtimeSession and/or
  OpenFileSession to open the trace sessions you want to consume, before
  calling Consume. Note that ETW only allows each consumer to consume zero
  or one realtime sessions, but you can otherwise consumer open up to 31
  sessions concurrently.
  When you're done with the sessions, call Close() to close them all.
  """
  def __init__(self):
    """Creates an idle consumer."""
    self._trace_handles = []
    self._buffer_callback = evntrace.EVENT_TRACE_BUFFER_CALLBACK(
        self._ProcessBufferCallback)
    self._event_callback = evntrace.EVENT_CALLBACK(
        self._ProcessEventCallback)

  def __del__(self):
    """Clean up any trace sessions we have open."""
    self.Close()

  def OpenRealtimeSession(self, name):
    """Open a trace session named "name".

    Args:
      name: name of the session to open.
    """
    logfile = evntrace.EVENT_TRACE_LOGFILE()
    logfile.LoggerName = name
    logfile.BufferCallback = self._buffer_callback
    logfile.EventCallback = self._event_callback
    trace = evntrace.OpenTrace(byref(logfile))
    self._trace_handles.append(trace)

  def OpenFileSession(self, path):
    """Open a file session for the file at "path".

    Args:
      path: relative or absolute path to the file to open.
    """
    logfile = evntrace.EVENT_TRACE_LOGFILE()
    logfile.LogFileName = path
    logfile.BufferCallback = self._buffer_callback
    logfile.EventCallback = self._event_callback

    trace = evntrace.OpenTrace(byref(logfile))
    self._trace_handles.append(trace)

  def Consume(self):
    """Consume all open sessions.

    Note: if any of the open sessions are realtime sessions, this function
      will not return until Close() is called to close the realtime session.
    """
    handles = (evntrace.TRACEHANDLE *
               len(self._trace_handles))()

    for i in range(len(self._trace_handles)):
      handles[i] = self._trace_handles[i]

    evntrace.ProcessTrace(cast(handles, POINTER(evntrace.TRACEHANDLE)),
                          len(self._trace_handles),
                          None,
                          None)

  def Close(self):
    """Close all open trace sessions."""
    while len(self._trace_handles):
      handle = self._trace_handles.pop()
      evntrace.CloseTrace(handle)

  def ProcessEvent(self, event):
    """Process a single event.

    Override this method in your base class to parse events.

    Args:
      event: a POINTER(TRACE_EVENT) for the current event.
    """
    pass

  def ProcessBuffer(self, buffer):
    """Process a buffer.

    Args:
      event: a POINTER(TRACE_EVENT) for the current event.
    """
    pass

  def _ProcessBufferCallback(self, buffer):
    try:
      self.ProcessBuffer(buffer)
    except:
      # terminate parsing on exception
      return 0

    # keep going
    return 1

  def _ProcessEventCallback(self, event):
    self.ProcessEvent(event)
