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
from ctypes import addressof, byref, cast, c_void_p, POINTER, sizeof
from etw import evntrace
from etw.descriptors import event


def EventHandler(event_info):
  """EventHandler decorator factory.

  This decorator factory assigns the event_info value passed in as a property
  of the decorated function. This is used by the Consumer class to
  populate an event handler map with the decorated functions.
  """
  def wrapper(func):
    func.event_info = event_info
    return func
  return wrapper


class MetaTraceConsumer(type):
  """Meta class for TraceConsumer.

  The purpose of this metaclass is to populate an event handler map for a
  TraceConsumer subclass. It iterates through the class' dict searching
  for functions that have an event_info property and assigns them to a map.
  The map is then assigned to the subclass type. It also handles a hierarchy
  of consumers and will register event handlers defined in parent classes
  for the given sub class.
  """
  def __new__(meta_class, name, bases, dict):
    """Create a new TraceConsumer class type."""
    event_handler_map = {}
    for base in bases:
      base_map = getattr(base, 'event_handler_map', None)
      if base_map:
        event_handler_map.update(base_map)
    for v in dict.values():
      event_info = getattr(v, 'event_info', None)
      if event_info:
        event_handler_map[event_info] = v
    new_type = type.__new__(meta_class, name, bases, dict)
    new_type.event_handler_map = event_handler_map
    return new_type


class TraceConsumer(object):
  """An Event Tracing for Windows consumer base class.

  Inherit from this class, and define event handlers like so:

  @EventHandler(module.Event.EventName)
  def handler(self, event):
    pass

  to handle events. Optionally override ProcessBuffer as well.

  To use, instantiate your subclass, then call OpenRealtimeSession and/or
  OpenFileSession to open the trace sessions you want to consume, before
  calling Consume. Note that ETW only allows each consumer to consume zero
  or one realtime sessions, but you can otherwise consumer open up to 31
  sessions concurrently.

  When you're done with the sessions, call Close() to close them all.
  """
  __metaclass__ = MetaTraceConsumer

  def __init__(self):
    """Creates an idle consumer."""
    self._is_64_bit_log = False
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

  def ProcessEvent(self, event_trace):
    """Process a single event.

    Retrieve the guid, version and type from the event and try to find a handler
    for the event and event class that can parse the event data. If both exist,
    dispatch the event object to the handler.

    Args:
      event_trace: a POINTER(EVENT_TRACE) for the current event.
    """
    header = event_trace.contents.Header
    guid = str(header.Guid)
    version = header.Class.Version
    type = header.Class.Type

    # Check for the event trace event GUID so that we can tease out whether
    # we're parsing a 64 bit log.
    if (guid == str(evntrace.EventTraceGuid) and type == 0 and
        event_trace.contents.MofLength >=
            sizeof(evntrace.TRACE_LOGFILE_HEADER)):
      trace_logfile_header = cast(
          event_trace.contents.MofData,
          POINTER(evntrace.TRACE_LOGFILE_HEADER))
      if trace_logfile_header.contents.PointerSize == 8:
        self._is_64_bit_log = True

    # Look for a handler and EventClass for the event.
    handler = self.event_handler_map.get((guid, type), None)
    event_class = event.EventClass.Get(guid, version, type)
    if handler and event_class:
      try:
        event_obj = event_class(event_trace, self._is_64_bit_log)
        handler(self, event_obj)
      except RuntimeError, e:
        logging.error(e)

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
