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
from collections import defaultdict
from ctypes import byref, cast, POINTER, sizeof
from etw import evntcons
from etw import evntrace
from etw import util
from etw.descriptors import event
import logging


def _BindHandler(handler_func, handler_instance):
  def BoundHandler(event):
    handler_func(handler_instance, event)
  return BoundHandler


def EventHandler(*event_infos):
  """EventHandler decorator factory.

  This decorator factory assigns the event_infos value passed in as a property
  of the decorated function. This is used by the Consumer class to
  populate an event handler map with the decorated functions.
  """
  def wrapper(func):
    func.event_infos = event_infos[:]
    return func
  return wrapper


class MetaEventConsumer(type):
  """Meta class for TraceConsumer.

  The purpose of this metaclass is to populate an event handler map for a
  TraceConsumer subclass. It iterates through the class' dict searching
  for functions that have an event_info property and assigns them to a map.
  The map is then assigned to the subclass type. It also handles a hierarchy
  of consumers and will register event handlers defined in parent classes
  for the given sub class.
  """
  def __new__(cls, name, bases, dict):
    """Create a new TraceConsumer class type."""
    event_handler_map = defaultdict(list)
    for base in bases:
      base_map = getattr(base, 'event_handler_map', None)
      if base_map:
        event_handler_map.update(base_map)
    for v in dict.values():
      event_infos = getattr(v, 'event_infos', [])
      for event_info in event_infos:
        event_handler_map[event_info].append(v)
    new_type = type.__new__(cls, name, bases, dict)
    new_type.event_handler_map = event_handler_map
    return new_type


class EventConsumer(object):
  """An Event Tracing for Windows event handler base class.

  Derive your handlers from this class, and define event handlers like so:

  @EventHandler(module.Event.EventName)
  def OnEventName(self, event):
    pass

  to handle events. One or more event handler instances can then be passed to a
  LogConsumer, which will dispatch log events to them during log consumption.

  Note that if any handler raises an exception, the exception will be logged,
  and log parsing will be terminated as soon as possible.
  """
  __metaclass__ = MetaEventConsumer


class _TraceLogSession(object):
  """An internal implementation class that wraps an open event trace session.

  The purpose of this class is to maintain per-session state, such as
  the ETW time to wall-clock conversion state, the event handle, etc.
  """
  def __init__(self, event_source, raw_time):
    self._event_source = event_source
    self._raw_time = raw_time
    # Assume FILETIME conversion until we get other data.
    self._time_epoch_delta = util.FILETIME_EPOCH_DELTA_S
    self._time_multiplier = util.FILETIME_TO_SECONDS_MULTIPLIER

    self._buffer_callback = evntrace.EVENT_TRACE_BUFFER_CALLBACK(
        self._ProcessBufferCallback)
    self._event_callback = evntrace.EVENT_CALLBACK(
        self._ProcessEventCallback)
    self._handle = None
    self._start_time = None
    self._processed_first_event = False
    self.is_64_bit_log = False

  def SessionTimeToTime(self, session_time):
    """Convert a raw time value from this session to a python time value.

    Args:
      session_time: a time value read from a event header or event field
          in this session.

    Returns: a floating point time value in seconds, with zero at 1.1.1970.
    """
    return session_time * self._time_multiplier - self._time_epoch_delta

  def Close(self):
    """Close this session."""
    try:
      evntrace.CloseTrace(self._handle)
    except:
      logging.exception("Exception closing session.")

  def OpenRealtimeSession(self, name):
    """Open a real time trace session named "name".

    Args:
      name: name of the session to open.
    """
    logfile = evntrace.EVENT_TRACE_LOGFILE()
    logfile.LoggerName = name
    logfile.ProcessTraceMode = evntcons.PROCESS_TRACE_MODE_REAL_TIME
    if self._raw_time:
      logfile.ProcessTraceMode = evntcons.PROCESS_TRACE_MODE_RAW_TIMESTAMP
    logfile.BufferCallback = self._buffer_callback
    logfile.EventCallback = self._event_callback
    self._handle = evntrace.OpenTrace(byref(logfile))
    self._ProcessHeader(logfile.LogfileHeader)

  def OpenFileSession(self, path):
    """Open a file session for the file at "path".

    Args:
      path: relative or absolute path to the file to open.
    """
    logfile = evntrace.EVENT_TRACE_LOGFILE()
    logfile.LogFileName = path
    if self._raw_time:
      logfile.ProcessTraceMode = evntcons.PROCESS_TRACE_MODE_RAW_TIMESTAMP
    logfile.BufferCallback = self._buffer_callback
    logfile.EventCallback = self._event_callback
    self._handle = evntrace.OpenTrace(byref(logfile))
    self._ProcessHeader(logfile.LogfileHeader)

  def _ProcessHeader(self, logfile_header):
    if logfile_header.PointerSize == 8:
      self.is_64_bit_log = True

    if self._raw_time:
      mode = logfile_header.ReservedFlags
      self._start_time = util.FileTimeToTime(logfile_header.StartTime)
      ticks_sec = None
      if mode == 1:  # QPC timer resolution
        ticks_sec = logfile_header.PerfFreq
      elif mode == 2:  # System time
        ticks_sec = 1000  # TODO(siggi): verify this is milliseconds
      elif mode == 3:  # CPU cycle counter
        ticks_sec = logfile_header.CpuSpeedInMHz * 1000000.0

      self._time_multiplier = 1.0 / ticks_sec

  def _ProcessFirstEvent(self, event):
    if self._raw_time:
      self._time_epoch_delta = (
        event.contents.Header.TimeStamp * self._time_multiplier -
            self._start_time)

  def _ProcessBufferCallback(self, buffer):
    return self._event_source._ProcessBufferCallback(self, buffer)

  def _ProcessEventCallback(self, event_trace):
    try:
      # When in raw time mode, we need special processing
      # for the first event to calibrate the session start time.
      if not self._processed_first_event:
        self._ProcessFirstEvent(event_trace)
        self._processed_first_event = True

      self._event_source._ProcessEventCallback(self, event_trace)
    except:
      logging.exception('Exception in _ProcessEventCallback')

class TraceEventSource(object):
  """An Event Tracing for Windows consumer class.

  To consume one or more logs, derive one or more handler classes from
  EventConsumer and declare a set of event handlers per the documentation
  of that class. Then instantiate one or more consumers and pass them into the
  TraceEventSource constructor, or add them to the list of handlers with
  AddHandler.
  Then proceed to open one or more sessions with OpenRealtimeSession and/or
  OpenFileSession, and lastly call Consume to consume the open sessions.
  This will fire events at the EventConsumers as the log is consumed.

  Note that each TraceEventSource can at most consume a single real time
  session, and no more than 63 sessions overall.
  """

  def __init__(self, handlers=[], raw_time=False):
    """Creates an idle consumer.

    Args:
      handlers: an optional list of handlers to consume the log(s).
          Each handler should be an object derived from EventConsumer.
      raw_time: if True, consume logs with the raw time option. This allows
          converting stamps recorded in events to wall-clock time.
    """
    self._stop = False
    self._handlers = handlers[:]
    self._raw_time = raw_time
    self._trace_sessions = []
    self._handler_cache = dict()

  def __del__(self):
    """Clean up any trace sessions we have open."""
    self.Close()

  def AddHandler(self, handler):
    """Add a new handler to this consumer.

    Args:
      handler: the handler to add.
    """
    self._handlers.append(handler)
    # Clear our handler cache.
    self._handler_cache.clear()

  def OpenRealtimeSession(self, name):
    """Open a trace session named "name".

    Args:
      name: name of the session to open.
    """
    session = _TraceLogSession(self, self._raw_time)
    session.OpenRealtimeSession(name)
    self._trace_sessions.append(session)

  def OpenFileSession(self, path):
    """Open a file session for the file at "path".

    Args:
      path: relative or absolute path to the file to open.
    """
    session = _TraceLogSession(self, self._raw_time)
    session.OpenFileSession(path)
    self._trace_sessions.append(session)

  def Consume(self):
    """Consume all open sessions.

    Note: if any of the open sessions are realtime sessions, this function
      will not return until Close() is called to close the realtime session.
    """
    handles = (evntrace.TRACEHANDLE *
               len(self._trace_sessions))()

    for i in range(len(self._trace_sessions)):
      handles[i] = self._trace_sessions[i]._handle

    evntrace.ProcessTrace(cast(handles, POINTER(evntrace.TRACEHANDLE)),
                          len(handles),
                          None,
                          None)

  def Close(self):
    """Close all open trace sessions."""
    while len(self._trace_sessions):
      session = self._trace_sessions.pop()
      session.Close()

  def ProcessEvent(self, session, event_trace):
    """Process a single event.

    Retrieve the guid, version and type from the event and try to find a handler
    for the event and event class that can parse the event data. If both exist,
    dispatch the event object to the handler.

    Args:
      session: the _TraceLogSession on which this event occurred.
      event_trace: a POINTER(EVENT_TRACE) for the current event.
    """
    header = event_trace.contents.Header
    guid = str(header.Guid)
    version = header.Class.Version
    type = header.Class.Type

    # Look for a handler and EventClass for the event.
    event_class = event.EventClass.Get(guid, version, type)
    if event_class:
      handlers = self._GetHandlers(guid, type)
      if handlers:
        event_obj = event_class(session, event_trace)
        for handler in handlers:
          handler(event_obj)

  def ProcessBuffer(self, session, buffer):
    """Process a buffer.

    Args:
      session: the _TraceLogSession on which this event occurred.
      event: a POINTER(TRACE_EVENT) for the current event.
    """
    pass

  def _ProcessBufferCallback(self, session, buffer):
    try:
      self.ProcessBuffer(session, buffer)
    except:
      # Terminate parsing on exception.
      logging.exception("Exception in ProcessBuffer, terminating parsing")
      self._stop = True

    if self._stop:
      return 0
    else:
      return 1

  def _ProcessEventCallback(self, session, event):
    # Don't process the event if we're stopping. Note that we can only
    # terminate the processing once a whole buffer has been processed.
    if self._stop:
      return

    try:
      self.ProcessEvent(session, event)
    except:
      # Terminate parsing on exception.
      logging.exception("Exception in ProcessEvent, terminating parsing")
      self._stop = True

  def _GetHandlers(self, guid, type):
    key = (guid, type)
    handler_list = self._handler_cache.get(key, None)
    if handler_list != None:
      return handler_list

    # We didn't cache this already.
    handler_list = []
    for handler_instance in self._handlers:
      for handler_func in handler_instance.event_handler_map.get(key, []):
        handler_list.append(_BindHandler(handler_func, handler_instance))

    return handler_list
