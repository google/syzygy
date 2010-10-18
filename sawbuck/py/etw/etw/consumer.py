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
from etw import evntrace
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


class TraceEventSource(object):
  """An Event Tracing for Windows consumer class.

  To consume a log, derive one or more handler classes from EventConsumer
  and define
  """

  def __init__(self, handlers=[]):
    """Creates an idle consumer.

    Args:
      handlers: an optional list of handlers to consume the log(s).
          Each handler should be an object derived from EventConsumer.
    """
    self._stop = False
    self._handlers = handlers[:]
    self._is_64_bit_log = False
    self._trace_handles = []
    self._buffer_callback = evntrace.EVENT_TRACE_BUFFER_CALLBACK(
        self._ProcessBufferCallback)
    self._event_callback = evntrace.EVENT_CALLBACK(
        self._ProcessEventCallback)
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
    event_class = event.EventClass.Get(guid, version, type)
    if event_class:
      handlers = self._GetHandlers(guid, type)
      if handlers:
        event_obj = event_class(event_trace, self._is_64_bit_log)
        for handler in handlers:
          handler(event_obj)

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
      # Terminate parsing on exception.
      logging.exception("Exception in ProcessBuffer, terminating parsing")
      self._stop = True

    if self._stop:
      return 0
    else:
      return 1

  def _ProcessEventCallback(self, event):
    # Don't process the event if we're stopping. Note that we can only
    # terminate the processing once a whole buffer has been processed.
    if self._stop:
      return

    try:
      self.ProcessEvent(event)
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
