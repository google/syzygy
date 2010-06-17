#!python
# Copyright 2009 Google Inc.
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
"""An Event Tracing for Windows event provider."""
from ctypes import addressof, byref, cast, pointer, sizeof
from ctypes import POINTER, Structure
import evntrace
import winerror

class MofEvent(object):
  """A utility class to wrap trace event structures"""
  def __init__(self, num_fields, event_class, type, level):
    """Create and initialize an event with a given number of MOF fields.

    Args:
      num_fields: the number of MOF fields to allocate. Each MOF field
        can be set with a buffer and length, which will cause the buffer
        contents to be logged with the event.
      event_class: the event class GUID.
      type: the integer event type.
      level: the trace level of this event.
    """
    class MofEventType(Structure):
      _fields_ = [('header', evntrace.EVENT_TRACE_HEADER),
                  ('fields', evntrace.MOF_FIELD * num_fields)]

    event = MofEventType()
    event.header.Size = sizeof(event)
    event.header.Guid = event_class
    event.header.Class.Type = type
    event.header.Class.Level = level
    event.header.Flags = (evntrace.WNODE_FLAG_TRACED_GUID |
                          evntrace.WNODE_FLAG_USE_MOF_PTR)
    self._event = event

  def _getEvent(self):
    return self._event

  event = property(_getEvent,
                   doc='Retrieve the event structure.')

  def SetField(self, index, data_len, data):
    """Set a MOF field with a length and a buffer.

    Args:
      index: index of the field to set.
      data_len: length of the buffer backing "data".
      data: a ctypes pointer to a buffer of length "data_len" or better.

    Note:
      The buffer "data" points to must remain valid for the lifetime of
      the event. If the event is logged after the e.g. the string or object
      backing "data" goes out of scope, the event will log garbage, or
      possibly cause a crash on logging.
    """
    self._event.fields[index].DataPtr = addressof(data.contents)
    self._event.fields[index].Length = data_len


class TraceProvider(object):
  """A trace provider for Event Tracing for Windows.

  To use select a provider GUID, then instantiate a TraceProvider with the GUID.
  The TraceProvider takes care of registering with ETW, handling ETW callbacks
  to update the tracing level and enable mask.

  To issue an event, first check the enable_level and the enable_mask.
  If an event should be issued, create a MofEvent, set its fields to point
  to the event data, and pass it to Log().
  """
  def __init__(self, control_guid, trace_guids = None):
    """Create a TraceProvider with a given control_guid name.

    Args:
      control_guid: the GUID that names this provider.
      trace_guids: optionally a list of GUIDs that name the event classes
        this provider will log.
    """
    self._guid = control_guid
    if trace_guids == None:
      trace_guids = [evntrace.GUID()]

    # Copy the trace guids, and allocate an array of guid
    # registrations to point to them.
    self._trace_guids = trace_guids[:]
    self._guid_registrations = (evntrace.TRACE_GUID_REGISTRATION *
                                len(trace_guids))()
    for i in range(len(trace_guids)):
      self._guid_registrations[i].Guid = pointer(self._trace_guids[i])

    self._registration_handle = evntrace.TRACEHANDLE()
    self._callback = evntrace.WMIDPREQUEST(self._ControlCallback)
    self._session_handle = None
    self._enable_level = 0
    self._enable_flags = 0;

    # If the provider is enabled, the control callback will fire from
    # within the call to RegisterTraceGuids, so don't touch anything
    # that the callback uses past this point.
    evntrace.RegisterTraceGuids(self._callback,
                                None,
                                self._guid,
                                len(self._trace_guids),
                                cast(self._guid_registrations, POINTER(
                                    evntrace.TRACE_GUID_REGISTRATION)),
                                None,
                                None,
                                byref(self._registration_handle))

  def ShouldLog(self, level, enable_flag):
    """Test whether an event should be logged at this time.

    Args:
      level: the trace level at which the event would be logged.
      enable_flags: a mask of enable bits that should trigger the event.

    Returns:
      true iff the current logging level is greater or equal to level, and
      any of the bits in enable_flags are currently enabled.
    """
    return (self.enable_level >= level and
            (self.enable_flags & enable_flag) != 0)

  def Log(self, mof_event):
    """Outputs mof_event to any listening trace session(s).

    Args:
      mof_event: a MofEvent instance initialized with the data to log.
    """
    return evntrace.TraceEvent(self._session_handle,
                               byref(mof_event.event.header))

  def _GetEnableLevel(self):
    return self._enable_level

  def _GetEnableFlags(self):
    return self._enable_flags

  enable_level = property(_GetEnableLevel,
                          doc='Retrieves the current enable level')

  enable_flags = property(_GetEnableFlags,
                          doc='Retrieves the current enable flags')

  def OnEventsEnabled(self):
    """An event hook for overriding in subclasses.

    Called when events have been enabled, or when the log level or enable mask
    has changed. The new enable_level and enable_mask are available from
    the properties in this call.
    """
    pass

  def OnEventsDisabled(self):
    """An event hook for overriding in subclasses.

    Called just before events are disabled, the old enable_level and
    enable_mask are still in effect.
    """
    pass

  def __del__(self):
    """Cleanup our registration if one is still in effect."""
    if self._registration_handle.value != 0:
      evntrace.UnregisterTraceGuids(self._registration_handle)

  def _ControlCallback(self, request, context, reserved, buffer):
    if request == evntrace.WMI_ENABLE_EVENTS:
      return self._EnableEvents(buffer)
    elif request == evntrace.WMI_DISABLE_EVENTS:
      return self._DisableEvents()

    return winerror.ERROR_INVALID_PARAMETER

  def _EnableEvents(self, buffer):
    # We're in a control callback and events were just enabled
    # or changed, retrieve our session properties.
    self._session_handle = evntrace.GetTraceLoggerHandle(buffer)
    self._enable_level = evntrace.GetTraceEnableLevel(self._session_handle)
    self._enable_flags = evntrace.GetTraceEnableFlags(self._session_handle)
    self.OnEventsEnabled()
    return winerror.ERROR_SUCCESS

  def _DisableEvents(self):
    # We're in a control callback and events were just disabled.
    # Clear our session properties.
    self._enable_level = 0
    self._enable_flags = 0
    self._session_handle = None
    return winerror.ERROR_SUCCESS
