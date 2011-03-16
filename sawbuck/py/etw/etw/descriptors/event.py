#!/usr/bin/python2.6
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
"""EventClass and EventCategory base classes for Event descriptors."""
import inspect
from etw.descriptors import binary_buffer


class EventClass(object):
  """Base class for event classes.

  The EventClass class is used to transform an event data buffer into a set of
  named attributes on the object. Classes that want to parse event data should
  derive from this class and define the _fields_ property:

  class MyEventClass(EventClass):
    _fields_ = [('IntField', field.Int32),
                ('StringField', field.String)]

  The constructor iterates over the _fields_ property and invokes the function
  defined in the second half of the tuple. The return value is assigned as a
  named attribute of this class, the name being the first half of the tuple. The
  function in the second half of the tuple should take a TraceLogSession and a
  BinaryBufferReader as parameters and should return a mixed value.

  Subclasses must also define the _event_types_ list. This will cause the
  subclass to be registered in the the EventClass's subclass map for each event
  listed in _event_types_. This is used by the log consumer to identify the
  proper event class to create when handling a particular log event.

  Attributes:
    process_id: The ID of the process that generated the event.
    thread_id: The ID of the thread that generated the event.
    raw_time_stamp: The raw time stamp of the ETW event.
    time_stamp: The timestamp of the event (in seconds since 01-01-1970).
  """
  # A map of all classes that derive from this class. The keys are
  # (string guid, number version, number event_type) tuples and the values are
  # the derived classes.
  _subclass_map = {}

  def __init__(self, log_session, event_trace):
    """Initialize by extracting event trace header and MOF data.

    Args:
      event_trace: a POINTER(EVENT_TRACE) for the current event.
      is_64_bit_log: whether the log is from a 64 bit system.
    """
    header = event_trace.contents.Header
    self.process_id = header.ProcessId
    self.thread_id = header.ThreadId

    self.raw_time_stamp = header.TimeStamp
    self.time_stamp = log_session.SessionTimeToTime(header.TimeStamp)
    reader = binary_buffer.BinaryBufferReader(event_trace.contents.MofData,
                                              event_trace.contents.MofLength)
    for name, field in self._fields_:
      setattr(self, name, field(log_session, reader))

  @staticmethod
  def Get(guid, version, event_type):
    """Returns the subclass for the given guid, version and event_type.

    Args:
      guid: The event category guid as a string.
      version: The version of the event as a number.
      event_type: The type of the event as a number.

    Returns:
      The type of the EventClass subclass that matches the
      guid/version/event_type tuple.
    """
    key = guid, version, event_type
    return EventClass._subclass_map.get(key, None)

  @staticmethod
  def Set(guid, version, event_type, subclass):
    """Sets the subclass for the given guid, version and event_type.

    Args:
      guid: The event category guid as a string.
      version: The version of the event as a number.
      event_type: The type of the event as a number.
      subclass: The EventClass subclass to add to the map.
    """
    key = guid, version, event_type
    EventClass._subclass_map[key] = subclass

  @classmethod
  def GetEventTypes(cls):
    return cls._event_types_

class MetaEventCategory(type):
  """Meta class for EventCategory.

  The purpose of this metaclass is to populate a map of EventClass classes
  that are defined as subclasses of EventCategory classes. When an EventCategory
  class is defined, the __new__ method is called, and the nested EventClass
  classes are saved into map using a tuple of the EventCategory's GUID and
  version along with the nested class' event types as a key. The populated map
  is accessed statically through the EventClass.Get method to retrieve a defined
  EventClass.
  """

  def __new__(cls, name, bases, attrs):
    """Create a new EventCategory class.

    Args:
      name: The name of the class to create.
      bases: The base classes of the class to create.
      attrs: The attributes of the class to create.

    Returns:
      A new class with the specified name, base classes and attributes.
    """
    for value in attrs.values():
      if inspect.isclass(value) and issubclass(value, EventClass):
        for event_type in value.GetEventTypes():
          EventClass.Set(attrs['GUID'], attrs['VERSION'], event_type[1], value)
    return type.__new__(cls, name, bases, attrs)


class EventCategory(object):
  """Base class for event categories.

  The EventCategory class provides subclasses with a common metaclass to enable
  the popuplation of its event class map. Subclasses must define GUID and
  VERSION constants as they are used as keys to the map.
  """
  __metaclass__ = MetaEventCategory
