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
"""EventClass and EventCategory base classes for Event descriptors."""
from binary_buffer import BinaryBufferReader
import inspect


class EventClass(object):
  """Base class for event classes.

  The EventClass class is used to transform an event data buffer into a set of
  named attributes on the object. Classes that want to parser event data should
  derive from this class and define the _fields_ property:

  class MyEventClass(EventClass):
    _fields_ = [('IntField', field.Int32'),
                ('StringField', field.String')]

  The constructor reads the _fields_ property and iterates through the tuples.
  It reads the values from the supplied buffer based on the field type and
  assigns the values to named attributes of itself. The subclass must also
  define the _event_types_ list so that it will be registered in the
  EventCategory event class map.
  """
  _subclass_map = {}

  def __init__(self, buffer, length, is_64_bit_log):
    """Initialize the class by reading its buffer to populate its fields."""
    reader = BinaryBufferReader(buffer, length)
    for (name, field) in self._fields_:
      setattr(self, name, field(reader, is_64_bit_log))

  @staticmethod
  def Get(guid, version, type):
    """Returns the EventClass subclass for the given guid, version and type."""
    key = (guid, version, type)
    return EventClass._subclass_map.get(key, None)


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
  def __new__(meta_class, name, bases, dict):
    """Create a new EventCategory class."""
    for v in dict.values():
      if inspect.isclass(v) and issubclass(v, EventClass):
        for event_type in v._event_types_:
          key = (dict['GUID'], dict['VERSION'], event_type)
          EventClass._subclass_map[key] = v
    return type.__new__(meta_class, name, bases, dict)


class EventCategory(object):
  """Base class for event categories.

  The EventCategory class provides subclasses with a common metaclass to enable
  the popuplation of its event class map. Subclasses must define GUID and
  VERSION constants as they are used as keys to the map.
  """
  __metaclass__ = MetaEventCategory
