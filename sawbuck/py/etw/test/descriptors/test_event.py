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
from etw.descriptors import field
from etw.descriptors.binary_buffer import BufferOverflowError
from etw.descriptors.event import EventCategory, EventClass
import ctypes
import unittest


class EventClassTest(unittest.TestCase):
  def testCreation(self):
    """Test creating a subclass of EventClass."""
    class TestEventClass(EventClass):
      _fields_ = [('TestString', field.String),
                  ('TestInt32', field.Int32),
                  ('TestInt64', field.Int64)]

    data = ctypes.c_buffer(18)
    data.value = 'Hello'

    ptr = ctypes.cast(data, ctypes.c_void_p)

    int = ctypes.cast(ptr.value + 6, ctypes.POINTER(ctypes.c_int))
    int.contents.value = 1234

    long = ctypes.cast(ptr.value + 10, ctypes.POINTER(ctypes.c_longlong))
    long.contents.value = 4321

    obj = TestEventClass(ptr.value, ctypes.sizeof(data), False)
    self.assertEqual(obj.TestString, 'Hello')
    self.assertEqual(obj.TestInt32, 1234)
    self.assertEqual(obj.TestInt64, 4321)

  def testBadBuffer(self):
    """Test using an invalid buffer."""
    class TestEventClass(EventClass):
      _fields_ = [('FieldA', field.Int32),
                  ('FieldB', field.Int32)]

    data = ctypes.c_buffer(4)
    ptr = ctypes.cast(data, ctypes.c_void_p)
    int = ctypes.cast(ptr.value, ctypes.POINTER(ctypes.c_int))
    int.contents.value = 1234

    self.assertRaises(BufferOverflowError, TestEventClass, ptr.value,
                     ctypes.sizeof(data), False)


class EventCategoryTest(unittest.TestCase):
  def testCreation(self):
    """Test creation of a subclass of EventCategory."""
    class TestEventCategory(EventCategory):
      GUID = 'a'
      VERSION = 1

      class TestEventClass1(EventClass):
        _event_types_ = [1, 3, 5]

      class TestEventClass2(EventClass):
        _event_types_ = [2, 4, 6]

    # Passing cases.
    self.assertNotEqual(EventClass.Get('a', 1, 1), None)
    self.assertNotEqual(EventClass.Get('a', 1, 2), None)
    self.assertNotEqual(EventClass.Get('a', 1, 3), None)
    self.assertNotEqual(EventClass.Get('a', 1, 4), None)
    self.assertNotEqual(EventClass.Get('a', 1, 5), None)
    self.assertNotEqual(EventClass.Get('a', 1, 6), None)

    # Failing cases.
    self.assertEqual(EventClass.Get('b', 1, 1), None)
    self.assertEqual(EventClass.Get('a', 2, 1), None)
    self.assertEqual(EventClass.Get('a', 1, 7), None)


if __name__ == '__main__':
  unittest.main()
