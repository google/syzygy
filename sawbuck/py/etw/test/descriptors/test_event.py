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
"""Unit test for the etw.descriptors.event module."""
import ctypes
import datetime
import time
import unittest
from etw import evntrace
from etw import util
from etw.descriptors import binary_buffer
from etw.descriptors import event
from etw.descriptors import field


class MockEventTrace(object):
  """This class mocks the EVENT_TRACE structure."""

  class MockContents(object):
    pass

  class MockHeader(object):
    def __init__(self, header_dict):
      for k, v in header_dict.items():
        setattr(self, k, v)

  def __init__(self, header_dict, mof_data, mof_length):
    self.contents = MockEventTrace.MockContents()
    self.contents.Header = MockEventTrace.MockHeader(header_dict)
    self.contents.MofData = mof_data
    self.contents.MofLength = mof_length


class MockSession(object):
  """This class mocks a _TraceLogSession object."""
  def __init__(self):
    self.is_64_bit_log = False

  def SessionTimeToTime(self, session_time):
    return util.FileTimeToTime(session_time)


class EventClassTest(unittest.TestCase):
  def testCreation(self):
    """Test creating a subclass of EventClass."""
    class TestEventClass(event.EventClass):
      _fields_ = [('TestString', field.String),
                  ('TestInt32', field.Int32),
                  ('TestInt64', field.Int64)]

    time_s = int(time.time())
    date_time = datetime.datetime.utcfromtimestamp(time_s)
    sys_time = evntrace.SYSTEMTIME(
        date_time.year, date_time.month, 0, date_time.day,
        date_time.hour, date_time.minute, date_time.second,
        date_time.microsecond / 1000)
    file_time = ctypes.wintypes.FILETIME()
    ctypes.windll.kernel32.SystemTimeToFileTime(ctypes.byref(sys_time),
                                                ctypes.byref(file_time))
    time_stamp = file_time.dwHighDateTime
    time_stamp <<= 32
    time_stamp |= file_time.dwLowDateTime

    header_dict = {'ProcessId': 5678, 'ThreadId': 8765, 'TimeStamp': time_stamp}

    data = ctypes.c_buffer(18)
    data.value = 'Hello'

    ptr = ctypes.cast(data, ctypes.c_void_p)

    int32 = ctypes.cast(ptr.value + 6, ctypes.POINTER(ctypes.c_int))
    int32.contents.value = 1234

    int64 = ctypes.cast(ptr.value + 10, ctypes.POINTER(ctypes.c_longlong))
    int64.contents.value = 4321

    mock_event_trace = MockEventTrace(header_dict, ptr.value,
                                      ctypes.sizeof(data))
    mock_session = MockSession()
    obj = TestEventClass(mock_session, mock_event_trace)
    self.assertEqual(obj.process_id, 5678)
    self.assertEqual(obj.thread_id, 8765)
    self.assertEqual(obj.time_stamp, time_s)
    self.assertEqual(obj.TestString, 'Hello')
    self.assertEqual(obj.TestInt32, 1234)
    self.assertEqual(obj.TestInt64, 4321)

  def testBadBuffer(self):
    """Test using an invalid buffer."""
    class TestEventClass(event.EventClass):
      _fields_ = [('FieldA', field.Int32),
                  ('FieldB', field.Int32)]

    header_dict = {'ProcessId': 5678, 'ThreadId': 8765, 'TimeStamp': 123456789}

    data = ctypes.c_buffer(4)
    ptr = ctypes.cast(data, ctypes.c_void_p)
    int32 = ctypes.cast(ptr.value, ctypes.POINTER(ctypes.c_int))
    int32.contents.value = 1234

    mock_event_trace = MockEventTrace(header_dict, ptr.value,
                                      ctypes.sizeof(data))
    mock_session = MockSession()
    self.assertRaises(binary_buffer.BufferOverflowError, TestEventClass,
                      mock_session, mock_event_trace)


class EventCategoryTest(unittest.TestCase):
  def testCreation(self):
    """Test creation of a subclass of EventCategory."""
    class TestEventCategory(event.EventCategory):
      # Although it may look like this class isn't used, it is actually
      # being registered in the EventClass map by the EventCategory
      # meta class.
      GUID = 'a'
      VERSION = 1

      class TestEventClass1(event.EventClass):
        _event_types_ = [('a', 1),
                         ('a', 3),
                         ('a', 5)]

      class TestEventClass2(event.EventClass):
        _event_types_ = [('a', 2),
                         ('a', 4),
                         ('a', 6)]

    # Passing cases.
    self.assertNotEqual(event.EventClass.Get('a', 1, 1), None)
    self.assertNotEqual(event.EventClass.Get('a', 1, 2), None)
    self.assertNotEqual(event.EventClass.Get('a', 1, 3), None)
    self.assertNotEqual(event.EventClass.Get('a', 1, 4), None)
    self.assertNotEqual(event.EventClass.Get('a', 1, 5), None)
    self.assertNotEqual(event.EventClass.Get('a', 1, 6), None)

    # Failing cases.
    self.assertEqual(event.EventClass.Get('b', 1, 1), None)
    self.assertEqual(event.EventClass.Get('a', 2, 1), None)
    self.assertEqual(event.EventClass.Get('a', 1, 7), None)


if __name__ == '__main__':
  unittest.main()
