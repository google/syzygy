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
"""Unit test for the generate_descriptors module."""

import generate_descriptor
import pywintypes
import unittest
import win32com.client


class MockSWbemObject(object):
  def __init__(self, className, qualifiers=None, properties=None):
    self.Path_ = MockSWbemObjectPath(className)
    self.Qualifiers_ = MockSWbemSet(qualifiers)
    self.Properties_ = MockSWbemSet(properties)


class MockSWbemObjectPath(object):
  def __init__(self, className):
    self.Class = className


class MockSWbemProperty(object):
  def __init__(self, name, cimtype, qualifiers):
    self.Name = name
    self.CIMType = cimtype
    self.Qualifiers_ = MockSWbemSet(qualifiers)


class MockSWbemQualifier(object):
  def __init__(self, name, value):
    self.Name = name
    self.Value = value


class MockSWbemSet(object):
  def __init__(self, items):
    if not items:
      items = []
    self._items = items

  def Item(self, name):
    for item in self._items:
      if item.Name == name:
        return item
    raise pywintypes.com_error

  def __iter__(self):
    return iter(self._items)


class DescriptorGeneratorTest(unittest.TestCase):
  _TEST_GUID = '{84c2c8bc-02c7-4de1-88da-40312efbd84d}'

  _EXPECTED_GENERATE_EVENT_TYPE_CLASS_OUTPUT = (
      'class Event(object):\n'
      '  GUID = \'%s\'\n'
      '  START = (GUID, 0)\n'
      '  STOP = (GUID, 1)\n'
      '  ERROR = (GUID, 2)\n'
      '  STARTED = (GUID, 3)\n'
      '  STOPPED = (GUID, 4)')

  def testGenerateEventTypeClass(self):
    """Test generating an event type class."""
    categories = [
        MockSWbemObject('Category1'),
        MockSWbemObject('Category2')
    ]

    qualifiers = [
        MockSWbemQualifier('EventType', [0, 1, 2]),
        MockSWbemQualifier('EventTypeName', ['START', 'STOP', 'ERROR']),
    ]
    event1 = MockSWbemObject('Event1', qualifiers)

    qualifiers = [
        MockSWbemQualifier('EventType', [3, 4]),
        MockSWbemQualifier('EventTypeName', ['STARTED', 'STOPPED'])
    ]
    event2 = MockSWbemObject('Event2', qualifiers)

    def _GetEvents(category):
      if category.Path_.Class == 'Category1':
        return [event1]
      elif category.Path_.Class == 'Category2':
        return [event1, event2]

    generator = generate_descriptor.DescriptorGenerator()
    generator._GetEvents = _GetEvents
    output = generator._GenerateEventTypeClass(self._TEST_GUID, categories)
    self.assertEquals(
        self._EXPECTED_GENERATE_EVENT_TYPE_CLASS_OUTPUT % self._TEST_GUID,
        output)

  _EXPECTED_GENERATE_CATEGORY_CLASS_OUTPUT = (
      'class Category(event.EventCategory):\n'
      '  GUID = Event.GUID\n'
      '  VERSION = 2\n'
      '\n'
      '  class Event1(event.EventClass):\n'
      '    _event_types_ = [Event.Test]\n'
      '    _fields_ = [(\'Int32\', field.Int32)]\n'
      '\n'
      '  class Event2(event.EventClass):\n'
      '    _event_types_ = [Event.Test]\n'
      '    _fields_ = [(\'Int32\', field.Int32)]')

  def testGenerateEventCategory(self):
    """Test generating an event category."""
    qualifiers = [MockSWbemQualifier('EventVersion', 2)]
    category = MockSWbemObject('Category', qualifiers)

    qualifiers = [
        MockSWbemQualifier('EventType', 0),
        MockSWbemQualifier('EventTypeName', 'Test')
    ]
    properties = [
        MockSWbemProperty('Int32', win32com.client.constants.wbemCimtypeSint32,
                          [MockSWbemQualifier('WmiDataId', '0')])
    ]

    def _GetEvents(unused_category):
      return [
          MockSWbemObject('Event1', qualifiers, properties),
          MockSWbemObject('Event2', qualifiers, properties)
      ]

    generator = generate_descriptor.DescriptorGenerator()
    generator._GetEvents = _GetEvents
    output = generator._GenerateCategoryClass(category)
    self.assertEquals(self._EXPECTED_GENERATE_CATEGORY_CLASS_OUTPUT, output)

  _EXPECTED_GENERATE_EVENT_CLASS_OUTPUT = (
      '  class Event(event.EventClass):\n'
      '    _event_types_ = [Event.Error,\n'
      '                     Event.Start,\n'
      '                     Event.Stop]\n'
      '    _fields_ = [(\'Int32\', field.Int32),\n'
      '                (\'Pointer\', field.Pointer),\n'
      '                (\'String\', field.String),\n'
      '                (\'SizeT\', field.Int32)]')

  def testGenerateEventClass(self):
    """Test generating an event class."""
    # Event type names are purposely out of order alphabetically as
    # they should get sorted.
    qualifiers = [
        MockSWbemQualifier('EventType', [0, 1, 2]),
        MockSWbemQualifier('EventTypeName', ['Start', 'Stop', 'Error'])
    ]
    # Properties are out of order by WmiDataId as they should get sorted.
    properties = [
        MockSWbemProperty('String', win32com.client.constants.wbemCimtypeString,
                          [MockSWbemQualifier('WmiDataId', '2'),
                           MockSWbemQualifier('format', '')]),
        MockSWbemProperty('Int32', win32com.client.constants.wbemCimtypeSint32,
                          [MockSWbemQualifier('WmiDataId', '0')]),
        MockSWbemProperty('SizeT', win32com.client.constants.wbemCimtypeObject,
                          [MockSWbemQualifier('WmiDataId', '3'),
                           MockSWbemQualifier('extension', 'SizeT')]),
        MockSWbemProperty('Pointer',
                          win32com.client.constants.wbemCimtypeUint32,
                          [MockSWbemQualifier('WmiDataId', '1'),
                           MockSWbemQualifier('pointer', True)])
    ]
    event = MockSWbemObject('Event', qualifiers, properties)

    generator = generate_descriptor.DescriptorGenerator()
    output = generator._GenerateEventClass('Category', event)
    self.assertEquals(self._EXPECTED_GENERATE_EVENT_CLASS_OUTPUT, output)


if __name__ == '__main__':
  unittest.main()
