#!/usr/bin/python2.6
# Copyright 2011 Google Inc.
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
"""Event descriptor for Call Trace events."""
from etw.descriptors import event
from etw.descriptors import field


class _Call(object):
  """Represents a function call at a certain time."""
  def __init__(self, tick_count, address):
    self.tick_count = tick_count
    self.address = address


def _CallsField(session, reader):
  """Field to handle a batch of calls for a given thread.

  Returns:
    A list of _Call objects.
  """
  num_calls = reader.ReadUInt32()
  calls = []
  for _ in range(num_calls):
    tick_count = reader.ReadUInt32()
    address = reader.ReadUInt32()
    calls.append(_Call(tick_count, address))
  return calls


class Event(object):
  """Call Trace event class."""
  GUID = '{44caeed0-5432-4c2d-96fa-cec50c742f01}'
  TraceBatchEnter = (GUID, 17)


class CallTrace(event.EventCategory):
  """Call Trace event category class."""
  GUID = Event.GUID
  VERSION = 0

  class TraceBatchEnter(event.EventClass):
    _event_types_ = [Event.TraceBatchEnter]
    _fields_ = [('ThreadId', field.UInt32),
                ('Calls', _CallsField)]
