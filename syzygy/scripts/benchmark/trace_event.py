#!/usr/bin/python2.6
# Copyright 2011 Google Inc. All Rights Reserved.
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
"""ETW event descriptor for Chrome's trace events."""

from etw.descriptors import event
from etw.descriptors import field


class Event(object):
  GUID = '{b967ae67-bb22-49d7-9406-55d91ee1d560}'
  EVENT_BEGIN = (GUID, 0x10)
  EVENT_END = (GUID, 0x11)
  EVENT_INSTANT = (GUID, 0x12)


class ChromeTraceEvent(event.EventCategory):
  GUID = Event.GUID
  VERSION = 0

  # While all the events are logged the same way, we separate
  # Begin/End and Instant for ease of parsing.
  class TraceEvent_Begin(event.EventClass):
    _event_types_ = [Event.EVENT_BEGIN]
    _fields_ = [('name', field.String),
                ('id', field.Pointer),
                ('extra', field.String),]

  class TraceEvent_End(event.EventClass):
    _event_types_ = [Event.EVENT_END]
    _fields_ = [('name', field.String),
                ('id', field.Pointer),
                ('extra', field.String),]

  class TraceEvent_Instant(event.EventClass):
    _event_types_ = [Event.EVENT_INSTANT]
    _fields_ = [('name', field.String),
                ('id', field.Pointer),
                ('extra', field.String),]
