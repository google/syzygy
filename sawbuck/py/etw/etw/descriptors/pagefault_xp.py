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
"""Hand-crafted event descriptor file for XP page faults.

These descriptions are missing from the MOF data on Win7, so the gaps
are plugged by hand here.
"""

from etw.descriptors.pagefault import Event
from etw.descriptors import event
from etw.descriptors import field


class PageFault_V1(event.EventCategory):
  GUID = Event.GUID
  VERSION = 1

  class PageFault_HardFault(event.EventClass):
    _event_types_ = [Event.HardFault]
    _fields_ = [('InitialTime', field.WmiTime),
                ('ReadOffset', field.UInt64),
                ('VirtualAddress', field.Pointer),
                ('FileObject', field.Pointer),
                ('TThreadId', field.UInt32),
                ('ByteCount', field.UInt32)]

  class PageFault_TypeGroup1(event.EventClass):
    _event_types_ = [Event.AccessViolation,
                     Event.CopyOnWrite,
                     Event.DemandZeroFault,
                     Event.GuardPageFault,
                     Event.HardPageFault,
                     Event.TransitionFault]
    _fields_ = [('VirtualAddress', field.Pointer),
                ('ProgramCounter', field.Pointer)]
