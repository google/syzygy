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
"""This module provides utility classes that make it easier to deal with
Event Tracing for Windows. The classes implement an ETW controller, consumer
and provider.
"""
from etw.consumer import TraceEventSource, EventConsumer, EventHandler
from etw.controller import TraceController, TraceProperties
from etw.provider import TraceProvider, MofEvent
from etw.guiddef import GUID

__all__ = ['GUID',
           'TraceProvider',
           'MofEvent',
           'EventConsumer',
           'EventHandler',
           'TraceEventSource',
           'TraceController',
           'TraceProperties']
