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
#
"""Function definitions for callable field types.

The functions defined here are meant to be used as callable field types
used with event descriptor field definitions. See event.EventClass for
how fields are defined using these field types.

The arguments passed to each function are the same:
  session: The _TraceLogSession instance the event arrived on.
    This has a session-related properties and functionality, such as
    the is_64_bit_log property and the SessionTimeToTime member that
    will convert a time stamp in the session's units to a python time.
  reader: A binary buffer reader to read the field type from.
"""

def Boolean(session, reader):
  return reader.ReadBoolean()

def Int8(session, reader):
  return reader.ReadInt8()

def UInt8(session, reader):
  return reader.ReadUInt8()

def Int16(session, reader):
  return reader.ReadInt16()

def UInt16(session, reader):
  return reader.ReadUInt16()

def Int32(session, reader):
  return reader.ReadInt32()

def UInt32(session, reader):
  return reader.ReadUInt32()

def Int64(session, reader):
  return reader.ReadInt64()

def UInt64(session, reader):
  return reader.ReadUInt64()

def Pointer(session, reader):
  if session.is_64_bit_log:
    return reader.ReadUInt64()
  else:
    return reader.ReadUInt32()

def String(session, reader):
  return reader.ReadString()

def WString(session, reader):
  return reader.ReadWString()

def Sid(session, reader):
  return reader.ReadSid(session.is_64_bit_log)

def WmiTime(session, reader):
  return session.SessionTimeToTime(reader.ReadUInt64())
