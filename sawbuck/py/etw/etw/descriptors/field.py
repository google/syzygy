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
  reader: A binary buffer reader to read the field type from.
  is_64_bit_log: Whether the log is for a 64 bit machine.
"""

def Int16(reader, is_64_bit_log):
  return reader.ReadInt16()

def UInt16(reader, is_64_bit_log):
  return reader.ReadUInt16()

def Int32(reader, is_64_bit_log):
  return reader.ReadInt32()

def UInt32(reader, is_64_bit_log):
  return reader.ReadUInt32()

def Int64(reader, is_64_bit_log):
  return reader.ReadInt64()

def UInt64(reader, is_64_bit_log):
  return reader.ReadUInt64()

def Pointer(reader, is_64_bit_log):
  return reader.ReadUInt64() if is_64_bit_log else reader.ReadUInt32()

def String(reader, is_64_bit_log):
  return reader.ReadString()

def WString(reader, is_64_bit_log):
  return reader.ReadWString()

def Sid(reader, is_64_bit_log):
  return reader.ReadSid(is_64_bit_log)

def WmiTime(reader, is_64_bit_log):
  return reader.ReadUInt64()
