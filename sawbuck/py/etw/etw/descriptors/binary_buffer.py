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
"""Helper classes for reading binary buffers."""
import ctypes
import pywintypes

ctypes.windll.advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
ctypes.windll.advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]


class BufferOverflowError(RuntimeError):
  """A custom error to throw when a buffer overflow occurs."""


class BufferDataError(RuntimeError):
  """A custom error to throw when the buffer contains invalid data."""


class BinaryBuffer(object):
  """A utility class to wrap a binary buffer.

  This class wraps a buffer of data and provides accessor methods for
  reading types from the buffer while checking to make sure accesses
  do not overflow the buffer.
  """

  def __init__(self, start, length):
    """Create a new binary buffer.

    Args:
      start: Integer start address of the buffer.
      length: Length of the buffer.
    """
    self._start = start
    self._length = length

  def Contains(self, offset, length):
    """Tests whether the current buffer contains the specified segment.

    Args:
      offset: Offset of the segment from the start of the buffer.
      length: Length of the segment.

    Returns:
      Whether the buffer contains the segment.
    """
    if offset < 0:
      return False
    if length < 0:
      return False
    return offset + length <= self._length

  def GetAt(self, offset, length):
    """Gets the address of a segment in the buffer checking for overflow.

    Args:
      offset: Offset of the segment from the start of the buffer.
      length: Length of the segment.

    Returns:
      The address of the segment in the buffer.

    Raises:
      BufferOverflowError: The position and length specifies a segment that
      overflows the buffer.
    """
    if not self.Contains(offset, length):
      raise BufferOverflowError()
    return self._start + offset

  def GetTypeAt(self, offset, data_type):
    """Gets a data type from an offset in the buffer.

    Args:
      offset: Offset of the data type from the start of the buffer.
      data_type: A ctypes type that specifies the data type to get from
        the buffer.

    Returns:
      The value of the data type at the offset within the buffer.
    """
    return ctypes.cast(self.GetAt(offset, ctypes.sizeof(data_type)),
                       ctypes.POINTER(data_type)).contents.value

  def GetStringAt(self, offset):
    """Gets a string from an offset in the buffer.

    Args:
      offset: Offset of the string from the start of the buffer.

    Returns:
      The string starting at position offset within the buffer.
    """
    return ctypes.string_at(self.GetAt(offset, ctypes.sizeof(ctypes.c_char)))

  def GetWStringAt(self, offset):
    """Gets a string from an offset in the buffer.

    Args:
      offset: Offset of the string from the start of the buffer.

    Returns:
      The string starting at position offset within the buffer.
    """
    return ctypes.wstring_at(self.GetAt(offset, ctypes.sizeof(ctypes.c_wchar)))


class BinaryBufferReader(object):
  """A utility class to help read values from a buffer.

  This class wraps a binary buffer and maintains a current position so that
  consecutive values can be read out of the buffer. It provides methods
  for reading specific types and consuming data while checking for overflow.
  """

  def __init__(self, start, length):
    """Creates a new binary buffer reader.

    Args:
      start: Integer start address of the buffer.
      length: Length of the buffer.
    """
    self._buffer = BinaryBuffer(start, length)
    self._offset = 0

  def Consume(self, length):
    """Advances the current offset in the buffer by length.

    Args:
      length: The length to consume.

    Raises:
      BufferOverflowError: Consuming the specified length will overflow
      the buffer.
    """
    if not self._buffer.Contains(self._offset, length):
      raise BufferOverflowError()
    self._offset += length

  def Read(self, data_type):
    """Reads the value of the data type from the current offset in the buffer.

    Args:
      data_type: A ctypes type that specifies the data type to get from
        the buffer.

    Returns:
      The value of the data type at the current offset in the buffer.
    """
    val = self._buffer.GetTypeAt(self._offset, data_type)
    self.Consume(ctypes.sizeof(data_type))
    return val

  def ReadBoolean(self):
    return self.Read(ctypes.c_byte) != 0

  def ReadInt8(self):
    return self.Read(ctypes.c_byte)

  def ReadUInt8(self):
    return self.Read(ctypes.c_ubyte)

  def ReadInt16(self):
    return self.Read(ctypes.c_short)

  def ReadUInt16(self):
    return self.Read(ctypes.c_ushort)

  def ReadInt32(self):
    return self.Read(ctypes.c_int)

  def ReadUInt32(self):
    return self.Read(ctypes.c_uint)

  def ReadInt64(self):
    return self.Read(ctypes.c_longlong)

  def ReadUInt64(self):
    return self.Read(ctypes.c_ulonglong)

  def ReadString(self):
    val = self._buffer.GetStringAt(self._offset)
    self.Consume(len(val) + ctypes.sizeof(ctypes.c_char))
    return val

  def ReadWString(self):
    val = self._buffer.GetWStringAt(self._offset)
    self.Consume(len(val) + ctypes.sizeof(ctypes.c_wchar))
    return val

  _MINIMUM_SID_SIZE = 8
  _POINTER_SIZE_32 = 4
  _POINTER_SIZE_64 = 8

  def ReadSid(self, is_64_bit_ptrs):
    """Reads a SID from the current offset in the buffer.

    Args:
      is_64_bit_ptrs: Whether the current buffer contains 64 bit pointers.

    Returns:
      The SID at the current offset in the buffer.

    Raises:
      BufferDataError: Raised if the buffer does not contain a valid SID at
      this offset.
    """
    # Two pointers are included before the SID, so skip them.
    pointer_size = (self._POINTER_SIZE_64 if is_64_bit_ptrs else
        self._POINTER_SIZE_32)
    self.Consume(2 * pointer_size)

    data = self._buffer.GetAt(self._offset, self._MINIMUM_SID_SIZE)
    if not ctypes.windll.advapi32.IsValidSid(data):
      raise BufferDataError('Invalid SID.')
    sid_len = ctypes.windll.advapi32.GetLengthSid(data)
    self.Consume(sid_len)

    sid_buffer = ctypes.string_at(data, sid_len)
    return pywintypes.SID(sid_buffer)
