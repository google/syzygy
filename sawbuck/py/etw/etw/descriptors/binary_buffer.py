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
import ctypes
import pywintypes

ctypes.windll.advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
ctypes.windll.advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]


class BufferOverflowError(RuntimeError):
  """A custom error to throw when a buffer overflow occurs."""
  pass


class BufferDataError(RuntimeError):
  """A custom error to throw when the buffer contains invalid data."""
  pass


class BinaryBuffer(object):
  """A utility class to wrap a binary buffer.

  This class wraps a buffer of data and provides accessor methods for
  reading types from the buffer while checking to make sure accesses
  do not overflow the buffer.
  """
  def __init__(self, data, length):
    """Create a new binary buffer.

    Args:
      data: Integer start address of the buffer.
      length: Length of the buffer.
    """
    self._data = data
    self._length = length

  def Contains(self, pos, length):
    """Tests whether the current buffer contains the specified section.

    Args:
      pos: Start position of range.
      length: Length of range.
    """
    if pos < 0 or pos > self._length:
      return False
    if length < 0 or length > self._length:
      return False
    return pos + length <= self._length

  def GetAt(self, pos, length):
    """Gets the address of a position in the buffer checking for overflow.

    Args:
      pos: Start position of range.
      length: Length of range.
    """
    if not self.Contains(pos, length):
      raise BufferOverflowError()
    return self._data + pos

  def GetTypeAt(self, pos, type):
    """Gets the desired type from the desired position in the buffer."""
    return ctypes.cast(self.GetAt(pos, ctypes.sizeof(type)),
                       ctypes.POINTER(type)).contents.value

  def GetStringAt(self, pos):
    """Gets a string from the desired position in the buffer."""
    return ctypes.string_at(self.GetAt(pos, ctypes.sizeof(ctypes.c_char)))

  def GetWStringAt(self, pos):
    """Gets a wide string from the desired position in the buffer."""
    return ctypes.wstring_at(self.GetAt(pos, ctypes.sizeof(ctypes.c_wchar)))


class BinaryBufferReader(object):
  """A utility class to help read values from a buffer.

  This class wraps a binary buffer and maintains a current position so that
  consecutive values can be read out of the buffer. It provies methods
  for reading specific types and consuming data while checking for overflow.
  """
  def __init__(self, data, length):
    """Creates a new binary buffer reader.

    Args:
      data: Integer start address of the buffer.
      length: Length of the buffer.
    """
    self._buffer = BinaryBuffer(data, length)
    self._pos = 0

  def Consume(self, length):
    """Advances the current position in the buffer by length."""
    if not self._buffer.Contains(self._pos, length):
      raise BufferOverflowError()
    self._pos += length

  def Read(self, type):
    """Gets the specified type from the current position in the buffer."""
    val = self._buffer.GetTypeAt(self._pos, type)
    self.Consume(ctypes.sizeof(type))
    return val

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
    val = self._buffer.GetStringAt(self._pos)
    self.Consume(len(val) + ctypes.sizeof(ctypes.c_char))
    return val

  def ReadWString(self):
    val = self._buffer.GetWStringAt(self._pos)
    self.Consume(len(val) + ctypes.sizeof(ctypes.c_wchar))
    return val

  MIN_SID_SIZE = 8
  POINTER_SIZE_32 = 4
  POINTER_SIZE_64 = 8

  def ReadSid(self, is_64_bit_ptrs):
    # Two pointers are included before the SID, so skip them.
    pointer_size = self.POINTER_SIZE_64 if is_64_bit_ptrs else \
        self.POINTER_SIZE_32
    self.Consume(2 * pointer_size)

    data = self._buffer.GetAt(self._pos, self.MIN_SID_SIZE)
    if not ctypes.windll.advapi32.IsValidSid(data):
      raise BufferDataError('Invalid SID.')
    len = ctypes.windll.advapi32.GetLengthSid(data)
    self.Consume(len)

    sid_buffer = ctypes.string_at(data, len)
    return pywintypes.SID(sid_buffer)
