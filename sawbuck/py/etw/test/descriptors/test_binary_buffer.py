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
from etw.descriptors.binary_buffer import BinaryBuffer, BufferOverflowError, \
    BinaryBufferReader
import ctypes
import unittest


class BinaryBufferTest(unittest.TestCase):
  def testContains(self):
    """Test buffer Contains."""
    buffer = BinaryBuffer(0, 10)

    self.assertFalse(buffer.Contains(-1, 5))  # pos < 0
    self.assertFalse(buffer.Contains(11, 5))  # pos > buffer length
    self.assertFalse(buffer.Contains(5, -1))  # len < 0
    self.assertFalse(buffer.Contains(5, 11))  # len > buffer length

    self.assertTrue(buffer.Contains(0, 0))
    self.assertTrue(buffer.Contains(0, 5))
    self.assertTrue(buffer.Contains(0, 10))
    self.assertFalse(buffer.Contains(0, 11))

    self.assertTrue(buffer.Contains(5, 0))
    self.assertTrue(buffer.Contains(5, 2))
    self.assertTrue(buffer.Contains(5, 5))
    self.assertFalse(buffer.Contains(5, 6))

    self.assertTrue(buffer.Contains(10, 0))
    self.assertFalse(buffer.Contains(10, 1))

  def testGetAt(self):
    """Test buffer GetAt."""
    buffer = BinaryBuffer(20, 10)

    self.assertEqual(20, buffer.GetAt(0, 0))
    self.assertEqual(20, buffer.GetAt(0, 5))
    self.assertEqual(22, buffer.GetAt(2, 5))
    self.assertEqual(28, buffer.GetAt(8, 2))

    self.assertRaises(BufferOverflowError, buffer.GetAt, 0, 11)
    self.assertRaises(BufferOverflowError, buffer.GetAt, 5, 10)
    self.assertRaises(BufferOverflowError, buffer.GetAt, 7, 15)

  def testGetTypeAt(self):
    """Test buffer GetTypeAt."""
    data = ctypes.c_buffer(8)
    ptr = ctypes.cast(data, ctypes.c_void_p)
    buffer = BinaryBuffer(ptr.value, ctypes.sizeof(data))

    # char
    data.value = 'hello'
    self.assertEqual('h', buffer.GetTypeAt(0, ctypes.c_char))
    self.assertEqual('o', buffer.GetTypeAt(4, ctypes.c_char))

    # uint
    uint = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_uint))
    uint.contents.value = 1234
    self.assertEqual(1234, buffer.GetTypeAt(0, ctypes.c_uint))

    # int
    int = ctypes.cast(ptr.value + 4, ctypes.POINTER(ctypes.c_int))
    int.contents.value = -4321
    self.assertEqual(-4321, buffer.GetTypeAt(4, ctypes.c_int))

    # ulonglong
    long = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ulonglong))
    long.contents.value = 123456789
    self.assertEqual(123456789, buffer.GetTypeAt(0, ctypes.c_ulonglong))

    # longlong
    long = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_longlong))
    long.contents.value = -123456789
    self.assertEqual(-123456789, buffer.GetTypeAt(0, ctypes.c_longlong))

    # error
    self.assertRaises(BufferOverflowError, buffer.GetTypeAt, 4,
                      ctypes.c_longlong)

  def testGetStringAt(self):
    """Test buffer GetStringAt."""
    # non-wide
    data = ctypes.create_string_buffer('Hello!')
    buffer = BinaryBuffer(ctypes.cast(data, ctypes.c_void_p).value,
                          ctypes.sizeof(data))
    self.assertEqual('Hello!', buffer.GetStringAt(0))
    self.assertEqual('lo!', buffer.GetStringAt(3))

    # wide
    data = ctypes.create_unicode_buffer('Hello!')
    buffer = BinaryBuffer(ctypes.cast(data, ctypes.c_void_p).value,
                          ctypes.sizeof(data))
    self.assertEqual(u'Hello!', buffer.GetWStringAt(0))
    self.assertEqual(u'lo!', buffer.GetWStringAt(6))

    #error
    self.assertRaises(BufferOverflowError, buffer.GetStringAt, 20)
    self.assertRaises(BufferOverflowError, buffer.GetWStringAt, 20)


class BinaryBufferReaderTest(unittest.TestCase):
  def testConsume(self):
    """Test buffer reader Consume."""
    reader = BinaryBufferReader(0, 10)
    reader.Consume(5)
    self.assertEquals(5, reader._pos)
    self.assertRaises(BufferOverflowError, reader.Consume, 6)

  def testRead(self):
    """Test buffer reader Read."""
    data = ctypes.c_buffer(4)
    reader = BinaryBufferReader(ctypes.cast(data, ctypes.c_void_p).value,
                                ctypes.sizeof(data))

    int = ctypes.cast(data, ctypes.POINTER(ctypes.c_int))
    int.contents.value = -4321
    self.assertEqual(-4321, reader.Read(ctypes.c_int))
    self.assertEqual(ctypes.sizeof(ctypes.c_int), reader._pos)

  def testReadString(self):
    """Test buffer reader ReaderString."""
    data = ctypes.create_string_buffer('Hello!')
    reader = BinaryBufferReader(ctypes.cast(data, ctypes.c_void_p).value,
                                ctypes.sizeof(data))
    self.assertEqual('Hello!', reader.ReadString())

    data = ctypes.create_unicode_buffer('Hello!')
    reader = BinaryBufferReader(ctypes.cast(data, ctypes.c_void_p).value,
                                ctypes.sizeof(data))
    self.assertEqual(u'Hello!', reader.ReadWString())

  POINTER_SIZE_32 = 4
  MAX_SID_SIZE = 68
  WIN_WORLD_SID = 1

  def testReadSid(self):
    """Test buffer reader ReadSid."""
    data = ctypes.c_buffer(2 * self.POINTER_SIZE_32 + self.MAX_SID_SIZE)
    ptr = ctypes.cast(data, ctypes.c_void_p)
    sidPtr = ctypes.cast(ptr.value + 2 * self.POINTER_SIZE_32, ctypes.c_void_p)

    size = ctypes.c_int()
    size.value = self.MAX_SID_SIZE
    self.assertNotEqual(0,
        ctypes.windll.advapi32.CreateWellKnownSid(self.WIN_WORLD_SID, None,
                                                  sidPtr, ctypes.byref(size)))

    reader = BinaryBufferReader(ptr.value, ctypes.sizeof(data))
    sid = reader.ReadSid(False)
    self.assertTrue(sid.IsValid())


if __name__ == '__main__':
  unittest.main()
