#!python
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unittests for the minidump_symbolizer module."""

import logging
import minidump_symbolizer
import re
import unittest


class TestInterceptorParser(unittest.TestCase):
  """Unittests for minidump_symbolizer.

  TODO(sebmarchand): Add more tests, we only test the regex for now.
  """

  def testStackFrameMatchRegex(self):
    valid_frame = '003cd6b8 0ff3a36b 007bff00 00004e84 003cd760 foo!bar+0x18'
    valid_frame_m = minidump_symbolizer._STACK_FRAME_RE.search(valid_frame)
    self.assertTrue(valid_frame_m != None)
    self.assertEqual(valid_frame_m.group('module'), 'foo')
    self.assertEqual(valid_frame_m.group('location'), 'bar+0x18')
    self.assertEqual(valid_frame_m.group('address'), None)

    valid_frame = '003cd6b8 0ff3a36b 007bff00 00004e84 003cd760 0xcafebabe'
    valid_frame_m = minidump_symbolizer._STACK_FRAME_RE.search(valid_frame)
    self.assertTrue(valid_frame_m != None)
    self.assertEqual(valid_frame_m.group('module'), None)
    self.assertEqual(valid_frame_m.group('location'), None)
    self.assertEqual(valid_frame_m.group('address'), '0xcafebabe')

    valid_frame = (
        '(Inline) -------- -------- -------- -------- foo!bar+0x42')
    valid_frame_m = minidump_symbolizer._STACK_FRAME_RE.search(valid_frame)
    self.assertTrue(valid_frame_m != None)
    self.assertEqual(valid_frame_m.group('module'), 'foo')
    self.assertEqual(valid_frame_m.group('location'), 'bar+0x42')
    self.assertEqual(valid_frame_m.group('address'), None)

    valid_frame = 'ab cd ef 01 23 foo!bar+0x18 (FPO: [0,0,0])'
    valid_frame_m = minidump_symbolizer._STACK_FRAME_RE.search(valid_frame)
    self.assertTrue(valid_frame_m != None)
    self.assertEqual(valid_frame_m.group('module'), 'foo')
    self.assertEqual(valid_frame_m.group('location'), 'bar+0x18 (FPO: [0,0,0])')
    self.assertEqual(valid_frame_m.group('address'), None)

    valid_frame = '001ccc48 76d0bedd 00000e40 00020000 00456ab0 foo+0x18c'
    valid_frame_m = minidump_symbolizer._STACK_FRAME_RE.search(valid_frame)
    self.assertTrue(valid_frame_m != None)
    self.assertEqual(valid_frame_m.group('module'), 'foo')
    self.assertEqual(valid_frame_m.group('location'), '0x18c')
    self.assertEqual(valid_frame_m.group('address'), None)

    invalid_frame = ''
    invalid_frame_m = minidump_symbolizer._STACK_FRAME_RE.search(invalid_frame)
    self.assertTrue(invalid_frame_m == None)

    invalid_frame = '003cd6b8 0ff3a36b 007bff00 00004e84 003cd760'
    invalid_frame_m = minidump_symbolizer._STACK_FRAME_RE.search(invalid_frame)
    self.assertTrue(invalid_frame_m == None)

    invalid_frame = '003cd6b8 0ff3a36b 007bff00 00004e84 003cd760 foo'
    invalid_frame_m = minidump_symbolizer._STACK_FRAME_RE.search(invalid_frame)
    self.assertTrue(invalid_frame_m == None)

    invalid_frame = '003cd6b8 0ff3a36b 007bff00 00004e84 003cd760 !bar'
    invalid_frame_m = minidump_symbolizer._STACK_FRAME_RE.search(invalid_frame)
    self.assertTrue(invalid_frame_m == None)

  def testModuleMatchRegex(self):
    valid_module = '00400000 004d7000   chrome   chrome.exe'
    valid_module_m = minidump_symbolizer._MODULE_MATCH_RE.search(valid_module)
    self.assertTrue(valid_module_m != None)
    self.assertEqual(valid_module_m.group('start'), '00400000')
    self.assertEqual(valid_module_m.group('end'), '004d7000')
    self.assertEqual(valid_module_m.group('module_name'), 'chrome')
    self.assertEqual(valid_module_m.group('image_name'), 'chrome.exe')

    invalid_module = '00400000 004d7000  chrome'
    invalid_module_m = minidump_symbolizer._MODULE_MATCH_RE.search(
        invalid_module)
    self.assertTrue(invalid_module_m == None)

  def testChromeFrameMatchRegex(self):
    valid_frame = 'chrome_00400000'
    valid_frame_m = minidump_symbolizer._CHROME_RE.search(
        valid_frame)
    self.assertTrue(valid_frame_m != None)

    invalid_frame = 'chrome_child'
    invalid_frame_m = minidump_symbolizer._MODULE_MATCH_RE.search(
        invalid_frame)
    self.assertTrue(invalid_frame_m == None)

    invalid_frame = 'foo_00400000'
    invalid_frame_m = minidump_symbolizer._MODULE_MATCH_RE.search(
        invalid_frame)
    self.assertTrue(invalid_frame_m == None)

  def testFramePointerMatchRegex(self):
    valid_frame_ptr = '001ce48c 762b15f7 00000002 001ce4dc 00000001'
    valid_frame_ptr_m = minidump_symbolizer._FRAME_POINTER_RE.search(
        valid_frame_ptr)
    self.assertTrue(valid_frame_ptr_m != None)
    self.assertEqual(valid_frame_ptr_m.group('address'), '762b15f7')

    invalid_frame_ptr = '00000000'
    invalid_frame_ptr_m = minidump_symbolizer._MODULE_MATCH_RE.search(
        invalid_frame_ptr)
    self.assertTrue(invalid_frame_ptr_m == None)

  def testEnumValMatchRegex(self):
    valid_enum_val = '5 ( USE_AFTER_FREE )'
    valid_enum_val_m = minidump_symbolizer._ENUM_VAL_RE.search(
        valid_enum_val)
    self.assertTrue(valid_enum_val_m != None)
    self.assertEqual(valid_enum_val_m.group('num_value'), '5')
    self.assertEqual(valid_enum_val_m.group('literal_value'), 'USE_AFTER_FREE')

    invalid_enum_val = '0x4d260ba3 Void'
    invalid_enum_val_m = minidump_symbolizer._ENUM_VAL_RE.search(
        invalid_enum_val)
    self.assertTrue(invalid_enum_val_m == None)


if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)
  unittest.main()
