#!/usr/bin/python2.6
# Copyright 2012 Google Inc. All Rights Reserved.
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
import chrome_control
import unittest
import win32con
import win32api
import _winreg


# This is to allow access to private internals without raising a warning.
# pylint: disable=W0212
class TestChromeControl(unittest.TestCase):
  def setUp(self):
    # Wipe the current settings to normalize.
    try:
      key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER,
                                  chrome_control._CHROME_FRAME_KEY,
                                  0,
                                  win32con.KEY_SET_VALUE)
    except Exception:
      return

    values = (chrome_control._PREREAD_VALUE,
              chrome_control._PREREAD_PERCENTAGE_VALUE,
              chrome_control._PREREAD_SIZE_VALUE,
              chrome_control._PREREAD_STEP_VALUE)
    for value in values:
      try:
        win32api.RegDeleteValue(key, value)
      except Exception:
        pass


  def tearDown(self):
    pass

  def testGetPreload(self):
    self.assertEqual(100, chrome_control.GetPreload())


  def testSetPreload(self):
    chrome_control.SetPreload(False)
    self.assertEqual(0, chrome_control.GetPreload())

    chrome_control.SetPreload(True)
    self.assertEqual(100, chrome_control.GetPreload())

    chrome_control.SetPreload(0)
    self.assertEqual(0, chrome_control.GetPreload())

    chrome_control.SetPreload(50)
    self.assertEqual(50, chrome_control.GetPreload())

    chrome_control.SetPreload(100)
    self.assertEqual(100, chrome_control.GetPreload())

  def testOldPreload(self):
    key = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER,
                            chrome_control._CHROME_FRAME_KEY)
    chrome_control._SetDWORDValueImpl(key, chrome_control._PREREAD_VALUE, 0)
    self.assertEqual(0, chrome_control.GetPreload())

    chrome_control._SetDWORDValueImpl(key, chrome_control._PREREAD_VALUE, 1)
    self.assertEqual(100, chrome_control.GetPreload())


if __name__ == '__main__':
  unittest.main()
