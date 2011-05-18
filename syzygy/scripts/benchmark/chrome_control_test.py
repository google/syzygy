#!/usr/bin/python2.6
# Copyright 2011 Google Inc.
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


class TestChromeControl(unittest.TestCase):
  def setUp(self):
    # Wipe the current settings to normalize.
    try:
      key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER,
                                  chrome_control._CHROME_FRAME_KEY,
                                  0,
                                  win32con.KEY_SET_VALUE)
    except Exception, ex:
      return

    values = (chrome_control._PREREAD_VALUE,
              chrome_control._PREREAD_SIZE_VALUE,
              chrome_control._PREREAD_STEP_VALUE)
    for value in values:
      try:
        win32api.RegDeleteValue(key, value)
      except Exception, ex:
        pass


  def tearDown(self):
    pass

  def testGetPreload(self):
    self.assertEqual((False, None, None),
                     chrome_control.GetPreload())


  def testsetPreload(self):
    chrome_control.SetPreload(True)
    self.assertEqual((True, None, None),
                     chrome_control.GetPreload())

    chrome_control.SetPreload(True, 100, 200)
    self.assertEqual((True, 100, 200),
                     chrome_control.GetPreload())

    chrome_control.SetPreload(False)
    self.assertEqual((False, None, None),
                     chrome_control.GetPreload())


if __name__ == '__main__':
  unittest.main()
