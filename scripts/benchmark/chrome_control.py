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
"""A utility module for controlling Chrome instances."""
import exceptions
import os.path
import win32api
import win32con
import win32event
import win32gui
import win32process
import winerror
import _winreg


class ChromeNotFoundException(Exception):
  pass

class TimeoutException(Exception):
  pass


_MESSAGE_WINDOW_CLASS = 'Chrome_MessageWindow'
_WIDGET_WINDOW_CLASS = 'Chrome_WidgetWin_0'


def _SendChromeEndSession(window, extra):
  if win32gui.GetClassName(window) == _WIDGET_WINDOW_CLASS:
    win32gui.PostMessage(window, win32con.WM_ENDSESSION)


def ShutDown(profile_dir, timeout_ms=win32event.INFINITE):
  """Shuts down the Chrome instance running in profile_dir.

  Sends WM_ENDSESSION to all top-level windows on the same thread
  as the message window, which roughly approximates user logoff.

  Args:
      profile_dir: the profile directory of the Chrome instance you want
          to shutdown
      timeout_ms: how long to wait for the Chrome instance to shut down in
          milliseconds. Defaults to waiting forever.

  Returns:
      The exit status of the Chrome browser process.

  Raises:
      ChromeNotFoundException: Chrome is not running in this profile.
      TimeoutException: Chrome did not exit in time.
  """
  profile_dir = os.path.abspath(profile_dir)

  # Find the message window associated with this profile directory.
  message_win = win32gui.FindWindowEx(None,
                                      None,
                                      _MESSAGE_WINDOW_CLASS,
                                      profile_dir)

  if not message_win:
    raise ChromeNotFoundException

  # Get the thread and process IDs associated with this window.
  (thread_id, process_id) = win32process.GetWindowThreadProcessId(message_win)

  # Open the process in question, so we can wait for it to exit.
  permissions = win32con.SYNCHRONIZE | win32con.PROCESS_QUERY_INFORMATION
  process_handle = win32api.OpenProcess(permissions, False, process_id)

  # Now send WM_ENDSESSION to all top-level widget windows on that thread.
  win32gui.EnumThreadWindows(thread_id, _SendChromeEndSession, None)

  # Wait for the process to exit and get its exit status.
  result = win32event.WaitForSingleObject(process_handle, timeout_ms)
  exit_status = win32process.GetExitCodeProcess(process_handle)
  process_handle.Close()

  # Raise if it didn't exit in time.
  if result != win32event.WAIT_OBJECT_0:
    raise TimeoutException

  return exit_status


_CHROME_FRAME_KEY = r'Software\Google\ChromeFrame'
_PREREAD_SIZE_VALUE = 'PreReadSize'
_PREREAD_STEP_VALUE = 'PreReadStepSize'
_PREREAD_VALUE = 'PreRead'


def _GetDWORDValue(key, name):
  try:
    (value, value_type) = _winreg.QueryValueEx(key, name)
  except exceptions.WindowsError, ex:
    if ex.errno is not winerror.ERROR_FILE_NOT_FOUND:
      raise
    return None

  return value

def GetPreload():
  """Reads Chrome.dll preload settings from the registry.

  Returns:
      a tuple (enable, size, stride)
  """
  try:
    key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, _CHROME_FRAME_KEY)
  except exceptions.WindowsError, ex:
    # We expect specific errors on non-present key or values.
    if ex.errno is not winerror.ERROR_FILE_NOT_FOUND:
      raise
    else:
      return (False, None, None)

  enable = bool(_GetDWORDValue(key, _PREREAD_VALUE))
  size = _GetDWORDValue(key, _PREREAD_SIZE_VALUE)
  stride = _GetDWORDValue(key, _PREREAD_STEP_VALUE)

  return (enable, size, stride)


def _SetDWORDValueImpl(key, name, value):
  if value == None:
    try:
      _winreg.DeleteValue(key, name)
    except WindowsError, ex:
      if ex.errno is not winerror.ERROR_FILE_NOT_FOUND:
        raise
  else:
    _winreg.SetValueEx(key, name, None, _winreg.REG_DWORD, value)


def SetPreload(enable, size=None, stride=None):
  """Writes Chrome.dll preload settings to the registry.

  Args:
      enable: if true, preloading will be enabled.
      size: optionally provides the amount of data to preload. If not provided
          the entire DLL will be preloaded by the current Chrome implementation.
      stride: optionally provides the stride used for preloading on Windows XP.
  """
  key = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, _CHROME_FRAME_KEY)
  _winreg.SetValueEx(key, _PREREAD_VALUE, None, _winreg.REG_DWORD, enable)
  _SetDWORDValueImpl(key, _PREREAD_SIZE_VALUE, size)
  _SetDWORDValueImpl(key, _PREREAD_STEP_VALUE, stride)
