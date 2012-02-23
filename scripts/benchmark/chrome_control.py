#!/usr/bin/python2.6
# Copyright 2012 Google Inc.
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
import pywintypes
import subprocess
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


def _FindProfileWindow(profile_dir):
  """Find the message window associated with profile_dir, if any."""
  profile_dir = os.path.abspath(profile_dir)

  try:
    return win32gui.FindWindowEx(None,
                                 None,
                                 _MESSAGE_WINDOW_CLASS,
                                 profile_dir)
  except pywintypes.error:
    # On Windows 7, FindWindowEx returns None without raising an error.
    # On older versions, it raises a FILE_NOT_FOUND error.
    return None


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
  message_win = _FindProfileWindow(profile_dir)
  if not message_win:
    raise ChromeNotFoundException

  # Get the thread and process IDs associated with this window.
  (thread_id, process_id) = win32process.GetWindowThreadProcessId(message_win)

  # Open the process in question, so we can wait for it to exit.
  permissions = win32con.SYNCHRONIZE | win32con.PROCESS_QUERY_INFORMATION
  process_handle = win32api.OpenProcess(permissions, False, process_id)

  # Loop around to periodically retry the end session window message.
  # It appears that there are times during Chrome startup where it'll
  # igore this message, or perhaps we sometimes hit a case where there
  # are no appropriate top-level windows.
  while True:
    # Now send WM_ENDSESSION to all top-level widget windows on that thread.
    win32gui.EnumThreadWindows(thread_id, _SendChromeEndSession, None)

    # Wait for the process to exit and get its exit status.
    curr_timeout_ms = 2000
    if timeout_ms != win32event.INFINITE:
      if timeout_ms < curr_timeout_ms:
        curr_timeout_ms = timeout_ms

      timeout_ms -= curr_timeout

    result = win32event.WaitForSingleObject(process_handle, curr_timeout_ms)
    # Exit the loop on successful wait.
    if result == win32event.WAIT_OBJECT_0:
      break

    # Did we time out?
    if timeout_ms == 0:
      raise TimeoutException


  exit_status = win32process.GetExitCodeProcess(process_handle)
  process_handle.Close()

  return exit_status


def IsProfileRunning(profile_dir):
  """Returns True iff there is a Chrome instance running in profile_dir."""
  if _FindProfileWindow(profile_dir):
    return True
  return False


_CHROME_FRAME_KEY = r'Software\Google\ChromeFrame'
_PREREAD_PERCENTAGE_VALUE = 'PreReadPercentage'
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
    The percentage of chrome.dll that will be preloaded.
  """
  try:
    with _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, _CHROME_FRAME_KEY) as key:
      percentage = _GetDWORDValue(key, _PREREAD_PERCENTAGE_VALUE)
      if percentage is None:
        percentage = 0 if _GetDWORDValue(key, _PREREAD_VALUE) == 0 else 100
      return percentage
  except exceptions.WindowsError, ex:
    # We expect specific errors on non-present key or values.
    if ex.errno is not winerror.ERROR_FILE_NOT_FOUND:
      raise
    else:
      return 100


def _SetDWORDValueImpl(key, name, value):
  if value == None:
    try:
      _winreg.DeleteValue(key, name)
    except WindowsError, ex:
      if ex.errno is not winerror.ERROR_FILE_NOT_FOUND:
        raise
  else:
    _winreg.SetValueEx(key, name, None, _winreg.REG_DWORD, value)


def SetPreload(value):
  """Writes Chrome.dll preload settings to the registry.

  Args:
    value: if true, full preloading will be enabled (100%); if false,
        preloading will be disabled (0%); if an integer between 0 and
        100, percentage based pre-loading will be enabled.
  """
  key = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, _CHROME_FRAME_KEY)
  if value is True:
    value = 100
  if value is False:
    value = 0
  _SetDWORDValueImpl(key, _PREREAD_VALUE, None)
  _SetDWORDValueImpl(key, _PREREAD_PERCENTAGE_VALUE, value)


def KillNamedProcesses(process_name):
  """Kills all processes with the given name. Only works on Windows.

  Args:
    process_name: The name of the processes to kill, e.g. "iexplore.exe".
  """
  subprocess.call(['taskkill.exe', '/IM', process_name])
