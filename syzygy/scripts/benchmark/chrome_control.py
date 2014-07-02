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
"""A utility module for controlling Chrome instances."""
import exceptions
import json
import logging
import os
import pywintypes
import shutil
import subprocess
import tempfile
import win32api
import win32con
import win32event
import win32gui
import win32process
import winerror
import _winreg


_LOGGER = logging.getLogger(__name__)


# Enumeration of Chrome startup types we support.
STARTUP_NEW_TAB_PAGE = 'new-tab-page'
STARTUP_HOMEPAGE = 'homepage'
STARTUP_MULTIPAGE = 'multipage'
STARTUP_RESTORE_SESSION = 'restore-session'
ALL_STARTUP_TYPES = (STARTUP_NEW_TAB_PAGE,
                     STARTUP_HOMEPAGE,
                     STARTUP_MULTIPAGE,
                     STARTUP_RESTORE_SESSION)
DEFAULT_STARTUP_TYPE = STARTUP_NEW_TAB_PAGE


class ChromeNotFoundException(Exception):
  pass


class TimeoutException(Exception):
  pass


_MESSAGE_WINDOW_CLASS = 'Chrome_MessageWindow'
_WIDGET_WINDOW_BASE_CLASS = 'Chrome_WidgetWin_'


def _FindProfileWindow(profile_dir):
  """Find the message window associated with profile_dir, if any."""
  profile_dir = os.path.abspath(profile_dir)

  try:
    return win32gui.FindWindowEx(None,
                                 None,
                                 _MESSAGE_WINDOW_CLASS,
                                 profile_dir)
  # This type is not found by the static analysis that pylint performs.
  # pylint: disable=E1101
  except pywintypes.error:
    # On Windows 7, FindWindowEx returns None without raising an error.
    # On older versions, it raises a FILE_NOT_FOUND error.
    return None


def ShutDown(profile_dir, timeout_ms=win32event.INFINITE):
  """Shuts down the Chrome instance running in profile_dir.

  Uses taskkill.exe to shut down the running Chrome instance attached to the
  given profile directory.

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
  _LOGGER.info('Found Chrome window with TID=%d PID=%d.', thread_id, process_id)

  # Open the process in question, so we can wait for it to exit.
  permissions = win32con.SYNCHRONIZE | win32con.PROCESS_QUERY_INFORMATION
  process_handle = win32api.OpenProcess(permissions, False, process_id)

  # Loop around to periodically retry to close Chrome.
  while True:
    _LOGGER.info('Killing Chrome with PID=%d.', process_id)

    with open(os.devnull, 'w') as f:
      subprocess.call(['taskkill.exe', '/PID', str(process_id)],
                      stdout=f, stderr=f)

    # Wait for the process to exit and get its exit status.
    curr_timeout_ms = 2000
    if timeout_ms != win32event.INFINITE:
      if timeout_ms < curr_timeout_ms:
        curr_timeout_ms = timeout_ms

      timeout_ms -= curr_timeout_ms

    _LOGGER.info('Waiting for Chrome PID=%d to exit.', process_id)
    result = win32event.WaitForSingleObject(process_handle, curr_timeout_ms)
    # Exit the loop on successful wait.
    if result == win32event.WAIT_OBJECT_0:
      break

    # Did we time out?
    if timeout_ms == 0:
      _LOGGER.error('Time-out waiting for Chrome process to exit.')
      raise TimeoutException

  exit_status = win32process.GetExitCodeProcess(process_handle)
  process_handle.Close()
  _LOGGER.info('Chrome exited with status %d.', exit_status)

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
    (value, dummy_value_type) = _winreg.QueryValueEx(key, name)
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
  elif value is False:
    value = 0
  _SetDWORDValueImpl(key, _PREREAD_PERCENTAGE_VALUE, value)
  if value is not None:
    value = 1 if value == 100 else 0
  _SetDWORDValueImpl(key, _PREREAD_VALUE, value)


def KillNamedProcesses(process_name):
  """Kills all processes with the given name. Only works on Windows.

  Args:
    process_name: The name of the processes to kill, e.g. "iexplore.exe".
  """
  subprocess.call(['taskkill.exe', '/IM', process_name])


def _GetPreferencesFile(profile_dir):
  """ Returns the path to the preferences file stored in the chrome profile
  given by @profile_dir.

  Args:
    profile_dir: The root directory where the profile is stored. There must
        be an existing profile in @p profile_dir.
  """
  return os.path.join(profile_dir, 'Default', 'Preferences')


def _LoadPreferences(profile_dir):
  """Loads the preferences from chrome profile stored in @p profile_dir.

  Args:
    profile_dir: The root directory where the profile is stored. There must
        be an existing profile in @p profile_dir.
  """
  _LOGGER.info('Reading preferences from "%s".', profile_dir)
  with open(_GetPreferencesFile(profile_dir)) as f:
    return json.load(f)


def _SavePreferences(profile_dir, prefs_dict):
  """Saves the preferences given by @prefs_dict to the chrome profile stored
  in @p profile_dir.

  Args:
    profile_dir: The root directory where the profile is stored. There must
        be an existing profile in @p profile_dir.
    prefs_dict: A dictionary of chrome preferences.
  """
  _LOGGER.info('Saving preferences to "%s".', profile_dir)
  preferences = _GetPreferencesFile(profile_dir)
  fd, new_preferences = tempfile.mkstemp(dir=os.path.dirname(preferences))
  try:
    with os.fdopen(fd, "w") as f:
      json.dump(prefs_dict, f, indent=2)
    if os.path.exists(preferences):
      os.remove(preferences)
    shutil.move(new_preferences, preferences)
  except:
    _LOGGER.exception('Failed to save preferences to "%s".', profile_dir)
    os.remove(new_preferences)
    raise


def _ConfigureStartupNewTabPage(prefs_dict, _unused):
  """Updates @p prefs_dict to start at the "New Tab Page" on startup.

  Args:
    prefs_dict: The current dictionary of chrome preferences.
  """
  prefs_dict['homepage_changed'] = True
  prefs_dict['homepage_is_newtabpage'] = True
  prefs_dict.setdefault('session', {})['restore_on_startup'] = 5


def _ConfigureStartupHomepage(prefs_dict, url_list):
  """Updates @p prefs_dict to open the given @p url as its homepage on startup.

  Args:
    prefs_dict: The current dictionary of chrome preferences.
    url_list: The list of URLs to open on startup.
  """
  assert url_list
  prefs_dict['homepage'] = url_list[0]
  prefs_dict['homepage_changed'] = True
  prefs_dict['homepage_is_newtabpage'] = False
  prefs_dict.setdefault('session', {})['restore_on_startup'] = 0


def _ConfigureStartupMultipage(prefs_dict, url_list):
  """Updates @p prefs_dict to open each url in @p url_list on startup.

  Args:
    prefs_dict: The current dictionary of chrome preferences.
    url_list: The list of URLs to open on startup.
  """
  assert url_list
  session_dict = prefs_dict.setdefault('session', {})
  prefs_dict['homepage_is_newtabpage'] = False
  session_dict['restore_on_startup'] = 4
  session_dict['urls_to_restore_on_startup'] = url_list


def _ConfigureStartupRestoreSession(prefs_dict, _unused):
  """Updates @p prefs_dict to restore the previous session on startup.

  Args:
    prefs_dict: The current dictionary of chrome preferences.
  """
  prefs_dict['homepage_is_newtabpage'] = False
  session_dict = prefs_dict.setdefault('session', {})
  session_dict['restore_on_startup'] = 1


_STARTUP_CONFIG_FUNCS = {
  STARTUP_NEW_TAB_PAGE : _ConfigureStartupNewTabPage,
  STARTUP_HOMEPAGE : _ConfigureStartupHomepage,
  STARTUP_MULTIPAGE : _ConfigureStartupMultipage,
  STARTUP_RESTORE_SESSION: _ConfigureStartupRestoreSession,
}


def ConfigureStartup(profile_dir, startup_type, startup_urls):
  """Configures Chrome to open the given @p url as its homepage on startup.

  For @p startup_type == STARTUP_RESTORE_SESSION, you must separately launch
  Chrome with the URLs you wish to start. This function will only enable the
  session restoration feature, not initialize the session.

  Args:
    profile_dir: The root directory where the profile is stored. There must
        be an existing profile in @p profile_dir.
    startup_type: The startup scenario to be configured. This must be one
        of the values in ALL_STARTUP_TYPES.
    startup_urls: The list of URLs to open on startup. This may be empty or
        None iff @p startup_type is STARTUP_NEW_TAB_PAGE or
        STARTUP_RESTORE_SESSION.
  """
  assert startup_urls is None or isinstance(startup_urls, (list, tuple))
  prefs_dict = _LoadPreferences(profile_dir)
  if 'backup' in prefs_dict:
    del prefs_dict['backup']
  _STARTUP_CONFIG_FUNCS[startup_type](prefs_dict, startup_urls)
  _SavePreferences(profile_dir, prefs_dict)
