#!python
# Copyright 2011 Google Inc. All Rights Reserved.
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
"""Provides an event consumer that tracks file events."""
from etw import EventConsumer, EventHandler
import etw.descriptors.fileio as fileio


class FileNameDatabase(EventConsumer):
  """Keeps a database on file object to file name mappings."""
  def __init__(self):
    EventConsumer.__init__(self)
    # Maps from file object to file name.
    self._file_objects = {}

  def GetFileName(self, file_object):
    """Retrieve the file name associated with a file object.

    Args:
      file_object: the file object of interest.

    Returns:
      The name associated with file_object, or None if no information
      is available.
    """
    return self._file_objects.get(file_object)

  @EventHandler(fileio.Event.FileRundown,
                fileio.Event.Name)
  def _OnFileOpen(self, event):
    self._file_objects[event.FileObject] = event.FileName

  @EventHandler(fileio.Event.Close)
  def _OnFileClose(self, event):
    self._file_objects.pop(event.FileObject, None)
