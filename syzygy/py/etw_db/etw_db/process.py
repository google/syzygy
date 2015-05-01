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
"""Provides an event consumer that tracks process and thread events."""
from etw import EventConsumer, EventHandler
import etw.descriptors.process as process
import etw.descriptors.thread as thread


class _Process:
  """Keeps information about a process."""
  def __init__(self, event):
    self.start_time = event.time_stamp
    self.process_id = event.ProcessId
    self.parent_id = event.ParentId
    self.session_id = event.SessionId
    self.image_file_name = event.ImageFileName
    # XP-generated logs don't have the base::CommandLine property,
    # so we use the image file name instead.
    try:
      self.cmd_line = event.CommandLine
    except AttributeError:
      self.cmd_line = self.image_file_name


class ProcessThreadDatabase(EventConsumer):
  """Keeps a database about current processes and threads.

  Sinks process and thread related events to be able to track which process
  a thread belongs with, as well as to return the command line associated
  with a particular process.
  """
  def __init__(self, no_pruning=False):
    """Initializes a new database.

    Args:
      no_pruning: if true, process and thread information is maintained past
          process/thread end events.
    """
    EventConsumer.__init__(self)
    self._no_pruning = no_pruning
    # Processes by id maps from process ID to command line.
    self._processes_by_id = {}
    # Threads by id maps from thread ID to owning process ID.
    self._threads_by_id = {}

  def GetThreadProcessId(self, thread_id):
    """Retrieves the id of the process that a given thread id belongs to.

    Args:
      thread_id: the id of the thread to query.

    Returns:
      The id of the owning process of the queried thread id, or None if
      the information is not available.
    """
    return self._threads_by_id.get(thread_id)

  def GetThreadProcess(self, thread_id):
    """Retrieves information about a thread's process.

    Args:
      thread_id: the id of the thread to query.

    Returns:
      A _Process object containing information about the requested thread's
      owning process, or None if the information is not available.
    """
    process_id = self._threads_by_id.get(thread_id)
    return self.GetProcess(process_id)

  def GetProcess(self, process_id):
    """Retrieves information about a process.

    Args:
      process_id: the id of the process to query.

    Returns:
      A _Process object containing information about the requested process,
      or None if the information is not available.
    """
    return self._processes_by_id.get(process_id)

  @EventHandler(process.Event.DCStart, process.Event.Start)
  def _OnProcessStart(self, event):
    self._processes_by_id[event.ProcessId] = _Process(event)

  @EventHandler(process.Event.DCEnd, process.Event.End)
  def _OnProcessEnd(self, event):
    if not self._no_pruning:
      self._processes_by_id.pop(event.ProcessId, None)

  @EventHandler(thread.Event.DCStart, thread.Event.Start)
  def _OnThreadStart(self, event):
    self._threads_by_id[event.TThreadId] = event.ProcessId

  @EventHandler(thread.Event.DCEnd, thread.Event.End)
  def _OnThreadEnd(self, event):
    if not self._no_pruning:
      self._threads_by_id.pop(event.TThreadId, None)
