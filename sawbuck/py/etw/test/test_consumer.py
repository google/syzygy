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
from etw import TraceEventSource, EventConsumer, EventHandler
from etw.descriptors import image
import exceptions
import os
import unittest


_SRC_DIR = os.path.abspath(os.path.join(__file__, '../../../../..'))

class TraceConsumerTest(unittest.TestCase):
  _TEST_LOG = os.path.normpath(
      os.path.join(_SRC_DIR,
                   'sawbuck/log_lib/test_data/image_data_32_v2.etl'))

  def _Consume(self, log_file, handlers):
    log_consumer = TraceEventSource(handlers)
    log_consumer.OpenFileSession(log_file)
    log_consumer.Consume()

  def testCreation(self):
    """Test creating a consumer."""
    consumer = TraceEventSource()

  def testOpenFileSession(self):
    """Test opening a file session."""
    consumer = TraceEventSource()
    consumer.OpenFileSession(self._TEST_LOG)

  def testConsume(self):
    """Test consuming a test log."""
    class TestConsumer(EventConsumer):
      def __init__(self):
        super(TestConsumer, self).__init__()
        self._image_load_events = 0

      @EventHandler(image.Event.Load)
      def OnImageLoad(self, event_data):
        self._image_load_events += 1

    consumer = TestConsumer()
    self._Consume(self._TEST_LOG, [consumer])
    self.assertNotEqual(consumer._image_load_events, 0)

  def testMultipleConsumers(self):
    """Test two consumers instances."""
    class TestConsumer(EventConsumer):
      def __init__(self):
        super(TestConsumer, self).__init__()
        self._image_load_events = 0

      @EventHandler(image.Event.Load)
      def OnImageLoad(self, event_data):
        self._image_load_events += 1

    consumer1 = TestConsumer()
    consumer2 = TestConsumer()

    self._Consume(self._TEST_LOG, [consumer1, consumer2])

    self.assertNotEqual(consumer1._image_load_events, 0)
    self.assertNotEqual(consumer2._image_load_events, 0)
    self.assertEqual(consumer1._image_load_events, consumer2._image_load_events)

  def testSubConsumers(self):
    """Test multi-level consumer hierarchy."""
    class TestConsumer(EventConsumer):
      def __init__(self):
        super(TestConsumer, self).__init__()
        self._image_load_events = 0

      @EventHandler(image.Event.Load)
      def OnImageLoad(self, event_data):
        self._image_load_events += 1

    class SubTestConsumer(TestConsumer):
      pass

    consumer = SubTestConsumer()
    self._Consume(self._TEST_LOG, [consumer])
    self.assertNotEqual(consumer._image_load_events, 0)

  def testMultipleEvents(self):
    """Test multiple event handlers."""
    class TestConsumer(EventConsumer):
      def __init__(self):
        super(TestConsumer, self).__init__()
        self._image_start_load_events = 0
        self._image_start_events = 0
        self._image_load_events = 0

      @EventHandler(image.Event.Load, image.Event.DCStart)
      def OnImageStartLoad(self, event_data):
        self._image_start_load_events += 1

      @EventHandler(image.Event.Load)
      def OnImageLoad(self, event_data):
        self._image_load_events += 1

      @EventHandler(image.Event.DCStart)
      def OnImageStart(self, event_data):
        self._image_start_events += 1

    consumer = TestConsumer()
    self._Consume(self._TEST_LOG, [consumer])
    self.assertTrue(consumer._image_start_load_events > 10)
    self.assertEquals(consumer._image_load_events +
                      consumer._image_start_events,
                      consumer._image_start_load_events)

  def testThrowFromHandler(self):
    """Test that throwing from a handler terminates processing."""
    class TestConsumer(EventConsumer):
      @EventHandler(image.Event.Load)
      def OnImageStartLoad(self, event_data):
        raise exceptions.RuntimeError("Intentionally throwing")

    consumer = TestConsumer()
    self.assertRaises(exceptions.WindowsError,
                      self._Consume,
                      self._TEST_LOG,
                      [consumer])


if __name__ == '__main__':
  unittest.main()
