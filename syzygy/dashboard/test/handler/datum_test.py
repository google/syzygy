#!python
# Copyright 2012 Google Inc.
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

import httplib
import json
import time
from handler import datum
from model import client as client_db
from model import datum as datum_db
from model import metric as metric_db
from model import product as product_db
from test.handler import handler_test

# TODO(ericdingle): Test timestamp filtering which would require figuring
# out how to write timestamps to the data store.

class DatumTest(handler_test.TestCase):

  def setUp(self):
    super(DatumTest, self,).setUp()

    # Insert values into the db.
    p1 = product_db.Product(key_name='p1')
    p1.put()

    c1 = client_db.Client(key_name='c1', parent=p1, description='c1_desc')
    c1.put()

    m1 = metric_db.Metric(key_name='m1', parent=c1, description='m1_desc',
                          units='stones')
    m1.put()

    self._d1 = datum_db.Datum(parent=m1, product_version='d1_prod_ver',
                              toolchain_version='d1_tool_ver',
                              values=[1.0, 2.0])
    self._d1.put()

    self._d2 = datum_db.Datum(parent=m1, product_version='d2_prod_ver',
                              toolchain_version='d2_tool_ver',
                              values=[3.0, 4.0])
    self._d2.put()

  def _InitHandler(self, input):
    self._handler = datum.DatumHandler()
    super(DatumTest, self)._InitHandler(self._handler, input)

  def testGetAll(self):
    self._InitHandler('')
    self._handler.get('p1', 'c1', 'm1', '')
    self.assertEqual(httplib.OK, self._response.status)

    result = json.loads(self._response.out.getvalue())
    self.assertEqual(
        {'product_id': 'p1',
         'client_id': 'c1',
         'metric_id': 'm1',
         'data': [
            {'datum_id': self._d1.key().id(),
             'product_version': 'd1_prod_ver',
             'toolchain_version': 'd1_tool_ver',
             'timestamp': self._d1.timestamp.strftime(
                datum.DatumHandler._TIMESTAMP_FORMAT),
             'values': [1.0, 2.0]},
            {'datum_id': self._d2.key().id(),
             'product_version': 'd2_prod_ver',
             'toolchain_version': 'd2_tool_ver',
             'timestamp': self._d2.timestamp.strftime(
                datum.DatumHandler._TIMESTAMP_FORMAT),
             'values': [3.0, 4.0]}
        ]},
        result)

  def testGetById(self):
    self._InitHandler('')
    self._handler.get('p1', 'c1', 'm1', self._d1.key().id())
    self.assertEqual(httplib.OK, self._response.status)

    result = json.loads(self._response.out.getvalue())
    self.assertEqual(
        {'product_id': 'p1',
         'client_id': 'c1',
         'metric_id': 'm1',
         'datum_id': self._d1.key().id(),
         'product_version': 'd1_prod_ver',
         'toolchain_version': 'd1_tool_ver',
         'timestamp': self._d1.timestamp.strftime(
            datum.DatumHandler._TIMESTAMP_FORMAT),
         'values': [1.0, 2.0]},
        result)

  def testGetArgValidation(self):
    # Invalid start time.
    self._InitHandler('start_time=blah')
    self._handler.get('p1', 'c1', 'm1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Invalid end time.
    self._InitHandler('end_time=blah')
    self._handler.get('p1', 'c1', 'm1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Non-existing product ID.
    self._InitHandler('')
    self._handler.get('p2', 'c1', 'm1', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing client ID.
    self._InitHandler('')
    self._handler.get('p1', 'c2', 'm1', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing metric ID.
    self._InitHandler('')
    self._handler.get('p1', 'c1', 'm2', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Invalid datum ID.
    self._InitHandler('')
    self._handler.get('p1', 'c1', 'm1', 'a')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # None-existing datum ID.
    self._InitHandler('')
    self._handler.get('p1', 'c1', 'm1', '1234567890')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

  def testPost(self):
    self._InitHandler('product_version=d3_prod_ver&'
                      'toolchain_version=d3_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.post('p1', 'c1', 'm1', '')
    self.assertEqual(httplib.CREATED, self._response.status)

    result = json.loads(self._response.out.getvalue())
    d3_id = result.get('datum_id')

    p1 = product_db.Product.get_by_key_name('p1')
    c1 = client_db.Client.get_by_key_name('c1', p1)
    m1 = metric_db.Metric.get_by_key_name('m1', c1)
    d3 = datum_db.Datum.get_by_id(d3_id, m1)
    self.assertTrue(d3 is not None)
    self.assertEqual('d3_prod_ver', d3.product_version)
    self.assertEqual('d3_tool_ver', d3.toolchain_version)
    self.assertEqual([5.0, 6.0], d3.values)

  def testPostArgValidation(self):
    # Datum ID in URL.
    self._InitHandler('product_version=d3_prod_ver&'
                      'toolchain_version=d3_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.post('p1', 'c1', 'm1', 'd3')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Product version missing from body.
    self._InitHandler('toolchain_version=d3_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.post('p1', 'c1', 'm1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Toolchain version missing from body.
    self._InitHandler('product_version=d3_prod_ver&'
                      'values=5.0&values=6.0')
    self._handler.post('p1', 'c1', 'm1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Values missing from body.
    self._InitHandler('product_version=d3_prod_ver&'
                      'toolchain_version=d3_tool_ver&')
    self._handler.post('p1', 'c1', 'm1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Invalid values.
    self._InitHandler('product_version=d3_prod_ver&'
                      'toolchain_version=d3_tool_ver&'
                      'values=5.0&values=A')
    self._handler.post('p1', 'c1', 'm1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Non-existing product ID.
    self._InitHandler('product_version=d3_prod_ver&'
                      'toolchain_version=d3_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.post('p2', 'c1', 'm1', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing client ID.
    self._InitHandler('product_version=d3_prod_ver&'
                      'toolchain_version=d3_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.post('p1', 'c2', 'm1', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing metric ID.
    self._InitHandler('product_version=d3_prod_ver&'
                      'toolchain_version=d3_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.post('p1', 'c1', 'm2', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

  def testPut(self):
    self._InitHandler('product_version=new_d1_prod_ver&'
                      'toolchain_version=new_d1_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.put('p1', 'c1', 'm1', self._d1.key().id())
    self.assertEqual(httplib.OK, self._response.status)

    p1 = product_db.Product.get_by_key_name('p1')
    c1 = client_db.Client.get_by_key_name('c1', p1)
    m1 = metric_db.Metric.get_by_key_name('m1', c1)
    d1 = datum_db.Datum.get_by_id(self._d1.key().id(), m1)
    self.assertEqual('new_d1_prod_ver', d1.product_version)
    self.assertEqual('new_d1_tool_ver', d1.toolchain_version)
    self.assertEqual([5.0, 6.0], d1.values)

  def testPutArgValidation(self):
    # Datum ID missing from URL.
    self._InitHandler('product_version=new_d1_prod_ver&'
                      'toolchain_version=new_d1_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.put('p1', 'c1', 'm1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Invalid datum ID.
    self._InitHandler('product_version=new_d1_prod_ver&'
                      'toolchain_version=new_d1_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.put('p1', 'c1', 'm1', 'a')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Product version missing from body.
    self._InitHandler('toolchain_version=new_d1_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.put('p1', 'c1', 'm1', self._d1.key().id())
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Toolchain version missing from body.
    self._InitHandler('product_version=new_d1_prod_ver&'
                      'values=5.0&values=6.0')
    self._handler.put('p1', 'c1', 'm1', self._d1.key().id())
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Values missing from body.
    self._InitHandler('product_version=new_d1_prod_ver&'
                      'toolchain_version=new_d1_tool_ver&')
    self._handler.put('p1', 'c1', 'm1', self._d1.key().id())
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Invalid values.
    self._InitHandler('product_version=new_d1_prod_ver&'
                      'toolchain_version=new_d1_tool_ver&'
                      'values=5.0&values=a')
    self._handler.put('p1', 'c1', 'm1', self._d1.key().id())
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Non-existing product ID.
    self._InitHandler('product_version=new_d1_prod_ver&'
                      'toolchain_version=new_d1_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.put('p2', 'c1', 'm1', self._d1.key().id())
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing client ID.
    self._InitHandler('product_version=new_d1_prod_ver&'
                      'toolchain_version=new_d1_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.put('p1', 'c2', 'm1', self._d1.key().id())
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing metric ID.
    self._InitHandler('product_version=new_d1_prod_ver&'
                      'toolchain_version=new_d1_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.put('p1', 'c1', 'm2', self._d1.key().id())
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing datum ID.
    self._InitHandler('product_version=new_d1_prod_ver&'
                      'toolchain_version=new_d1_tool_ver&'
                      'values=5.0&values=6.0')
    self._handler.put('p1', 'c1', 'm1', '1234567890')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

  def testDelete(self):
    self._InitHandler('')
    self._handler.delete('p1', 'c1', 'm1', self._d1.key().id())
    self.assertEqual(httplib.OK, self._response.status)

    p1 = product_db.Product.get_by_key_name('p1')
    c1 = client_db.Client.get_by_key_name('c1', p1)
    m1 = metric_db.Metric.get_by_key_name('m1', c1)
    self.assertTrue(datum_db.Datum.get_by_id(self._d1.key().id(), m1) is None)

  def testDeleteArgValidation(self):
    # Datum ID missing from URL.
    self._InitHandler('')
    self._handler.delete('p1', 'c1', 'm1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Invalid datum ID.
    self._InitHandler('')
    self._handler.delete('p1', 'c1', 'm1', 'a')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Non-existing product ID.
    self._InitHandler('')
    self._handler.delete('p2', 'c1', 'm1', self._d1.key().id())
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing client ID.
    self._InitHandler('')
    self._handler.delete('p1', 'c2', 'm1', self._d1.key().id())
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing metric ID.
    self._InitHandler('')
    self._handler.delete('p1', 'c1', 'm2', self._d1.key().id())
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing datum ID.
    self._InitHandler('')
    self._handler.delete('p1', 'c1', 'm1', '1234567890')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)
