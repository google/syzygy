# Copyright 2012 Google Inc. All Rights Reserved.
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
import urlparse
from google.appengine.ext import webapp
from model import client as client_db
from model import metric as metric_db
from model import product as product_db


class MetricHandler(webapp.RequestHandler):
  """A class to handle creating, reading, updating and deleting metrics.

  Handles GET, POST, PUT and DELETE requests for /metrics/<product>/<client>/
  and /metrics/<product>/<client>/<metric>. All functions have the same
  signature, even though they may not use all parameters, so that a single route
  can be used for the handler.
  """

  def get(self, product_id, client_id, metric_id):
    """Responds with information about all metrics or a specific metric.

    /metrics/<product>/<client>
      Responds with a JSON encoded object that contains a list of metric IDs for
      the given product and client
    /metrics/<product>/<client>/<metric>
      Responds with a JSON encoded object of the product ID, client ID, metric
      ID, description and units for the given product, client and metric.

    Args:
      product_id: The product ID.
      client_id: The client ID.
      metric_id: The metric ID. May be empty.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(httplib.NOT_FOUND)
      return

    client = client_db.Client.get_by_key_name(client_id, product)
    if not client:
      self.error(httplib.NOT_FOUND)
      return

    if not metric_id:
      metrics = metric_db.Metric.all()
      metrics.ancestor(client)
      metrics_result = []
      for metric in metrics:
        metrics_result.append({'metric_id': metric.key().name(),
                               'description': metric.description,
                               'units': metric.units})

      result = {'product_id': product.key().name(),
                'client_id': client.key().name(),
                'metrics': metrics_result}
    else:
      metric = metric_db.Metric.get_by_key_name(metric_id, client)
      if not metric:
        self.error(httplib.NOT_FOUND)
        return

      result = {'product_id': product.key().name(),
                'client_id': client.key().name(),
                'metric_id': metric.key().name(),
                'description': metric.description,
                'units': metric.units}

    self.response.headers['Content-Type'] = 'application/json'
    json.dump(result, self.response.out)

  def post(self, product_id, client_id, metric_id):
    """Creates a new metric.

    /metrics/<product>/<client>
      Creates a new metric. The metric ID, description and units should be
      specified in the body of the request.
    /metrics/<product>/<client>/<metric>
      Unused.

    Args:
      product_id: The product ID.
      client_id: The client ID.
      metric_id: The metric ID. Must be empty.
    """
    # Validate input.
    if metric_id:
      self.error(httplib.BAD_REQUEST)
      return
    
    metric_id = self.request.get('metric_id', None)
    description = self.request.get('description', None)
    units = self.request.get('units', None)
    if not metric_id or not description or not units:
      self.error(httplib.BAD_REQUEST)
      return

    # Perform DB lookups.
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(httplib.NOT_FOUND)
      return

    client = client_db.Client.get_by_key_name(client_id, product)
    if not client:
      self.error(httplib.NOT_FOUND)
      return

    # Make sure that this metric ID doesn't already exist.
    metric = metric_db.Metric.get_by_key_name(metric_id, client)
    if metric:
      self.error(httplib.BAD_REQUEST)
      return

    # Creates a new metric.
    metric = metric_db.Metric(key_name=metric_id, parent=client,
                              description=description, units=units)
    metric.put()
    self.response.set_status(httplib.CREATED, message='MetricCreated')

  def put(self, product_id, client_id, metric_id):
    """Updates a metric.

    /metrics/<product>/<client>
      Unused.
    /metrics/<product>/<client>/<metric>
      Updates a metric. The description and units should be specified in the
      body of the request.

    Args:
      product_id: The product ID.
      client_id: The client ID.
      metric_id: The metric ID. Must not be empty.
    """
    # Validate input.
    if not metric_id:
      self.error(httplib.BAD_REQUEST)
      return

    # Appengine bug: parameters in body aren't parsed for PUT requests.
    # http://code.google.com/p/googleappengine/issues/detail?id=170
    params = urlparse.parse_qs(self.request.body)
    description = params.get('description', [None])[0]
    units = params.get('units', [None])[0]
    if not description or not units:
      self.error(httplib.BAD_REQUEST)
      return

    # Perform DB lookups.
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(httplib.NOT_FOUND)
      return

    client = client_db.Client.get_by_key_name(client_id, product)
    if not client:
      self.error(httplib.NOT_FOUND)
      return

    metric = metric_db.Metric.get_by_key_name(metric_id, client)
    if not metric:
      self.error(httplib.NOT_FOUND)
      return

    # Update the metric.
    metric.description = description
    metric.units = units
    metric.put()

  def delete(self, product_id, client_id, metric_id):
    """Deletes a metric.

    /metrics/<product>/<client>
      Unused.
    /metrics/<product>/<client>/<metric>
      Deletes the specified metric.

    Args:
      product_id: The product ID.
      client_id: The client ID.
      metric_id: The metric ID. Must not be empty.
    """
    # Validate input.
    if not metric_id:
      self.error(httplib.BAD_REQUEST)
      return

    # Perform DB lookups.
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(httplib.NOT_FOUND)
      return

    client = client_db.Client.get_by_key_name(client_id, product)
    if not client:
      self.error(httplib.NOT_FOUND)
      return

    metric = metric_db.Metric.get_by_key_name(metric_id, client)
    if not metric:
      self.error(httplib.NOT_FOUND)
      return

    # Delete the metric.
    metric.delete()
