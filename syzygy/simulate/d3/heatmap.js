/**
 * @license Copyright 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The global heatmap namespace object.
 */
var heatmap = {};

/**
 * @type {Array} The heat map data loaded from the JSON file by LoadData_.
 * @private
 */
heatmap.data_ = [];

/**
 * @type {number} The size of each time slice, in microseconds.
 * @private
 */
heatmap.time_slice_usecs_ = 0;

/**
 * @type {number} The size of each memory slice, in bytes.
 * @private
 */
heatmap.memory_slice_bytes_ = 0;

/**
 * Update the DOM elements that indicating that the heat map is being drawn, and
 * call GenerateHeatMap.
 */
heatmap.UpdateHeatMap = function() {
  $('#heatmap-data-container').css('display', 'block');
  $('#drawing-heatmap').css('display', 'block');
  $('#heatmap-body').css('display', 'none');

  // Make a 100 millisecond pause before executing the rest of the function, so
  // the 'loading' DOM elements are redrawn.
  window.setTimeout(heatmap.GenerateHeatMap_, 100);
};

/**
 * Start loading the given JSON file, and call LoadJSONData when done.
 */
heatmap.Init = function() {
  file = $('#file-select').val().slice(12);
  $('#body-container').css('display', 'block');
  $('#loading-json').css('display', 'block').text('Loading ' + file + ' ...');
  $('#main-body').css('display', 'none');
  $('#heatmap-data-container').css('display', 'none');

  d3.json(file, heatmap.LoadJSONData_);
};

/**
 * Create the time/memory sliders using data provided by the JSON file, and call
 * LoadData to parse the rest of it.
 * @param {Object} json The JSON data parsed by d3.json.
 * @private
 */
heatmap.LoadJSONData_ = function(json) {
  $('#loading-json').css('display', 'none');
  $('#main-body').css('display', 'block');

  heatmap.time_slice_usecs_ = json['time_slice_usecs'];
  heatmap.memory_slice_bytes_ = json['memory_slice_bytes'];
  $('#time-slice-usecs').text(heatmap.time_slice_usecs_);
  $('#memory-slice-bytes').text(heatmap.memory_slice_bytes_);

  $('#time-slider').slider({
    range: true,
    min: 0,
    max: json['max_time_slice_usecs'] + 1,
    values: [0, 100],
    animate: 'fast',
    slide: function(event, ui) {
      $('#time-slider-min').text($('#time-slider').slider('values')[0]);
      $('#time-slider-max').text($('#time-slider').slider('values')[1]);
    }
  });
  $('#time-slider-min').text($('#time-slider').slider('values')[0]);
  $('#time-slider-max').text($('#time-slider').slider('values')[1]);

  $('#memory-slider').slider({
    range: true,
    min: 0,
    max: json['max_memory_slice_bytes'] + 1,
    values: [0, 100],
    animate: 'fast',
    slide: function(event, ui) {
      $('#memory-slider-min').text($('#memory-slider').slider('values')[0]);
      $('#memory-slider-max').text($('#memory-slider').slider('values')[1]);
    }
  });
  $('#memory-slider-min').text($('#memory-slider').slider('values')[0]);
  $('#memory-slider-max').text($('#memory-slider').slider('values')[1]);

  heatmap.LoadData_(json);
};

/**
 * Dump the parsed JSON data and put it into heatmap.data
 * @param {Object} json The JSON data parsed by d3.json.
 * @private
 */
heatmap.LoadData_ = function(json) {
  var max_time_slice = json["max_time_slice_usecs"];
  var max_memory_slice = json["max_memory_slice_bytes"];

  heatmap.data = [];
  for (var i = 0; i <= max_memory_slice; i++) {
    heatmap.data.push([]);
    for (var u = 0; u <= max_time_slice; u++) {
      heatmap.data[i].push({y: i, x: u, value: 0});
    }
  }

  for (var i in json['time_slice_list']) {
    var time_slice = json['time_slice_list'][i];
    var timestamp = time_slice['timestamp'];

    if (timestamp >= max_time_slice)
      continue;

    for (var u in time_slice['memory_slice_list']) {
      var memory_slice = time_slice['memory_slice_list'][u];
      var slice_id = memory_slice['memory_slice'];

      if (slice_id >= max_memory_slice)
        continue;

      heatmap.data[slice_id][timestamp]['value'] = memory_slice['quantity'];
    }
  }
};

/**
 * Draw the heat map with the given data.
 * @private
 */
heatmap.GenerateHeatMap_ = function() {
  var min_time_slice = $('#time-slider').slider('values')[0];
  var max_time_slice = $('#time-slider').slider('values')[1];
  var time_slice_range = max_time_slice - min_time_slice;

  var min_memory_slice = $('#memory-slider').slider('values')[0];
  var max_memory_slice = $('#memory-slider').slider('values')[1];
  var memory_slice_range = max_memory_slice - min_memory_slice;

  d3.select('#heatmap').select('svg').remove();

  var map = heatmap.data.slice(min_memory_slice, max_memory_slice);
  for (var i = 0; i < memory_slice_range; i++)
    map[i] = map[i].slice(min_time_slice, max_time_slice);

  var total_slices = [];
  for (var i = 0; i < time_slice_range; i++) {
    total_slices[i] = 0;

    for (var u = 0; u < memory_slice_range; u++)
      total_slices[i] += map[u][i]['value'];
  }

  var width = 1500;
  var height = width / time_slice_range * memory_slice_range;

  if (height > 750) {
    height = 750;
    width = height / memory_slice_range * time_slice_range;
  }

  var graphic = d3.select('#heatmap').append('svg:svg')
    .attr('width', width).attr('height', height)

  graphic.selectAll('g').data(map).enter().append('svg:g')
      .selectAll('rect').data(function(d) {
        return d;
      })
      .enter().append('svg:rect')
      .attr('x', function(d, i) {
        return (d.x - min_time_slice) * (width / time_slice_range);
      })
      .attr('y', function(d, i) {
        return (d.y - min_memory_slice) * (height / memory_slice_range);
      })
      .attr('color', function(d, i) {
        if (total_slices[d.x - min_time_slice] == 0)
          return "#fffffb";

        var color = d3.interpolateRgb('#fff', '#000');
        return color(d.value / total_slices[d.x - min_time_slice]);
      })
      .attr('width', width / time_slice_range)
      .attr('height', height / memory_slice_range)
      .on('mouseover', function(d, i) {
        $('#time').text(d.y * heatmap.time_slice_usecs_);
        $('#memory').text((d.x * heatmap.memory_slice_bytes_).toString(16));
        $('#value').text(d.value);
        this.setAttribute('style', 'stroke:#f00');
      })
      .on('mouseout', function(d, i) {
        this.setAttribute('style', 'stroke:currentColor');
      });

  $('#drawing-heatmap').css('display', 'none');
  $('#heatmap-body').css('display', 'block');
};

$(document).ready(function() {
  $('#file-select').change(heatmap.Init);
  $('#refresh-heat-map').click(heatmap.UpdateHeatMap);
});
