/**
 * Copyright 2012 Google Inc. All Rights Reserved.
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
 * @type {Array} The total value of each time stamp loaded from the JSON file.
 * @private
 */
heatmap.total_ = [];

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
  $('#memory-slice-bytes')
      .text('0x' + heatmap.memory_slice_bytes_.toString(16));

  $('#time-slider').slider({
    range: true,
    min: 0,
    max: json['max_time_slice_usecs'] + 1,
    values: [0, 100],
    animate: 'fast',
    slide: function(event, ui) {
      $('#time-slider-min').text(ui.values[0]);
      $('#time-slider-max').text(ui.values[1]);
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
      $('#memory-slider-min').text(ui.values[0]);
      $('#memory-slider-max').text(ui.values[1]);
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
  var max_time_slice = json['max_time_slice_usecs'];
  var max_memory_slice = json['max_memory_slice_bytes'];

  // Push default values for all elements of heatmap.data_ and heatmap.total_.
  heatmap.data_ = [];
  for (var i = 0; i <= max_memory_slice; i++) {
    heatmap.data_.push([]);
    for (var u = 0; u <= max_time_slice; u++) {
      heatmap.data_[i].push({y: i, x: u, value: 0, functions: []});
    }
  }

  for (var i = 0; i <= max_time_slice; i++) {
    heatmap.total_[i] = 0;
  }

  // Copy the json data to those elements.
  for (var i in json['time_slice_list']) {
    var time_slice = json['time_slice_list'][i];
    var timestamp = time_slice['timestamp'];

    heatmap.total_[timestamp] = time_slice['total_memory_slices'];

    if (timestamp >= max_time_slice)
      continue;

    for (var u in time_slice['memory_slice_list']) {
      var memory_slice = time_slice['memory_slice_list'][u];
      var slice_id = memory_slice['memory_slice'];

      if (slice_id >= max_memory_slice)
        continue;

      heatmap.data_[slice_id][timestamp]['value'] = memory_slice['quantity'];
      heatmap.data_[slice_id][timestamp]['functions'] =
          memory_slice['functions'];
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

  // Remove the heatmap, if there's one.
  d3.select('#heatmap').select('svg').remove();
  d3.select('#time-summary').select('svg').remove();

  // The elements from heatmap.data_ that are in the time/memory range, and have
  // a nonzero value.
  var map = [];

  // The sum of the values of each time slice in the current zoom, each time
  // slice in the whole heat map, all the time/memory slices in the current
  // zoom, or all the time/memory slices in the whole heat map, depending on the
  // value of the checkboxes.
  var total_slices = [];
  var max_slice = 0;
  var sum_slices = 0;
  for (var i = 0; i < time_slice_range; i++)
    total_slices[i] = 0;

  // Load the nonzero values of data between the given time and memory slices.
  for (var i = min_memory_slice; i < max_memory_slice; i++) {
    for (var u = min_time_slice; u < max_time_slice; u++) {
      var slice = u - min_time_slice;
      if (heatmap.data_[i][u].value > 0)
        map.push(heatmap.data_[i][u]);

      if ($('#relative-selected-time-slices').is(':checked')) {
        total_slices[slice] += heatmap.data_[i][u].value;
        sum_slices += heatmap.data_[i][u].value;
      } else if (i == min_memory_slice) {
        total_slices[slice] += heatmap.total_[u];
        sum_slices += heatmap.total_[u];
      }

      max_slice = Math.max(max_slice, total_slices[slice]);
    }
  }

  // The background color of the heat maps.
  var background_color = '#fffffb';

  // Calculate an appropiate size for the heat map, so that it fits in a
  // max_width x max_height rectangle, and all the slices are square.
  var max_width = 1600;
  var max_height = 750;

  var width = max_width;
  var height = width / time_slice_range * memory_slice_range;

  if (height > max_height) {
    height = max_height;
    width = height / memory_slice_range * time_slice_range;
  }

  // Put the information about the functions in a new line if they don't fit
  // easily in the screen.
  if (3 * width > 2 * screen.width) {
    $('#functions').css('width', screen.width);
    $('#functions').css('clear', 'left');
  } else {
    $('#functions').css('width', screen.width - width - 40 + 'px');
    $('#functions').css('clear', '');
  }

  // Create the time summary heat map.
  var time_summary_height = Math.max(7.5, height / memory_slice_range);
  var time_summary = d3.select('#time-summary').append('svg:svg');
  time_summary.attr('width', width).attr('height', time_summary_height);

  var rect = time_summary.selectAll('rect').data(total_slices).enter()
      .append('svg:rect');
  rect.attr('x', function(d, i) { return i * (width / time_slice_range); });
  rect.attr('y', 0);
  rect.attr('color', function(d, i) {
    var color = d3.interpolateRgb('#fff', '#000');
    if (total_slices[i] == 0) return '#fffffb';
    return color(total_slices[i] / max_slice);
  });
  rect.attr('width', width / time_slice_range);
  rect.attr('height', time_summary_height);

  // Create the svg heat map, and make the information on the current
  // time/memory slice change if the user mouses over one with a value of zero.
  var graphic = d3.select('#heatmap').append('svg:svg');
  graphic.attr('width', width).attr('height', height);
  graphic.style('background-color', background_color);

  graphic.on('mousemove', function(d, i) {
    var mouse = d3.mouse(this);
    var time_slice = Math.floor(mouse[0] * time_slice_range / width);
    var memory_slice = Math.floor(mouse[1] * memory_slice_range / height);

    time_slice = time_slice + min_time_slice;
    memory_slice = memory_slice + min_memory_slice;

    $('#time').text(time_slice * heatmap.time_slice_usecs_);
    $('#memory').text(
        '0x' + (memory_slice * heatmap.memory_slice_bytes_).toString(16));

    if ($('#functions').text() == '' || $('#value').text() == '?') {
      $('#value').text('0 / ' + total_slices[time_slice - min_time_slice]);
      $('#functions').html('');
    }
  });

  // Create rectangles for the slices with nonzero value.
  rect = graphic.selectAll('rect').data(map).enter().append('svg:rect');
  rect.attr('x', function(d, i) {
    return (d.x - min_time_slice) * (width / time_slice_range);
  });
  rect.attr('y', function(d, i) {
    return (d.y - min_memory_slice) * (height / memory_slice_range);
  });
  rect.attr('color', function(d, i) {
    if (total_slices[d.x - min_time_slice] == 0)
      return '#fffffb';

    var total = 0;
    if ($('#relative-same-time-slice').is(':checked'))
      total = total_slices[d.x - min_time_slice];
    else
      total = sum_slices;

    var color = d3.interpolateRgb('#fff', '#000');
    return color(Math.pow(d.value / total, 3/16));
  });
  rect.attr('width', width / time_slice_range);
  rect.attr('height', height / memory_slice_range);
  rect.on('mouseover', function(d, i) {
    var total = 0;
    if ($('#relative-same-time-slice').is(':checked'))
      total = total_slices[d.x - min_time_slice];
    else
      total = sum_slices;
    $('#value').text(d.value + ' / ' + total);
    this.setAttribute('style', 'stroke:#f00');

    var function_text = '';
    if (d.functions[0] == undefined) {
      function_text = '?';
    } else {
      for (var i = 0; i < d.functions.length; i++) {
        function_text += '<div class="container">' +
            '<div class="data">' + d.functions[i]['quantity'] + '</div>' +
            '<div class="text">' + d.functions[i]['name'] + '</div>' +
            '</div>';
      }
    }

    $('#functions').html(function_text);
  });
  rect.on('mouseout', function(d, i) {
    $('#value').text('?');
    this.setAttribute('style', 'stroke:currentColor');
  });

  // Make everything visible.
  $('#drawing-heatmap').css('display', 'none');
  $('#heatmap-body').css('display', 'block');
};

$(document).ready(function() {
  $('#file-select').change(heatmap.Init);
  $('#refresh-heat-map').click(heatmap.UpdateHeatMap);
});
