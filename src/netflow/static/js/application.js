$(document).ready(function(){
    // Load available models on page load
    loadAvailableModels();
    
    // connect to the socket server (support http/https)
    var socket = io(window.location.protocol + '//' + document.domain + ':' + location.port + '/test');
    socket.on('connect', function(){
        console.log('Socket connected to /test');
    });
    var messages_received = [];
    var currentPage = 1;
    var maxPageSize = 1000;
    var pageSize = 100;
    // Restore liveMode from localStorage, default to true
    var liveMode = localStorage.getItem('liveMode') !== null ? localStorage.getItem('liveMode') === 'true' : true;
    var ctx = document.getElementById("myChart");
    var chartUpdateQueued = false;
    var chartQueuedData = null;
    var logContainer = $('#log');
    
    // Load initial flows on page load
    var initialLoadComplete = false;

    // ======= Model Management Functions =======
    function loadAvailableModels() {
        $.getJSON('/api/models', function(resp) {
            if (resp.success) {
                var dgiMulticlassSelect = $('#dgi-multiclass-model-select');
                var multiclassSelect = $('#multiclass-model-select');
                var dgiAnomalySelect = $('#dgi-anomaly-model-select');

                // Populate DGI Multiclass models
                dgiMulticlassSelect.empty();
                (resp.available_models.dgi_multiclass_models || []).forEach(function(model) {
                    dgiMulticlassSelect.append('<option value="' + model + '">' + model + '</option>');
                });

                // Populate Multiclass (CatBoost) models
                multiclassSelect.empty();
                (resp.available_models.multiclass_models || []).forEach(function(model) {
                    multiclassSelect.append('<option value="' + model + '">' + model + '</option>');
                });

                // Populate DGI Anomaly models
                dgiAnomalySelect.empty();
                (resp.available_models.dgi_anomaly_models || []).forEach(function(model) {
                    dgiAnomalySelect.append('<option value="' + model + '">' + model + '</option>');
                });

                // Set current selections
                if (resp.current_models) {
                    dgiMulticlassSelect.val(resp.current_models.dgi_multiclass_model);
                    multiclassSelect.val(resp.current_models.multiclass_model);
                    dgiAnomalySelect.val(resp.current_models.dgi_anomaly_model);
                }

                // Update display
                updateCurrentModelsDisplay(resp.current_models || {});
            }
        }).fail(function() {
            console.log('Failed to load available models');
        });
    }
    
    function updateCurrentModelsDisplay(currentModels) {
        $('#current-dgi-multiclass-model').text(currentModels.dgi_multiclass_model || '');
        $('#current-multiclass-model').text(currentModels.multiclass_model || '');
        $('#current-dgi-anomaly-model').text(currentModels.dgi_anomaly_model || '');
    }
    
    $('#load-models-btn').on('click', function() {
        var dgiMulticlassModel = $('#dgi-multiclass-model-select').val();
        var multiclassModel = $('#multiclass-model-select').val();
        var dgiAnomalyModel = $('#dgi-anomaly-model-select').val();

        if (!dgiMulticlassModel || !multiclassModel || !dgiAnomalyModel) {
            alert('Please select all models');
            return;
        }

        $(this).prop('disabled', true).text('Loading...');

        $.ajax({
            url: '/api/load-model',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                dgi_multiclass_model: dgiMulticlassModel,
                multiclass_model: multiclassModel,
                dgi_anomaly_model: dgiAnomalyModel
            }),
            success: function(resp) {
                if (resp.success) {
                    updateCurrentModelsDisplay(resp.current_models);
                    alert('Models loaded successfully!');
                } else {
                    alert('Error loading models: ' + (resp.message || resp.error || 'Unknown error'));
                }
            },
            error: function() {
                alert('Failed to load models');
            },
            complete: function() {
                $('#load-models-btn').prop('disabled', false).text('Load Models');
            }
        });
    });
    // ======= End Model Management Functions =======

    // ======= Anomaly Detection Flows Management =======
    var anomalyFlowsLoaded = false;
    var anomalyPredictions = {}; // Store anomaly predictions by flow_id

    $('#upload-anomaly-flows-btn').on('click', function() {
        var fileInput = $('#anomaly-flows-file')[0];
        if (!fileInput.files || fileInput.files.length === 0) {
            alert('Please select a flows CSV file');
            return;
        }

        var maxFlows = parseInt($('#max-flows-input').val()) || 100000;
        var nEstimators = parseInt($('#n-estimators-input').val()) || 50;
        var contamination = parseFloat($('#contamination-input').val()) || 0.01;

        var formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('max_flows', maxFlows);
        formData.append('n_estimators', nEstimators);
        formData.append('contamination', contamination);

        $(this).prop('disabled', true).text('Processing...');
        $('#anomaly-flows-status').text('Uploading and detecting anomalies...');

        $.ajax({
            url: '/api/upload-anomaly-flows',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(resp) {
                if (resp.success) {
                    anomalyFlowsLoaded = true;
                    anomalyPredictions = {}; // Reset predictions
                    $('#anomaly-flows-status').text('Loaded: ' + resp.filename + ' - Model trained on ' + resp.total_flows + ' flows. Predicting anomalies on new flows...');
                    alert('Anomaly detection model loaded!\nTrained on ' + resp.total_flows + ' flows.\n' + (resp.message || 'Ready to detect anomalies on new flows.'));
                    
                    // Refresh the table to show anomaly column
                    if (liveMode) {
                        rebuildTableFromArray(messages_received);
                    }
                } else {
                    alert('Error: ' + (resp.message || resp.error || 'Unknown error'));
                    $('#anomaly-flows-status').text('Error loading file');
                }
            },
            error: function(xhr) {
                var errorMsg = 'Failed to upload and process file';
                try {
                    var resp = JSON.parse(xhr.responseText);
                    errorMsg += ': ' + (resp.error || resp.message || '');
                } catch(e) {}
                alert(errorMsg);
                $('#anomaly-flows-status').text('Error');
            },
            complete: function() {
                $('#upload-anomaly-flows-btn').prop('disabled', false).text('Upload & Detect');
            }
        });
    });
    // ======= End Anomaly Detection Flows Management =======

    var myChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    // 'rgba(255, 99, 132, 0.2)',
                    // 'rgba(54, 162, 235, 0.2)',
                    // 'rgba(255, 206, 86, 0.2)',
                    // 'rgba(75, 192, 192, 0.2)',
                    // 'rgba(153, 102, 255, 0.2)'
                ],
                borderColor: [
                    // 'rgba(255,99,132,1)',
                    // 'rgba(54, 162, 235, 1)',
                    // 'rgba(255, 206, 86, 1)',
                    // 'rgba(75, 192, 192, 1)',
                    // 'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {

                legend: {
                  display: false
                }
              ,
            scales: {
    
                yAxes: [{
                    ticks: {
                        beginAtZero:true
                    }
                }]
            }
        }
    });

    // debounced chart updater to avoid lag when many flows arrive quickly
    function scheduleChartUpdate(ips) {
        chartQueuedData = ips;
        if (chartUpdateQueued) {
            return;
        }
        chartUpdateQueued = true;
        setTimeout(function() {
            // limit bars to the top 20 to keep rendering light
            var maxBars = 20;
            myChart.data.labels = [];
            myChart.data.datasets[0].data = [];
            for (var i = 0; i < Math.min(chartQueuedData.length, maxBars); i++) {
                myChart.data.datasets[0].data.push(chartQueuedData[i].count);
                myChart.data.labels.push(chartQueuedData[i].SourceIP);
            }
            myChart.update(0); // skip animation for faster redraw
            chartQueuedData = null;
            chartUpdateQueued = false;
        }, 200); // small debounce window
    }

    function isAtBottom($el) {
        if (!$el || !$el[0]) {
            return false;
        }
        var node = $el[0];
        return node.scrollHeight - $el.scrollTop() - $el.outerHeight() <= 5;
    }

    function scrollToBottom($el) {
        if ($el && $el[0]) {
            $el.scrollTop($el[0].scrollHeight);
        }
    }
    function rebuildTableFromArray(arr) {
        var messages_string = '<tr><th>Flow ID</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Protocol</th><th>Flow Duration (ms)</th><th>App name</th><th>Anomaly</th><th>Prediction</th><th>Prob</th><th>Risk</th><th>Actions</th></tr>';
        for (var i = 0; i < arr.length; i++) {
            messages_string += '<tr>';
            for (var j = 0; j < arr[i].length; j++) {
                // Replace PID column (index 8) with anomaly prediction if available
                if (j === 8 && anomalyFlowsLoaded) {
                    var flowId = arr[i][0];
                    var anomalyPred = anomalyPredictions[flowId];
                    if (anomalyPred !== undefined) {
                        var anomalyText = anomalyPred === 1 ? '<span style="color: red; font-weight: bold;">Anomaly</span>' : '<span style="color: green;">Normal</span>';
                        messages_string += '<td>' + anomalyText + '</td>';
                    } else {
                        messages_string += '<td>N/A</td>';
                    }
                } else {
                    messages_string += '<td>' + arr[i][j].toString() + '</td>';
                }
            }
            messages_string += '<td> <a href="/flow-detail?flow_id=' + arr[i][0].toString() + '"><div>Detail</div></a></td>';
            messages_string += '<td><button class="btn btn-sm btn-primary re-evaluate-btn" data-flow-id="' + arr[i][0].toString() + '">Re-evaluate</button></td>' + '</tr>';
        }
        $('#details').html(messages_string);
    }

    function loadPage(page) {
        liveMode = false;   
        localStorage.setItem('liveMode', 'false');
        $.getJSON('/api/flows', { page_size: pageSize }, function(resp) {
            currentPage = 1; // API now returns latest flows only
            messages_received = resp.data || [];
            // Load anomaly predictions from response
            if (resp.anomaly_predictions) {
                for (var flowId in resp.anomaly_predictions) {
                    anomalyPredictions[parseInt(flowId)] = resp.anomaly_predictions[flowId];
                }
                // Mark that anomaly predictions are available
                if (Object.keys(resp.anomaly_predictions).length > 0) {
                    anomalyFlowsLoaded = true;
                }
            }
            // Restore anomaly model status
            if (resp.anomaly_model_status && resp.anomaly_model_status.loaded) {
                anomalyFlowsLoaded = true;
                $('#anomaly-flows-status').text('Loaded: ' + resp.anomaly_model_status.filename + 
                    ' - Model trained on ' + resp.anomaly_model_status.total_flows + ' flows. Predicting anomalies on new flows...');
            }
            rebuildTableFromArray(messages_received);
            // update controls text
            $('#pagination-page').text('Static');
            initialLoadComplete = true;
        });
    }
    
    // Load initial data on page load based on liveMode state
    setTimeout(function() {
        if (!liveMode) {
            // If in static mode, load the data
            loadPage(1);
        } else {
            // If in live mode, just load anomaly model status
            $.getJSON('/api/flows', { page_size: 0 }, function(resp) {
                if (resp.anomaly_model_status && resp.anomaly_model_status.loaded) {
                    anomalyFlowsLoaded = true;
                    $('#anomaly-flows-status').text('Loaded: ' + resp.anomaly_model_status.filename + 
                        ' - Model trained on ' + resp.anomaly_model_status.total_flows + ' flows. Predicting anomalies on new flows...');
                }
            });
            $('#pagination-page').text('Live');
        }
        initialLoadComplete = true;
    }, 500);

    // Add simple pagination controls
    var controlsHtml = '<div id="pagination-controls" style="margin: 8px 0;">' +
        '<span id="pagination-page">...</span> ' +
        '<button id="refresh-page" class="btn btn-sm btn-default">Refresh</button> ' +
        '<button id="live-page" class="btn btn-sm btn-primary">Live</button>' +
        '<span style="margin-left: 20px;">Page Size (Max:1000):</span> ' +
        '<input type="number" id="page-size-input" min="1" value="' + pageSize + '" style="width: 80px; margin: 0 5px;"> ' +
        '<button id="set-page-size" class="btn btn-sm btn-info">Set</button> ' +
        '<span style="margin-left: 20px;">Flow Range:</span> ' +
        '<input type="number" id="flow-from" placeholder="From" style="width: 80px; margin: 0 5px;" min="1"> ' +
        '<input type="number" id="flow-to" placeholder="To" style="width: 80px; margin: 0 5px;" min="1"> ' +
        '<button id="load-range-btn" class="btn btn-sm btn-warning">Show Range</button>' +
        '</div>';
    $('#content').prepend(controlsHtml);

    $('#refresh-page').on('click', function() {
        // Refresh the current paginated view
        loadPage(currentPage);
    });
    $('#set-page-size').on('click', function() {
        var newSize = parseInt($('#page-size-input').val());
        if (isNaN(newSize) || newSize <= 0) {
            alert('Please enter a valid page size (> 0)');
            return;
        }
        if (newSize > 1000) {
            alert('Page size too large, max is 1000');
            return;
        }
        pageSize = newSize;
        $('#pagination-page').text('Static (page size ' + pageSize + ')');
    });
    $('#live-page').on('click', function() {
        liveMode = true;
        localStorage.setItem('liveMode', 'true');
        currentPage = 1; // treat live as latest
        rebuildTableFromArray(messages_received);
        $('#pagination-page').text('Live');
    });

    $('#load-range-btn').on('click', function() {
        var fromId = parseInt($('#flow-from').val());
        var toId = parseInt($('#flow-to').val());

        if (isNaN(fromId) || isNaN(toId)) {
            alert('Please enter valid flow IDs for both From and To');
            return;
        }

        if (fromId > toId) {
            alert('From flow ID must be less than or equal to To flow ID');
            return;
        }

        // Filter messages_received to show only flows in the range
        var filteredFlows = messages_received.filter(function(flow) {
            return flow[0] >= fromId && flow[0] <= toId;
        });

        if (filteredFlows.length === 0) {
            alert('No flows found in the specified range');
            return;
        }

        liveMode = false;
        rebuildTableFromArray(filteredFlows);
        $('#pagination-page').text('Range: ' + fromId + ' - ' + toId);
    });

    //receive details from server
    socket.on('newresult', function(msg) {
        if (!liveMode) {
            // Ignore live updates while viewing paginated history
            return;
        }
        // live mode: append and rebuild (unlimited - no size restriction)
        messages_received.push(msg.result);
        
        // Store anomaly prediction if provided
        if (msg.anomaly_pred !== undefined && msg.flow_id !== undefined) {
            anomalyPredictions[msg.flow_id] = msg.anomaly_pred;
        }

        // Trim messages if exceeding maxPageSize (1000)
        if (messages_received.length > maxPageSize) {
            messages_received = messages_received.slice(-maxPageSize);
        }

        var stickToBottom = isAtBottom(logContainer);
        rebuildTableFromArray(messages_received);
        if (stickToBottom) scrollToBottom(logContainer);
        scheduleChartUpdate(msg.ips);
    });

    // Handle re-evaluation button clicks
    $(document).on('click', '.re-evaluate-btn', function() {
        var flowId = $(this).data('flow-id');
        // console.log('Re-evaluating flow: ' + flowId);
        socket.emit('re_evaluate_flow', {flow_id: flowId});
    });

    // Handle re-evaluation results
    socket.on('re_evaluation_result', function(msg) {
        // console.log("Received re-evaluation result for flow " + msg.flow_id);
        
        // Store anomaly prediction if provided
        if (msg.anomaly_pred !== undefined) {
            anomalyPredictions[msg.flow_id] = msg.anomaly_pred;
        }
        
        // Find and update the flow in messages_received
        for (var i = 0; i < messages_received.length; i++) {
            if (messages_received[i][0] == msg.flow_id) {
                // Update anomaly (index 8), classification (index 9), probability (index 10), and risk (index 11)
                if (msg.anomaly_pred !== undefined) {
                    messages_received[i][8] = msg.anomaly_pred;
                }
                messages_received[i][9] = msg.classification;
                messages_received[i][10] = msg.probability;
                messages_received[i][11] = msg.risk;
                break;
            }
        }
        
        // Rebuild the table
        rebuildTableFromArray(messages_received);
    });

});



