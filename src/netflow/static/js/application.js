$(document).ready(function(){
    // connect to the socket server (support http/https)
    var socket = io(window.location.protocol + '//' + document.domain + ':' + location.port + '/test');
    socket.on('connect', function(){
        console.log('Socket connected to /test');
    });
    var messages_received = [];
    var currentPage = 1;
    var pageSize = 100;
    var liveMode = true; // live updates only when viewing latest page
    var ctx = document.getElementById("myChart");
    var chartUpdateQueued = false;
    var chartQueuedData = null;
    var logContainer = $('#log');
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
        var messages_string = '<tr><th>Flow ID</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Protocol</th><th>Flow Duration (ms)</th><th>App name</th><th>PID</th><th>Prediction</th><th>Prob</th><th>Risk</th><th>Actions</th></tr>';
        for (var i = 0; i < arr.length; i++) {
            messages_string += '<tr>';
            for (var j = 0; j < arr[i].length; j++) {
                messages_string += '<td>' + arr[i][j].toString() + '</td>';
            }
            messages_string += '<td> <a href="/flow-detail?flow_id=' + arr[i][0].toString() + '"><div>Detail</div></a></td>';
            messages_string += '<td><button class="btn btn-sm btn-primary re-evaluate-btn" data-flow-id="' + arr[i][0].toString() + '">Re-evaluate</button></td>' + '</tr>';
        }
        $('#details').html(messages_string);
    }

    function loadPage(page) {
        liveMode = false;
        $.getJSON('/api/flows', { page_size: pageSize }, function(resp) {
            currentPage = 1; // API now returns latest flows only
            messages_received = resp.data || [];
            rebuildTableFromArray(messages_received);
            // update controls text
            $('#pagination-page').text('Static');
        });
    }

    // Add simple pagination controls
    var controlsHtml = '<div id="pagination-controls" style="margin: 8px 0;">' +
        '<span id="pagination-page">Live</span> ' +
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
        
        // Find and update the flow in messages_received
        for (var i = 0; i < messages_received.length; i++) {
            if (messages_received[i][0] == msg.flow_id) {
                // Update classification (index 9), probability (index 10), and risk (index 11)
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



