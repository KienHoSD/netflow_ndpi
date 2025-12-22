$(document).ready(function(){
    // connect to the socket server (support http/https)
    var socket = io(window.location.protocol + '//' + document.domain + ':' + location.port + '/test');
    socket.on('connect', function(){
        console.log('Socket connected to /test');
    });
    var messages_received = [];
    var currentPage = 1;
    var pageSize = 1000;
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
        }, 2000); // small debounce window
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
        $.getJSON('/api/flows', { page: page, page_size: pageSize }, function(resp) {
            currentPage = resp.page;
            messages_received = resp.data || [];
            rebuildTableFromArray(messages_received);
            // update controls text
            $('#pagination-page').text('Page ' + resp.page + ' / ' + resp.total_pages);
        });
    }

    // Add simple pagination controls
    var controlsHtml = '<div id="pagination-controls" style="margin: 8px 0;">' +
        '<button id="prev-page" class="btn btn-sm btn-default">Prev</button> ' +
        '<span id="pagination-page">Page 1</span> ' +
        '<button id="next-page" class="btn btn-sm btn-default">Next</button> ' +
        '<button id="live-page" class="btn btn-sm btn-primary">Live</button>' +
        '</div>';
    $('#content').prepend(controlsHtml);

    $('#prev-page').on('click', function() {
        if (currentPage > 1) {
            loadPage(currentPage - 1);
        }
    });
    $('#next-page').on('click', function() {
        loadPage(currentPage + 1);
    });
    $('#live-page').on('click', function() {
        liveMode = true;
        currentPage = 1; // treat live as latest
        rebuildTableFromArray(messages_received);
        $('#pagination-page').text('Live');
    });

    //receive details from server
    socket.on('newresult', function(msg) {
        if (!liveMode) {
            // Ignore live updates while viewing paginated history
            return;
        }
        // live mode: append and rebuild
        messages_received.push(msg.result);
        if (messages_received.length > pageSize) {
            messages_received = messages_received.slice(-pageSize);
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



