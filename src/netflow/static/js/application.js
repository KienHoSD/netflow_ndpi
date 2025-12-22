$(document).ready(function(){
    // connect to the socket server (support http/https)
    var socket = io(window.location.protocol + '//' + document.domain + ':' + location.port + '/test');
    socket.on('connect', function(){
        console.log('Socket connected to /test');
    });
    var messages_received = [];
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
    //receive details from server
    socket.on('newresult', function(msg) {
        console.log("Received result" + msg.result);
        //show all flows - no limit
        messages_received.push(msg.result);
        // keep only the latest 1000 flows to avoid an ever-growing table
        if (messages_received.length > 1000) {
            messages_received = messages_received.slice(-1000);
        }
        var stickToBottom = isAtBottom(logContainer);
        messages_string = '<tr><th>Flow ID</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Protocol</th><th>Flow start time</th><th>Flow last seen</th><th>App name</th><th>PID</th><th>Prediction</th><th>Prob</th><th>Risk</th><th>Actions</th></tr>';

        for (var i = 0 ; i < messages_received.length; i++){
            messages_string = messages_string + '<tr>';
            for (var j = 0; j <messages_received[i].length; j++){
                messages_string = messages_string + '<td>' + messages_received[i][j].toString() + '</td>'; 
            }
            messages_string = messages_string+ '<td> <a href="/flow-detail?flow_id='+messages_received[i][0].toString()+'"><div>Detail</div></a></td>';
            messages_string = messages_string+ '<td><button class="btn btn-sm btn-primary re-evaluate-btn" data-flow-id="'+messages_received[i][0].toString()+'">Re-evaluate</button></td>' + '</tr>';

        }
        $('#details').html(messages_string);
        if (stickToBottom) {
            scrollToBottom(logContainer);
        }

        scheduleChartUpdate(msg.ips);


    });

    // Handle re-evaluation button clicks
    $(document).on('click', '.re-evaluate-btn', function() {
        var flowId = $(this).data('flow-id');
        console.log('Re-evaluating flow: ' + flowId);
        socket.emit('re_evaluate_flow', {flow_id: flowId});
    });

    // Handle re-evaluation results
    socket.on('re_evaluation_result', function(msg) {
        console.log("Received re-evaluation result for flow " + msg.flow_id);
        
        // Find and update the flow in messages_received
        for (var i = 0; i < messages_received.length; i++) {
            if (messages_received[i][0] == msg.flow_id) {
                // Update classification (index 10), probability (index 11), and risk (index 12)
                messages_received[i][10] = msg.classification;
                messages_received[i][11] = msg.probability;
                messages_received[i][12] = msg.risk;
                break;
            }
        }
        
        // Rebuild the table
        messages_string = '<tr><th>Flow ID</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Protocol</th><th>Flow start time</th><th>Flow last seen</th><th>App name</th><th>PID</th><th>Prediction</th><th>Prob</th><th>Risk</th><th>Actions</th></tr>';
        for (var i = 0 ; i < messages_received.length; i++){
            messages_string = messages_string + '<tr>';
            for (var j = 0; j <messages_received[i].length; j++){
                messages_string = messages_string + '<td>' + messages_received[i][j].toString() + '</td>'; 
            }
            messages_string = messages_string+ '<td> <a href="/flow-detail?flow_id='+messages_received[i][0].toString()+'"><div>Detail</div></a></td>';
            messages_string = messages_string+ '<td><button class="btn btn-sm btn-primary re-evaluate-btn" data-flow-id="'+messages_received[i][0].toString()+'">Re-evaluate</button></td>' + '</tr>';
        }
        $('#details').html(messages_string);
    });

});



