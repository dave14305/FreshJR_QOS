﻿<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<!-- 
 Modification on-top of RMerlins QoS_Stats page taken from 384.9_alpha2-g2ee0afa1c
 QoS_Stats.asp was modified so that the QoS Statistics page will reflect changes arising
 from the FreshJR_QOS Modification Script instead default AdaptiveQoS behavior
 Beta1 tested with FreshJR_QOS v7 on an AC-68U running 384.9_alpha2-g2ee0afa1c
 -->
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#705#> - QoS Statistics</title>
<link rel="stylesheet" type="text/css" href="index_style.css">
<link rel="stylesheet" type="text/css" href="form_style.css">
<link rel="stylesheet" type="text/css" href="usp_style.css">
<link rel="stylesheet" type="text/css" href="/js/table/table.css">
<script type="text/javascript" src="/js/jquery.js"></script>
<script type="text/javascript" src="/js/chart.min.js"></script>
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/js/table/table.js"></script>
<script>
var qos_type = "<% nvram_get("qos_type "); %>";
if ("<% nvram_get("qos_enable "); %>" == 0) { // QoS disabled
    var qos_mode = 0;
} else if (bwdpi_support && (qos_type == "1")) { // aQoS
    var qos_mode = 2;
} else if (qos_type == "0") { // tQoS
    var qos_mode = 1;
} else if (qos_type == "2") { // BW limiter
    var qos_mode = 3;
} else { // invalid mode
    var qos_mode = 0;
}
if (qos_mode == 2) {
    var bwdpi_app_rulelist = "<% nvram_get("bwdpi_app_rulelist "); %>".replace(/&#60/g, "<");
    var category_title = ["Net Control Packets", "<#752#>", "<#762#>", "<#756#>", "<#764#>", "<#751#>", "<#757#>", "Game Transferring"];
    var cat_id_array = [
        [9, 20],
        [8],
        [4],
        [0, 5, 6, 15, 17],
        [13, 24],
        [1, 3, 14],
        [7, 10, 11, 21, 23],
        []
    ];
    var bwdpi_app_rulelist_row = bwdpi_app_rulelist.split("<");
    if (bwdpi_app_rulelist == "" || bwdpi_app_rulelist_row.length != 9) {
        bwdpi_app_rulelist = "9,20<8<4<0,5,6,15,17<13,24<1,3,14<7,10,11,21,23<<";
        bwdpi_app_rulelist_row = bwdpi_app_rulelist.split("<");
    }
	var bwdpi_cindex_net=bwdpi_app_rulelist_row.indexOf(cat_id_array[0].toString())
	var bwdpi_cindex_gaming=bwdpi_app_rulelist_row.indexOf(cat_id_array[1].toString())
	var bwdpi_cindex_streaming=bwdpi_app_rulelist_row.indexOf(cat_id_array[2].toString())
	var bwdpi_cindex_voip=bwdpi_app_rulelist_row.indexOf(cat_id_array[3].toString())
	var bwdpi_cindext_web=bwdpi_app_rulelist_row.indexOf(cat_id_array[4].toString())
	var bwdpi_cindex_downloads=bwdpi_app_rulelist_row.indexOf(cat_id_array[5].toString())
	var bwdpi_cindex_others=bwdpi_app_rulelist_row.indexOf(cat_id_array[6].toString())
	var bwdpi_cindex_default=bwdpi_app_rulelist_row.indexOf(cat_id_array[7].toString())
} else {
    var category_title = ["", "Highest", "High", "Medium", "Low", "Lowest"];
}
var pie_obj_ul, pie_obj_dl;
var refreshRate;
var timedEvent = 0;
var color = ["#B3645B", "#B98F53", "#C6B36A", "#849E75", "#2B6692", "#7C637A", "#4C8FC0", "#6C604F"];
if (qos_mode == 2) {
	  var color = ["#B3645B", "#B98F53", "#C6B36A", "#849E75", "#2B6692", "#7C637A", "#796B58", "#6C604F"];
}
<% get_tcclass_array(); %>;
<% bwdpi_conntrack(); %>;
var pieOptions = {
    segmentShowStroke: false,
    segmentStrokeColor: "#000",
    animationEasing: "easeOutQuart",
    animationSteps: 100,
    animateScale: true,
    legend: {
        display: false
    },
    tooltips: {
        callbacks: {
            title: function(tooltipItem, data) {
                return data.labels[tooltipItem[0].index];
            },
            label: function(tooltipItem, data) {
                var value = data.datasets[tooltipItem.datasetIndex].data[tooltipItem.index];
                var orivalue = value;
                var total = eval(data.datasets[tooltipItem.datasetIndex].data.join("+"));
                var unit = " bytes";
                if (value > 1024) {
                    value = value / 1024;
                    unit = " KB";
                }
                if (value > 1024) {
                    value = value / 1024;
                    unit = " MB";
                }
                if (value > 1024) {
                    value = value / 1024;
                    unit = " GB";
                }
                return value.toFixed(2) + unit + ' ( ' + parseFloat(orivalue * 100 / total).toFixed(2) + '% )';
            },
        }
    },
}

function comma(n) {
    n = '' + n;
    var p = n;
    while ((n = n.replace(/(\d+)(\d{3})/g, '$1,$2')) != p) p = n;
    return n;
}

function initial() {
    show_menu();
    refreshRate = document.getElementById('refreshrate').value
    get_data();
    draw_conntrack_table();
}

function get_qos_class(category, appid) {
    var i, j, catlist, rules;
    
	if (category == 0 && (appid == 0 || appid == 107) )
		return bwdpi_cindex_others
	else if (category == 19 || category == 20)
		return bwdpi_cindext_web
	else if (category == 13 && (appid == 7 || appid == 134 || appid == 160) )
		return bwdpi_cindex_downloads
		
    for (i = 0; i < bwdpi_app_rulelist_row.length - 2; i++) {
        rules = bwdpi_app_rulelist_row[i];
        if (bwdpi_cindex_net == i)
            rules += ",18,19";
        else if (bwdpi_cindext_web == i)
            rules += ",28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43";
        else if ( bwdpi_cindex_streaming == i)
            rules += ",12";
        catlist = rules.split(",");
        for (j = 0; j < catlist.length; j++) {
            if (catlist[j] == category) {
                return i;
            }
        }
    }
    return 7;
}

function compIPV6(input) {
    input = input.replace(/\b(?:0+:){2,}/, ':');
    return input.replace(/(^|:)0{1,4}/g, ':');
}

function draw_conntrack_table() {
    var i, label;
    if (qos_mode != 2) return;
    for (i = 0; i < bwdpi_conntrack.length; i++) {
		if (bwdpi_conntrack[i][4] == 500 || bwdpi_conntrack[i][4] == 4500)
		{
			label = "Wi-Fi Calling";
			bwdpi_conntrack[i][5] = "<span style=\"padding: 4px 8px 4px 8px; color: white; background-color: " + color[bwdpi_cindex_voip] + ";\">" + label + "</span>";
		}
		else if (bwdpi_conntrack[i][2] >= 16384 && bwdpi_conntrack[i][2] <= 16415)
		{
			label = "Facetime";
			bwdpi_conntrack[i][5] = "<span style=\"padding: 4px 8px 4px 8px; color: white; background-color: " + color[bwdpi_cindex_voip] + ";\">" + label + "</span>";
		}
		else if (bwdpi_conntrack[i][7] == 8 && (bwdpi_conntrack[i][4] == 80 || bwdpi_conntrack[i][4] == 443) && bwdpi_conntrack[i][0] == "tcp" )		{
			label = "Game Transferring: " + bwdpi_conntrack[i][5];
			bwdpi_conntrack[i][5] = "<span style=\"padding: 4px 8px 4px 8px; color: white; background-color: " + color[bwdpi_cindex_default] + ";\">" + label + "</span>";
		}
        else{ 
		    label = bwdpi_conntrack[i][5];
			bwdpi_conntrack[i][5] = "<span style=\"padding: 4px 8px 4px 8px; color: white; background-color: " + color[get_qos_class(bwdpi_conntrack[i][7], bwdpi_conntrack[i][6])] + ";\">" + label + "</span>";
		}
		
        if (bwdpi_conntrack[i][1].indexOf(":") >= 0) {
            bwdpi_conntrack[i][1] = compIPV6(bwdpi_conntrack[i][1]);
        }
        if (bwdpi_conntrack[i][3].indexOf(":") >= 0) {
            bwdpi_conntrack[i][3] = compIPV6(bwdpi_conntrack[i][3]);
        }
    }
    var tabledata = bwdpi_conntrack.map(function(val) {
        return val.slice(0, -2);
    });
    var tableStruct = {
        data: tabledata,
        container: "tableContainer",
        title: "Tracked connections",
        header: [{
                "title": "Proto",
                "sort": "str",
                "width": "6%"
            },
            {
                "title": "Source",
                "sort": "ip",
                "width": "25%"
            },
            {
                "title": "SPort",
                "sort": "num",
                "width": "8%"
            },
            {
                "title": "Destination",
                "sort": "ip",
                "width": "25%"
            },
            {
                "title": "DPort",
                "sort": "num",
                "width": "8%"
            },
            {
                "title": "Application",
                "sort": "str",
                "width": "28%"
            }
        ]
    }
    if (tableStruct.data.length) {
        tableApi.genTableAPI(tableStruct);
    }
}

function redraw() {
    var code;
    switch (qos_mode) {
        case 0: // Disabled
            document.getElementById('dl_tr').style.display = "none";
            document.getElementById('ul_tr').style.display = "none";
            document.getElementById('no_qos_notice').style.display = "";
            return;
        case 3: // Bandwith Limiter
            document.getElementById('dl_tr').style.display = "none";
            document.getElementById('ul_tr').style.display = "none";
            document.getElementById('limiter_notice').style.display = "";
            return;
        case 1: // Traditional
            document.getElementById('dl_tr').style.display = "none";
            document.getElementById('tqos_notice').style.display = "";
            break;
        case 2: // Adaptive
            if (pie_obj_dl != undefined) pie_obj_dl.destroy();
            var ctx_dl = document.getElementById("pie_chart_dl").getContext("2d");
            tcdata_lan_array.sort(function(a, b) {
                return a[0] - b[0]
            });
            code = draw_chart(tcdata_lan_array, ctx_dl, "dl");
            document.getElementById('legend_dl').innerHTML = code;
            break;
    }
    if (pie_obj_ul != undefined) pie_obj_ul.destroy();
    var ctx_ul = document.getElementById("pie_chart_ul").getContext("2d");
    tcdata_wan_array.sort(function(a, b) {
        return a[0] - b[0]
    });
    code = draw_chart(tcdata_wan_array, ctx_ul, "ul");
    document.getElementById('legend_ul').innerHTML = code;
    pieOptions.animation = false; // Only animate first time
}

function get_data() {
    if (timedEvent) {
        clearTimeout(timedEvent);
        timedEvent = 0;
    }
    $.ajax({
        url: '/ajax_gettcdata.asp',
        dataType: 'script',
        error: function(xhr) {
            get_data();
        },
        success: function(response) {
            redraw();
            draw_conntrack_table();
            if (refreshRate > 0)
                timedEvent = setTimeout("get_data();", refreshRate * 1000);
        }
    });
}

function draw_chart(data_array, ctx, pie) {
    var code = '<table><thead style="text-align:left;"><tr><th style="padding-left:5px;">Class</th><th style="padding-left:5px;">Total</th><th style="padding-left:20px;">Rate</th><th style="padding-left:20px;">Packet rate</th></tr></thead>';
    var code_delay_append = '';
	var values_array = [];
    var labels_array = [];
	for (i = 0; i < data_array.length - 1; i++) {
        var value = parseInt(data_array[i][1]);
        var tcclass = parseInt(data_array[i][0]);
        var rate;
        if (qos_mode == 2) {
            var index = 0;
            for (j = 1; j < cat_id_array.length; j++) {
                if (cat_id_array[j] == bwdpi_app_rulelist_row[i]) {
					  index = j;
                    break;
                }
            }
            var label = category_title[index];
        } else {
            tcclass = tcclass / 10;
            var label = category_title[tcclass];
            if (label == undefined) {
                label = "Class " + tcclass;
            }
        }
        labels_array.push(label);
        values_array.push(value);
        var unit = " Bytes";
        if (value > 1024) {
            value = value / 1024;
            unit = " KB";
        }
        if (value > 1024) {
            value = value / 1024;
            unit = " MB";
        }
        if (value > 1024) {
            value = value / 1024;
            unit = " GB";
        }
		if (qos_mode == 2 && i == (data_array.length - 3) ) {
			code_delay_append += '<tr><td style="word-wrap:break-word;padding-left:5px;padding-right:5px;background-color:' + color[i] + ';margin-right:10px;line-height:20px;">' + label + '</td>';
			code_delay_append += '<td style="padding-left:5px;">' + value.toFixed(2) + unit + '</td>';
			rate = comma(data_array[i][2]);
			code_delay_append += '<td style="padding-left:20px;">' + rate.replace(/([0-9,])([a-zA-Z])/g, '$1 $2') + '</td>';
			rate = comma(data_array[i][3]);
			code_delay_append += '<td style="padding-left:20px;">' + rate.replace(/([0-9,])([a-zA-Z])/g, '$1 $2') + '</td></tr>';	
		}
		else
		{
			code += '<tr><td style="word-wrap:break-word;padding-left:5px;padding-right:5px;background-color:' + color[i] + ';margin-right:10px;line-height:20px;">' + label + '</td>';
			code += '<td style="padding-left:5px;">' + value.toFixed(2) + unit + '</td>';
			rate = comma(data_array[i][2]);
			code += '<td style="padding-left:20px;">' + rate.replace(/([0-9,])([a-zA-Z])/g, '$1 $2') + '</td>';
			rate = comma(data_array[i][3]);
			code += '<td style="padding-left:20px;">' + rate.replace(/([0-9,])([a-zA-Z])/g, '$1 $2') + '</td></tr>';
		}
    }
	code += code_delay_append;
    code += '</table>';
    var pieData = {
        labels: labels_array,
        datasets: [{
            data: values_array,
            backgroundColor: color,
            hoverBackgroundColor: color,
            borderColor: "#444",
            borderWidth: "1"
        }]
    };
    var pie_obj = new Chart(ctx, {
        type: 'pie',
        data: pieData,
        options: pieOptions
    });
    if (pie == "ul")
        pie_obj_ul = pie_obj;
    else
        pie_obj_dl = pie_obj;
    return code;
}
</script>
</head>
<body onload="initial();">
<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="form" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<input type="hidden" name="current_page" value="/QoS_stats.asp">
<input type="hidden" name="next_page" value="/QoS_Stats.asp">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="">
<input type="hidden" name="action_wait" value="5">
<input type="hidden" name="flag" value="">
<table class="content" align="center" cellpadding="0" cellspacing="0">
<tr>
<td width="17">&nbsp;</td>
<td valign="top" width="202">
<div id="mainMenu"></div>
<div id="subMenu"></div></td>
<td valign="top">
<div id="tabMenu" class="submenuBlock"></div>
<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
<tr>
<td valign="top">
<table width="760px" border="0" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTitle" id="FormTitle">
<tbody>
<tr bgcolor="#4D595D">
<td valign="top">
    <div class="formfonttitle" style="display: inline-block; margin: 10px;">QoS - Traffic classification Statistics </div>
    <div style="float: right; font-size:75%;color:#FFCC00; display: inline-block; margin:5px;">FreshJR Mod</div>
	<div style="margin:5 0 5px 5px;" class="splitLine"></div>
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
<tr>
<th>Automatically refresh data every</th>
<td>
<select name="refreshrate" class="input_option" onchange="refreshRate = this.value; get_data();" id="refreshrate">
<option value="0">No refresh</option>
<option value="3" selected>3 seconds</option>
<option value="5">5 seconds</option>
<option value="10">10 seconds</option>
</select>
</td>
</tr>
</table>
<br>
<div id="limiter_notice" style="display:none;font-size:125%;color:#FFCC00;">Statistics not available in Bandwidth Limiter mode.</div>
<div id="no_qos_notice" style="display:none;font-size:125%;color:#FFCC00;">QoS is not enabled.</div>
<div id="tqos_notice" style="display:none;font-size:125%;color:#FFCC00;">Note: Traditional QoS only classifies uploaded traffic.</div>
<table>
<tr id="dl_tr">
<td style="padding-right:50px;font-size:125%;color:#FFCC00;"><div>Download</div><canvas id="pie_chart_dl" width="200" height="200"></canvas></td>
<td><span id="legend_dl"></span></td>
</tr>
<tr style="height:50px;"><td colspan="2">&nbsp;</td></tr>
<tr id="ul_tr">
<td style="padding-right:50px;font-size:125%;color:#FFCC00;"><div>Upload</div><canvas id="pie_chart_ul" width="200" height="200"></canvas></td>
<td><span id="legend_ul"></span></td>
</tr>
</table>
<br>
<div id="tableContainer" style="margin-top:-10px;"></div>
<br>
<div class="apply_gen" style="padding-top: 25px;"><input type="button" onClick="location.href=location.href" value="<#1281#>" class="button_gen"></div>
</td>
</tr>
</tbody>
</table>
</td>
</tr>
</table>
</td>
<td width="10" align="center" valign="top">&nbsp;</td>
</tr>
</table>
</form>
<div id="footer"></div>
</body>
</html>
