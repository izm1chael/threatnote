"use strict";
var KTDatatablesDataSourceHtml = function() {

	var initTable1 = function() {
		var table = $('#kt_table_1');

		// begin first table
		table.DataTable({
			responsive: true,
			order: [[ 4, 'desc' ]],
			//columnDefs: [
				// {
				// 	targets: -1,
				// 	title: 'Actions',
				// 	orderable: false,
				// 	render: function(data, type, full, meta) {
				// 		return `
				// 		<a href="/edit_report/{{ report.id }}" class="btn btn-sm btn-clean btn-icon btn-icon-md" title="View">
				// 		<i class="la la-edit"></i>
				// 	  </a>
                //         <a href="#" class="btn btn-sm btn-clean btn-icon btn-icon-md" title="View">
                //           <i class="la la-trash"></i>
                //         </a>`;
				// 	},
				// },
				/*{
					targets: -3,
					render: function(data, type, full, meta) {
						var status = {
							'High': {'title': 'High', 'class': 'danger'},
							'Medium': {'title': 'Medium', 'class': 'info'},
							'Low': {'title': 'Low', 'class': 'success'},
						};
						if (typeof status[data] === 'undefined') {
							return data;
						}
						
						return '<span class="btn btn-bold btn-sm btn-font-sm  btn-label-' + status[data].class + '">' + status[data].title + '</span>';
					},
				},
				
			],*/
		});

	};
	var initIndicatorTable = function() {
		var table = $('#kt_indicator_table');

		// begin first table
		table.DataTable({
			responsive: true,
			order: [[ 3, 'desc' ]],
		});

	};
	return {

		//main function to initiate the module
		init: function() {
			initTable1();
			initIndicatorTable();

		}
	};
}();

jQuery(document).ready(function() {
	KTDatatablesDataSourceHtml.init();
});