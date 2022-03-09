jQuery(function ($) {
	"use strict";
});

$(document).on('click', '#expand-service-list', function(event){
    console.log("expanding list");
    $('#service-list').addClass('hidden');
    $('#expanded-service-list').removeClass('hidden');
});
