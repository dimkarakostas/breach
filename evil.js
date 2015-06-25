function makeRequest(iterator = 0, total = 0) {
	jQuery.get("request.txt", function(data) {
		var input = data.split('\n');
		var ref = input[0];
		var alphabet = input[1].split(',');
		var search = alphabet[iterator];
		request = "https://touch.facebook.com/messages/?q=" + search;
		var img = new Image();
		img.src = request;
		iterator = iterator > alphabet.length - 1 ? 0 : ++iterator;
		console.log("making request %d: %s", total++, request);
	});
	setTimeout(function() {
		makeRequest(iterator, total);
	}, 3000);
}
makeRequest();
