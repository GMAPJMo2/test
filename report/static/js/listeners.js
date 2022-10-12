// listeners on Report page

// VisibilityChange
document.addEventListener("visibilitychange", function() {
    var LogTime_Action = document.visibilityState
    console.log(LogTime_Action);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/LogPageChange', true);
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    xhr.send(LogTime_Action);
});