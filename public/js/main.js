if (document.getElementById('countDown')) {
  var countDown = new Date('Jan 22, 2019 16:05:00');
  var countDownDate = countDown.getTime();

  var x = setInterval(function() {
    var now = new Date().getTime();
    var distance = countDownDate - now;
    var days = Math.floor(distance / (1000 * 60 * 60 * 24));
    var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    var seconds = Math.floor((distance % (1000 * 60)) / 1000);
    document.getElementById('countDown').innerHTML = days + " : " + hours + ' : ' + minutes + ' : ' + seconds;
  }, 1000);
}
