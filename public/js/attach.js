var socket = io();

var overLap = document.getElementsByClassName('overLap')[0];
var attachment = document.getElementsByClassName('attachment')[0];
var attachDest = document.getElementsByClassName('attachDest')[0];

function attach() {
  overLap.style.display = 'block';
  socket.emit('photoReq');
}

function unAttach() {
  overLap.style.display = 'none';
}

socket.on('photoUpdate', function(imgs) {
  attachment.innerHTML = '<div style="margin: 10px; margin-bottom: 30px;"><label style="font-size: 25px;">첨부파일 선택</label></div><br />';
  Array.prototype.forEach.call(imgs, function(item) {
    attachment.innerHTML += '<div class="attachContainer" onclick="attachImg(\'' + item._id.toString() + '\')"><img src="/photo/' + item._id.toString() + '/raw" class="attachItem"></img></div>'
  });
});

function attachImg(id) {
  attachDest.innerHTML += '<br /><a href="/photo/' + id + '"><img src="/photo/' + id + '/raw" class="attachedImg"></img></a><br />';
}
