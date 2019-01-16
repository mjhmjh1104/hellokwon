window.addEventListener('load', ready);

function ready() {
  if (/Trident|MSIE/.test(navigator.userAgent)) {
    alert('IE 쓰지 마세요.');
    window.close();
    document.getElementsByTagName('html')[0].removeChild(document.getElementsByTagName('head')[0]);
    document.getElementsByTagName('html')[0].removeChild(document.getElementsByTagName('body')[0]);
  }
}

var socket = io();

Array.prototype.forEach.call(
  document.getElementsByTagName('button'), function(item) {
  item.addEventListener('mousedown', createRipple);
});
Array.prototype.forEach.call(
  document.getElementsByTagName('textarea'), function(item) {
  item.addEventListener('keyup', autoGrow);
});

function createRipple(e) {
  var circle = document.createElement('div');

  var radius = Math.max(this.clientWidth, this.clientHeight);
  circle.style.width = circle.style.height = radius + 'px';
  circle.style.left = e.clientX - this.offsetLeft - radius / 2 + 'px';
  circle.style.top = e.clientY - this.offsetTop - radius / 2 + 'px';
  circle.style.opacity = 0;

  circle.classList.add('ripple');
  this.appendChild(circle);
}

function autoGrow(e) {
  if (this.scrollHeight > this.clientHeight) this.style.height = this.scrollHeight + "px";
}

function includes(arr, entity) {
  for (var i = 0; i < arr.length; i++) if (arr[i] === entity) return true;
  return false;
}
