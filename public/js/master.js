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

function autoGrow(oField) {
  if (oField.scrollHeight > oField.clientHeight) {
    oField.style.height = oField.scrollHeight + "px";
  }
}
