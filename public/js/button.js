Array.prototype.forEach.call(
  document.getElementsByTagName('button'), function(item) {
  item.addEventListener('mousedown', createRipple);
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
