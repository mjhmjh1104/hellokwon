var socket = io(), tPost, tUser, tType;
var likeButton = document.getElementsByClassName('like')[0];
var likeLabel = document.getElementsByClassName('likeLabel')[0];

function likeInit(user, post, type) {
  tUser = user;
  tPost = post;
  tType = type;
}

function likeReq() {
  socket.emit('likeReq', tType, tPost);
}

function likeUpdate(type, post, likes) {
  if (type == tType && post == tPost) {
    if (likes.length > 0) likeLabel.innerHTML = likes.length + '명이 이 게시물을 좋아합니다.';
    else likeLabel.innerHTML = '';
    if (likeButton) {
      if (includes(likes, tUser)) {
        likeButton.style.backgroundColor = '#4080FF';
        likeButton.innerHTML = 'Unlike';
        likeButton.style.color = 'white';
        likeButton.setAttribute('onclick', 'unlike();');
      } else {
        likeButton.style.backgroundColor = 'white';
        likeButton.innerHTML = 'Like';
        likeButton.style.color = '#3C4043';
        likeButton.setAttribute('onclick', 'like();');
      }
    }
  }
}

function like() {
  socket.emit('like', tType, tPost);
}

function unlike() {
  socket.emit('unlike', tType, tPost);
}

socket.on('likeUpdate', likeUpdate);
