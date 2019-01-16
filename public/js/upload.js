window.addEventListener('load', uploadInit);

var fileTarget = document.getElementsByClassName('fileInput')[0];
var fileDest = document.getElementsByClassName('fileName')[0];
var fileButton = document.getElementsByClassName('fileButton')[0];
var fileBox = document.getElementsByClassName('fileBox')[0];

function uploadInit() {
  fileTarget.addEventListener('change', fileChosen);
}

function fileChosen(e) {
  fileDest.value = fileTarget.value;
  if (fileTarget.value != '') fileButton.disabled = false;
  else fileButton.disabled = true;
}
