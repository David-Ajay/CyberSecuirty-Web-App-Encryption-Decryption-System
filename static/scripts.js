function toggleInputBoxes() {
  const inputType = document.getElementById('inputType').value;
  if (inputType === 'text') {
    document.getElementById('textInputBox').style.display = 'block';
    document.getElementById('imageInputBox').style.display = 'none';
  } else {
    document.getElementById('textInputBox').style.display = 'none';
    document.getElementById('imageInputBox').style.display = 'block';
  }
}
window.onload = toggleInputBoxes;
