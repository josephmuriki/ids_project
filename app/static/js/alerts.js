const socket=io();

socket.on("alert",data=>{
let box=document.getElementById("alertBox");
box.classList.remove("hidden");
box.classList.add("blink");
});