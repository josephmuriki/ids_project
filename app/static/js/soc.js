setInterval(()=>{
 fetch("/alerts")
 .then(r=>r.json())
 .then(d=>{
   if(d.alerts>0){
     document.getElementById("alertBanner").innerText="⚠ HIGH ALERT ACTIVE";
   }
 });
},3000);