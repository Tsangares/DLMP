$( document ).ready(function() {
    $(".influence").each((i,e)=>{
	console.log($(e).text())
	var time = new Date($(e).text()+"+00:00")
	var duration = (new Date()-time)/10000
	$(e).text(Math.floor(duration))
    })
});