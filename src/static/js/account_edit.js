
$("#image-upload").change((event)=>{
    let element = $(event.target)
    let filename = element.val().split('\\').pop()
    console.log(filename)
    $("#image-filename").text(filename)
    $("form").submit()
})

$("#clear-redirect").click((e)=>{
    $("#redirect").val("")
})