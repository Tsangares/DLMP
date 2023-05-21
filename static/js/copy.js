const copy = (obj)=>{
    //Copy Button
    const tmp = $(`<input value="${$(obj).val()}" />`)
    $('html').append(tmp)
    tmp.select()
    document.execCommand('copy');
    tmp.remove()
    
    //Notify user using toast
    bulmaToast.toast({
	message: "Copied!",
	type: 'is-success',
	position: 'bottom-center',
    })
}

const refresh = (obj)=>{
    d = new Date();
    $(obj).attr("src","/badge/random/"+d.getTime())
}
