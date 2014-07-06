$('#login').submit(function(event) {
    console.log('what bull is happening')
		var formData = {
			'username' 				: $('input[name=username]').val(),
			'password' 			: $('input[name=password]').val(),
		};
		$.ajax({
			type 		: 'POST',
			url 		: '/login',
			data 		: JSON.stringify(formData),
			dataType 	: 'json',
            encode      : true
		}).done(function(data) {
				console.log(data);
			});
		event.preventDefault();
	});