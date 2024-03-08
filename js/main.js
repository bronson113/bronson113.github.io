function scrollToTop(){
  $('html, body').animate({ scrollTop: 0 }, 400);
  return false;
}

function toggleScrollToTopButton(){
  var threshold = 800;
  if ($(window).scrollTop() > threshold){
    $('#back-to-top-button').fadeIn('slow');
  } else {
    $('#back-to-top-button').fadeOut('slow');
  }
}

// setup color-mode button
$('.color-mode').click(function(){
  if(localStorage.getItem('dark') === "true"){
    localStorage.setItem('dark', "false");
  } else {
    localStorage.setItem('dark', "true");
  }
    $('.color-mode-light').toggleClass('d-none')
    $('.color-mode-dark').toggleClass('d-none')
    $('body').toggleClass('dark-mode')
    $('body').attr("data-bs-theme", localStorage.getItem('dark') === "true" ? "dark":"light")
})


if(localStorage.getItem('dark') === "true"){
  $('body').toggleClass('dark-mode')
  $('.color-mode-light').toggleClass('d-none')
  $('.color-mode-dark').toggleClass('d-none')
}
$('body').attr("data-bs-theme", localStorage.getItem('dark') === "true" ? "dark":"light")

// initialize scroll button
$(document).ready(function () {
  $('#back-to-top-button').click(scrollToTop);
  $(window).scroll(toggleScrollToTopButton);
})


