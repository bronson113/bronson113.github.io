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

$(document).ready(function () {
  $('#back-to-top-button').click(scrollToTop);
  $(window).scroll(toggleScrollToTopButton);
})
