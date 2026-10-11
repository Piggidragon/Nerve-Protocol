// The login form works without this file; this only shows that the token
// is being checked and undoes that when the browser brings the page back
// from its cache.
"use strict";
(function () {
  var form = document.querySelector(".login-form");
  if (!form) return;
  var button = form.querySelector(".login-submit");
  form.addEventListener("submit", function () {
    button.disabled = true;
    button.textContent = "Checking…";
  });
  window.addEventListener("pageshow", function () {
    button.disabled = false;
    button.textContent = "Sign in";
  });
})();
