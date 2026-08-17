// Restore theme before first paint to avoid flash.
// Lives outside index.html so the Content-Security-Policy can drop 'unsafe-inline'
// from script-src; loaded from <head> so it still runs before the first frame.
(function() {
  var t = localStorage.getItem('vigilyx-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', t);
})();
