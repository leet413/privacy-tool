document.addEventListener('submit', function (e) {
  var m = e.target.dataset && e.target.dataset.confirm;
  if (m && !window.confirm(m)) e.preventDefault();
});
(function () {
  var box = document.getElementById('scan-status');
  if (!box) return;
  var bar = document.getElementById('bar'), txt = document.getElementById('prog');
  function tick() {
    fetch(box.dataset.url, { credentials: 'same-origin' }).then(function (r) { return r.json(); }).then(function (s) {
      if (s.total) bar.value = Math.round(100 * s.done / s.total);
      txt.textContent = s.status + (s.total ? ' (' + s.done + ' of ' + s.total + ' searches)' : '');
      if (s.status === 'queued' || s.status === 'running') setTimeout(tick, 3000);
      else location.reload();
    }).catch(function () { setTimeout(tick, 5000); });
  }
  tick();
})();
