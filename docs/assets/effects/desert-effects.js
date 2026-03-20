(function () {
  // Only run in light mode (site uses body.dark for dark mode)
  if (document.body.classList.contains('dark')) return;
  if (document.getElementById('desert-effects')) return;

  const wrap = document.createElement('div');
  wrap.id = 'desert-effects';

  // ── 1. Sun rays ──────────────────────────────
  const raysDiv = document.createElement('div');
  raysDiv.id = 'sun-rays';
  const angles  = [25, 45, 65, 85, 105, 125, 145, 165, 35, 75, 115, 155];
  const lengths = [220,180,200,160, 210, 170, 190, 150,240,185, 205, 165];
  angles.forEach(function (angle, i) {
    const ray = document.createElement('div');
    ray.className = 'ray';
    ray.style.cssText =
      'width:'  + lengths[i] + 'px;' +
      'transform:rotate(' + angle + 'deg);' +
      'animation-delay:' + (i * 0.35).toFixed(1) + 's';
    raysDiv.appendChild(ray);
  });
  wrap.appendChild(raysDiv);

  // ── 2. Sand grains ───────────────────────────
  var grainData = [
    {w:2,h:2,top:14,dur:9,  delay:0,   dy:-14},
    {w:3,h:2,top:28,dur:13, delay:1.5, dy:10 },
    {w:2,h:2,top:42,dur:10, delay:0.7, dy:-8 },
    {w:3,h:3,top:58,dur:14, delay:3,   dy:16 },
    {w:2,h:2,top:36,dur:11, delay:2,   dy:-20},
    {w:2,h:2,top:70,dur:8,  delay:0.3, dy:8  },
    {w:3,h:2,top:22,dur:15, delay:4,   dy:-10},
    {w:2,h:2,top:52,dur:12, delay:1,   dy:12 },
    {w:2,h:2,top:46,dur:9,  delay:5,   dy:-16},
    {w:3,h:2,top:65,dur:11, delay:2.5, dy:6  },
    {w:2,h:2,top:18,dur:14, delay:6,   dy:-12},
    {w:2,h:3,top:80,dur:10, delay:3.5, dy:10 },
    {w:3,h:2,top:35,dur:13, delay:0.5, dy:-8 },
    {w:2,h:2,top:60,dur:9,  delay:7,   dy:14 },
    {w:2,h:2,top:50,dur:12, delay:4.5, dy:-6 },
    {w:2,h:2,top:25,dur:10, delay:8,   dy:8  },
    {w:3,h:2,top:75,dur:13, delay:1.2, dy:-4 },
    {w:2,h:2,top:88,dur:11, delay:5.5, dy:6  }
  ];
  grainData.forEach(function (g) {
    var el = document.createElement('div');
    el.className = 'grain';
    el.style.cssText =
      'width:'             + g.w    + 'px;' +
      'height:'            + g.h    + 'px;' +
      'top:'               + g.top  + '%;'  +
      'left:-6px;'                          +
      '--dy:'              + g.dy   + 'px;' +
      'animation-duration:'+ g.dur  + 's;'  +
      'animation-delay:-'  + g.delay+ 's';
    wrap.appendChild(el);
  });

  // ── 3. Heat waves ─────────────────────────────
  var heatWrap = document.createElement('div');
  heatWrap.id = 'heat-wrap';
  for (var i = 0; i < 3; i++) {
    var hw = document.createElement('div');
    hw.className = 'heat-wave';
    heatWrap.appendChild(hw);
  }
  wrap.appendChild(heatWrap);

  document.body.appendChild(wrap);

  // Re-hide if user switches to dark mode after page load
  var observer = new MutationObserver(function () {
    var el = document.getElementById('desert-effects');
    if (el) el.style.display = document.body.classList.contains('dark') ? 'none' : '';
  });
  observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });
})();
