(function () {
  const C = {
    teal: '#35d0b6', amber: '#f4b740', rose: '#ff5d73',
    indigo: '#7c8cff', muted: '#8fa1c2', line: '#223350', void: '#070c18',
  };

  // ---- custom throughput sparkline ---------------------------------------
  const canvas = document.getElementById('rateChart');
  const ctx = canvas.getContext('2d');
  let rateData = new Array(60).fill(0);

  function drawRate() {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const max = Math.max(5, ...rateData);
    const step = w / (rateData.length - 1);
    const y = v => h - 8 - (v / max) * (h - 20);

    // grid
    ctx.strokeStyle = 'rgba(34,51,80,0.5)';
    ctx.lineWidth = 1;
    for (let g = 0; g <= 3; g++) {
      const gy = 8 + (g / 3) * (h - 16);
      ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(w, gy); ctx.stroke();
    }

    // area
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, 'rgba(53,208,182,0.35)');
    grad.addColorStop(1, 'rgba(53,208,182,0.02)');
    ctx.beginPath();
    ctx.moveTo(0, h);
    rateData.forEach((v, i) => ctx.lineTo(i * step, y(v)));
    ctx.lineTo(w, h); ctx.closePath();
    ctx.fillStyle = grad; ctx.fill();

    // line
    ctx.beginPath();
    rateData.forEach((v, i) => i ? ctx.lineTo(i * step, y(v)) : ctx.moveTo(0, y(v)));
    ctx.strokeStyle = C.teal; ctx.lineWidth = 2; ctx.stroke();

    // head dot
    const lx = (rateData.length - 1) * step, ly = y(rateData[rateData.length - 1]);
    ctx.beginPath(); ctx.arc(lx, ly, 3, 0, Math.PI * 2);
    ctx.fillStyle = C.teal; ctx.fill();
  }
  window.addEventListener('resize', drawRate);

  // ---- threat mix donut ---------------------------------------------------
  let mixChart = null;
  function renderMix(breakdown) {
    const empty = document.getElementById('mixEmpty');
    const cv = document.getElementById('mixChart');
    if (!breakdown.length) {
      cv.style.display = 'none'; empty.style.display = 'block';
      if (mixChart) { mixChart.destroy(); mixChart = null; }
      return;
    }
    cv.style.display = 'block'; empty.style.display = 'none';
    const palette = [C.rose, C.amber, C.indigo, C.teal, '#c98bff', '#5ad1ff'];
    const labels = breakdown.map(b => b.type);
    const data = breakdown.map(b => b.count);
    if (!mixChart) {
      mixChart = new Chart(cv, {
        type: 'doughnut',
        data: { labels, datasets: [{ data, backgroundColor: palette, borderColor: C.void, borderWidth: 3 }] },
        options: {
          cutout: '64%', plugins: {
            legend: { position: 'bottom', labels: { color: C.muted, font: { size: 11, family: 'JetBrains Mono' }, boxWidth: 10, padding: 12 } },
          },
        },
      });
    } else {
      mixChart.data.labels = labels;
      mixChart.data.datasets[0].data = data;
      mixChart.update('none');
    }
  }

  // ---- protocol split -----------------------------------------------------
  function renderProto(protocols) {
    const host = document.getElementById('protoList');
    if (!protocols.length) { host.innerHTML = '<div class="empty">No traffic yet</div>'; return; }
    const total = protocols.reduce((a, p) => a + p.count, 0) || 1;
    host.innerHTML = protocols.map(p => {
      const pct = Math.round((p.count / total) * 100);
      return `<div>
        <div class="row-between" style="margin-bottom:6px;">
          <span class="mono" style="font-size:13px;text-transform:uppercase;">${p.protocol}</span>
          <span class="mono faint" style="font-size:12px;">${p.count} · ${pct}%</span>
        </div>
        <div class="meter"><span style="width:${pct}%"></span></div>
      </div>`;
    }).join('');
  }

  // ---- feed ---------------------------------------------------------------
  function badge(v) {
    const map = { allow: 'badge-allow', flag: 'badge-flag', block: 'badge-block' };
    return `<span class="badge ${map[v] || 'badge-neutral'}">${v}</span>`;
  }
  async function renderFeed() {
    try {
      const rows = await api('/api/events');
      const body = document.getElementById('feedBody');
      if (!rows.length) { body.innerHTML = '<tr><td colspan="5" class="empty">Waiting for traffic…</td></tr>'; return; }
      body.innerHTML = rows.slice(0, 8).map(r => `
        <tr class="fresh">
          <td class="mono faint">${r.ts}</td>
          <td class="ip">${r.src_ip}</td>
          <td class="mono" style="font-size:12.5px;">${r.service}</td>
          <td>${badge(r.verdict)}</td>
          <td class="mono">${r.confidence}%</td>
        </tr>`).join('');
    } catch (e) {}
  }

  // ---- poll ---------------------------------------------------------------
  async function poll() {
    try {
      const d = await api('/api/overview');
      const s = d.snapshot || {}, t = d.totals || {}, st = s.stats || {};
      document.getElementById('s_flows').textContent = st.flows ?? 0;
      document.getElementById('s_flagged').textContent = st.flagged ?? 0;
      document.getElementById('s_blocked').textContent = st.blocked ?? 0;
      document.getElementById('s_active').textContent = t.active_blocks ?? 0;
      document.getElementById('s_alerts').textContent = t.open_alerts ?? 0;
      document.getElementById('statusLine').textContent =
        `engine ${s.capturing ? 'capturing on ' + s.interface : (s.source_status || 'idle')} · ${s.enforcement} enforcement`;

      rateData = (s.rate && s.rate.length === 60) ? s.rate : rateData;
      drawRate();
      const now = rateData[rateData.length - 1] || 0;
      document.getElementById('rateNow').textContent = `${now} flows/s`;

      renderMix(d.attack_breakdown || []);
      renderProto(d.protocols || []);

      const btn = document.getElementById('captureBtn');
      btn.textContent = s.capturing ? 'Stop capture' : 'Start capture';
      btn.classList.toggle('btn-danger', !!s.capturing);
      btn.classList.toggle('btn-primary', !s.capturing);
    } catch (e) {}
    renderFeed();
  }

  // ---- controls -----------------------------------------------------------
  document.getElementById('captureBtn').addEventListener('click', async (e) => {
    const capturing = e.target.textContent.includes('Stop');
    try {
      const r = capturing ? await post('/api/capture/stop') : await post('/api/capture/start', {});
      toast(r.message, r.ok ? 'ok' : 'err');
    } catch (err) { toast('Action failed', 'err'); }
    poll();
  });

  document.querySelectorAll('.sim').forEach(b => {
    b.addEventListener('click', async () => {
      b.disabled = true;
      try {
        const r = await post('/api/simulate', { scenario: b.dataset.s });
        toast(r.message, 'ok');
      } catch (e) { toast('Simulation failed', 'err'); }
      b.disabled = false;
      poll();
    });
  });

  drawRate();
  poll();
  setInterval(poll, 2000);
})();
