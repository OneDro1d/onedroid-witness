// Marks every element under <body> whose computed style makes it not visible with data-witness-hidden="1" and
// returns [{xpath, text, reason}] for them (text: whitespace-normalised textContent, capped). Run after load.
// Not visible means any of:
//   checkVisibility() false with visibility and opacity checks (display:none on it or an ancestor, the hidden
//   attribute, visibility:hidden|collapse, opacity:0 on it or an ancestor, content-visibility:hidden);
//   font-size 0, a fully transparent text colour, or a text colour equal to the background behind it, on an element
//   with its own text;
//   entirely left of or above the document (the "left:-9999px" pattern);
//   a box of at most 1x1 px that clips its overflow and holds text (the "sr-only" pattern);
//   own text whose rendered boxes have no area left once clipped by every clipping ancestor (overflow hidden|clip,
//   the clip property, clip-path inset()), or lie wholly left of or above the document (text-indent, height:0 with
//   overflow hidden, clip-path inset(50%), transform scale(0)). Scrollable boxes (overflow auto|scroll) do not clip
//   here: their content can be scrolled into view.
() => {
  const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE", "LINK", "META", "BASE", "TITLE"]);
  const NO_GEOMETRY = new Set(["OPTION", "OPTGROUP", "SELECT", "DATALIST", "TEXTAREA"]);
  const MAX_NODES = 10000, MAX_TEXT = 100000;
  const out = [];
  const sx = window.scrollX, sy = window.scrollY;
  const clipCache = new Map();
  function xpath(el) {
    const parts = [];
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      let i = 1;
      for (let s = n.previousElementSibling; s; s = s.previousElementSibling) if (s.nodeName === n.nodeName) i++;
      parts.unshift(n.nodeName.toLowerCase() + "[" + i + "]");
    }
    return "/" + parts.join("/");
  }
  function ownTextNodes(el) {
    const nodes = [];
    for (const c of el.childNodes) if (c.nodeType === 3 && c.data.trim()) nodes.push(c);
    return nodes;
  }
  function rgba(color) {
    if (color === "transparent") return [0, 0, 0, 0];
    const m = color.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(/[ ,\/]+/).filter(Boolean).map(parseFloat);
    if (p.length < 3) return null;
    return [p[0], p[1], p[2], p.length >= 4 ? p[3] : 1];
  }
  function transparent(color) {
    const c = rgba(color);
    return !!c && c[3] === 0;
  }
  // the colour painted behind el: the first opaque background-color up the tree; null when an image or a
  // translucent layer is in the way (no claim is made then), white when nothing paints one (the canvas)
  function backdrop(el) {
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (cs.backgroundImage && cs.backgroundImage !== "none") return null;
      const c = rgba(cs.backgroundColor);
      if (!c) return null;
      if (c[3] === 0) continue;
      return c[3] >= 0.99 ? c : null;
    }
    return [255, 255, 255, 1];
  }
  function sameColour(el, cs) {
    const fg = rgba(cs.color);
    if (!fg || fg[3] < 0.99) return false;
    if (cs.textShadow && cs.textShadow !== "none") return false;
    if (cs.webkitTextStrokeWidth && parseFloat(cs.webkitTextStrokeWidth) > 0) return false;
    const bg = backdrop(el);
    if (!bg) return false;
    return Math.max(Math.abs(fg[0] - bg[0]), Math.abs(fg[1] - bg[1]), Math.abs(fg[2] - bg[2])) <= 8;
  }
  function intersect(a, b) {
    const l = Math.max(a.l, b.l), t = Math.max(a.t, b.t), r = Math.min(a.r, b.r), bo = Math.min(a.b, b.b);
    return {l: l, t: t, r: Math.max(l, r), b: Math.max(t, bo)};
  }
  function len(v, ref) {
    v = v.trim();
    if (v.endsWith("%")) return parseFloat(v) / 100 * ref;
    const f = parseFloat(v);
    return isNaN(f) ? 0 : f;
  }
  // the rectangle (viewport coordinates) an element clips its own content to, or null when it clips nothing
  function ownClip(n) {
    if (clipCache.has(n)) return clipCache.get(n);
    const cs = getComputedStyle(n);
    const b = n.getBoundingClientRect();
    let box = {l: b.left, t: b.top, r: b.right, b: b.bottom};
    let clip = null;
    const clips = v => v === "hidden" || v === "clip";
    if (clips(cs.overflowX) || clips(cs.overflowY)) {
      clip = {l: clips(cs.overflowX) ? box.l : -Infinity, r: clips(cs.overflowX) ? box.r : Infinity,
              t: clips(cs.overflowY) ? box.t : -Infinity, b: clips(cs.overflowY) ? box.b : Infinity};
    }
    if (cs.clip && cs.clip.startsWith("rect(") && (cs.position === "absolute" || cs.position === "fixed")) {
      const v = cs.clip.slice(5, -1).split(/[ ,]+/).filter(Boolean);
      if (v.length === 4) {
        const at = (s, d) => s === "auto" ? d : parseFloat(s);
        const c = {t: box.t + at(v[0], 0), r: box.l + at(v[1], b.width), b: box.t + at(v[2], b.height),
                   l: box.l + at(v[3], 0)};
        clip = clip ? intersect(clip, c) : c;
      }
    }
    if (cs.clipPath && cs.clipPath.startsWith("inset(")) {
      const v = cs.clipPath.slice(6, -1).split(/\s+round\s+/)[0].split(/\s+/).filter(Boolean);
      if (v.length) {
        const top = v[0], right = v[1] || top, bottom = v[2] || top, left = v[3] || right;
        const c = {t: box.t + len(top, b.height), r: box.r - len(right, b.width), b: box.b - len(bottom, b.height),
                   l: box.l + len(left, b.width)};
        clip = clip ? intersect(clip, c) : c;
      }
    }
    clipCache.set(n, clip);
    return clip;
  }
  function textHidden(el, nodes) {
    if (!nodes.length || el.closest("select, datalist, textarea, svg")) return null;
    const clippers = [];
    for (let n = el; n && n.nodeType === 1 && n !== document.documentElement; n = n.parentElement) {
      const c = ownClip(n);
      if (c) clippers.push(c);
      const pos = getComputedStyle(n).position;
      if (pos === "fixed") break;
    }
    let anyArea = false, anyOnPage = false;
    for (const t of nodes) {
      const range = document.createRange();
      range.selectNodeContents(t);
      for (const r of range.getClientRects()) {
        let box = {l: r.left, t: r.top, r: r.right, b: r.bottom};
        for (const c of clippers) box = intersect(box, c);
        if (box.r - box.l > 0.5 && box.b - box.t > 0.5) {
          anyArea = true;
          if (box.r + sx > 0 && box.b + sy > 0) anyOnPage = true;
        }
      }
    }
    if (!anyArea) return "clipped";
    if (!anyOnPage) return "offscreen";
    return null;
  }
  function reason(el) {
    const cs = getComputedStyle(el);
    let vis = true;
    try {
      vis = el.checkVisibility({visibilityProperty: true, opacityProperty: true, checkOpacity: true,
                                checkVisibilityCSS: true});
    } catch (e) { vis = cs.display !== "none" && cs.visibility === "visible" && cs.opacity !== "0"; }
    if (!vis) {
      if (cs.display === "none") return "display";
      if (cs.visibility !== "visible") return "visibility";
      if (cs.opacity === "0") return "opacity";
      return "ancestor";
    }
    const nodes = ownTextNodes(el);
    const own = nodes.length > 0;
    if (own && parseFloat(cs.fontSize) === 0) return "font-size";
    if (own && transparent(cs.color)) return "color";
    const r = el.getBoundingClientRect();
    if ((r.width > 0 || r.height > 0) && (r.right + sx <= 0 || r.bottom + sy <= 0)) return "offscreen";
    if (r.width <= 1 && r.height <= 1 && el.textContent.trim() &&
        (cs.overflow !== "visible" || cs.clip !== "auto" || cs.clipPath !== "none")) return "clipped";
    if (own && !NO_GEOMETRY.has(el.nodeName)) {
      const why = textHidden(el, nodes);
      if (why) return why;
    }
    if (own && sameColour(el, cs)) return "same-colour";
    return null;
  }
  if (!document.body) return out;
  for (const el of document.body.querySelectorAll("*")) {
    if (SKIP.has(el.nodeName)) continue;
    const why = reason(el);
    if (!why) continue;
    el.setAttribute("data-witness-hidden", "1");
    if (out.length < MAX_NODES) {
      out.push({xpath: xpath(el), text: el.textContent.replace(/\s+/g, " ").trim().slice(0, MAX_TEXT), reason: why});
    }
  }
  return out;
}
