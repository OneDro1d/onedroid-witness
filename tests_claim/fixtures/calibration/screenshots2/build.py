#!/usr/bin/env python3
"""The second match.screenshot calibration set (DECISIONS BD19, README_CLAIM.md decision 157): the first set
(../screenshots/, decision 74) had honest screenshots at widths 1280 and 390 only, 116 to 165 tokens per page, and it let T/F
sit where an honest 1000 x 420 screenshot of a 45-token page (9111 bp) was signed `differs`. This set widens the honest side
and keeps the forgeries on the same layouts. Deterministic (fixed seed, pinned browser):

    /home/coder/.venvs/dewgrub/bin/python tests_claim/fixtures/calibration/screenshots2/build.py   # cases.json, pages/, images/

Built with Playwright 1.63.0 and the Chromium headless shell 1255 installed here (CHROMIUM_BIN=.../chromium_headless_shell-1255/
chrome-headless-shell-linux64/chrome-headless-shell, the build Playwright 1.63 expects is not installed), DejaVu Serif / Sans / Sans Mono; the images are committed
and cases.json holds every file's sha256 (measure.py checks them first). Reuses the first set's article and forgery code.

Layouts (width, device scale factor, family, size): widths 1000, 1024, 1440, 1280 and 390; scale 1 and 2; serif and sans.
Pages: 12 articles, half of them SHORT (3 paragraphs of 1 or 2 sentences, about 40 to 70 tokens) and half long (4 to 6
paragraphs); every page carries a navigation bar, a byline with "—" and "·", a monospace "Ref" line with an id-like token (a
uuid, a hex digest prefix or a-b_c), and a footer.

Cases (each image is compared with the page named by the case):
  honest     per article: full page or crop of two consecutive paragraphs x PNG or JPEG 80 (4), plus the full-page PNG
             resampled by 0.75 and by 0.5 in the browser (canvas, high quality) and kept as PNG (2)           -> 12 x 6 = 72
  forgery    the same views of the page with exactly one sentence (inside the cropped paragraphs) replaced by a sentence of
             similar length that is not in the page, compared with the ORIGINAL page (6 per article)           -> 72
  unrelated  an honest screenshot of another article, compared with this page                                  -> 12
"""
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import random
import uuid

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("shots1_build", HERE.parent / "screenshots" / "build.py")
b1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b1)

SEED = 20261125
LAYOUTS = [  # (width, device scale factor, font family, font size px, line height)
    (1000, 1, "DejaVu Serif", 18, 1.5),
    (1000, 1, "DejaVu Sans", 14, 1.4),
    (1024, 1, "DejaVu Sans", 14, 1.4),
    (1024, 1, "DejaVu Serif", 18, 1.5),
    (1440, 1, "DejaVu Serif", 18, 1.5),
    (1440, 1, "DejaVu Sans", 14, 1.4),
    (1280, 2, "DejaVu Sans", 14, 1.4),
    (1000, 2, "DejaVu Serif", 18, 1.5),
    (1280, 1, "DejaVu Serif", 18, 1.5),
    (390, 2, "DejaVu Sans", 14, 1.4),
    (1280, 1, "DejaVu Sans", 14, 1.4),
    (390, 2, "DejaVu Serif", 18, 1.5),
]
N = len(LAYOUTS)
SCALES = (0.75, 0.5)


def ref_token(rng, i):
    kind = i % 3
    if kind == 0:
        return str(uuid.UUID(int=rng.getrandbits(128), version=4))
    if kind == 1:
        return "".join(rng.choice("0123456789abcdef") for _ in range(24))
    return "-".join("".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(3, 6))) for _ in range(3)).replace("-", "_", 1)


def article(rng, i):
    short = i % 2 == 0
    title = rng.choice(b1.SECTIONS) + ": " + rng.choice(b1.BANK).split(" ", 2)[-1].rstrip(".")[:40].rstrip()
    sentences = rng.sample(b1.BANK, 18)
    paras, k = [], 0
    for _ in range(3 if short else rng.randint(4, 6)):
        n = rng.randint(1, 2) if short else rng.randint(2, 3)
        paras.append(sentences[k:k + n])
        k += n
    return {"id": f"b{i + 1}", "title": title, "short": short, "ref": ref_token(rng, i), "paras": paras,
            "byline": f"By the newsroom — {rng.randint(1, 28)} November 2026 · {rng.randint(2, 9)} min read"}


def page_html(a, layout):
    _, _, family, size, lh = layout
    style = (f"body{{margin:0;font-family:'{family}';font-size:{size}px;line-height:{lh};color:#1a1a1a;background:#fff}}"
             "header{background:#f2f2f2;border-bottom:1px solid #ccc;padding:8px 16px}"
             "header .brand{font-weight:bold;margin-right:16px}nav a{margin-right:12px;color:#0645ad;text-decoration:none}"
             "main{max-width:760px;margin:0 auto;padding:16px}h1{font-size:1.6em;line-height:1.25;margin:0.4em 0}"
             ".byline{color:#555}code.ref{font-family:'DejaVu Sans Mono';font-size:0.85em;word-break:break-all}"
             "footer{border-top:1px solid #ccc;padding:12px 16px;color:#555;margin-top:24px}")
    nav = "".join(f"<a href='/{n.lower()}'>{n}</a>" for n in b1.NAV)
    body = "".join(f"<p id='p{j}'>{b1.esc(' '.join(p))}</p>" for j, p in enumerate(a["paras"]))
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
            f"<title>{b1.esc(a['title'])}</title><style>{style}</style></head><body><header><span class='brand'>Example News</span>"
            f"<nav>{nav}</nav></header><main><article><h1>{b1.esc(a['title'])}</h1><p class='byline'>{b1.esc(a['byline'])}</p>{body}"
            f"<p>Ref: <code class='ref'>{a['ref']}</code></p></article></main>"
            "<footer><p>Example News, 1 Harbour Street. Corrections: desk@example.org</p></footer></body></html>")


def forge(rng, a):
    crop = rng.randrange(len(a["paras"]) - 1)
    spots = [(j, s) for j in (crop, crop + 1) for s in range(len(a["paras"][j]))]
    j, s = rng.choice(spots)
    old = a["paras"][j][s]
    used = {x for p in a["paras"] for x in p}
    pool = [x for x in b1.BANK if x not in used and abs(len(x.split()) - len(old.split())) <= 3]
    new = rng.choice(pool)
    paras = [list(p) for p in a["paras"]]
    paras[j][s] = new
    return dict(a, paras=paras), crop, {"paragraph": j, "sentence": s, "old": old, "new": new}


def sha(b):
    return hashlib.sha256(b).hexdigest()


RESAMPLE = """async ([b64, scale]) => { const img = new Image(); img.src = 'data:image/png;base64,' + b64; await img.decode();
    const c = document.createElement('canvas'); c.width = Math.round(img.width * scale); c.height = Math.round(img.height * scale);
    const g = c.getContext('2d'); g.imageSmoothingEnabled = true; g.imageSmoothingQuality = 'high'; g.drawImage(img, 0, 0, c.width, c.height);
    return c.toDataURL('image/png').split(',')[1]; }"""


def shoot(browser, html, layout, crop):
    """{(view, fmt): bytes} and the DOM after load (page.content())."""
    width, dpr = layout[0], layout[1]
    ctx = browser.new_context(viewport={"width": width, "height": 800}, device_scale_factor=dpr)
    page = ctx.new_page()
    page.set_content(html, wait_until="load")
    page.evaluate("document.fonts.ready")
    dom = page.content()
    box = page.evaluate("""(ids) => { const r = ids.map(i => document.getElementById(i).getBoundingClientRect());
        const top = Math.min(...r.map(x => x.top)) + window.scrollY, bottom = Math.max(...r.map(x => x.bottom)) + window.scrollY;
        return {x: 0, y: Math.max(0, Math.floor(top) - 6), width: document.documentElement.clientWidth,
                height: Math.ceil(bottom - top) + 12}; }""", [f"p{crop}", f"p{crop + 1}"])
    out = {}
    for fmt in ("png", "jpeg"):
        kw = {"type": fmt, "animations": "disabled", "caret": "hide"}
        if fmt == "jpeg":
            kw["quality"] = 80
        out[("full", fmt)] = page.screenshot(full_page=True, **kw)
        out[("crop", fmt)] = page.screenshot(full_page=True, clip=box, **kw)
    ctx.close()
    ctx = browser.new_context(viewport={"width": 800, "height": 600})
    rp = ctx.new_page()
    for sc in SCALES:
        small = rp.evaluate(RESAMPLE, [base64.b64encode(out[("full", "png")]).decode(), sc])
        out[(f"full-s{int(sc * 100)}", "png")] = base64.b64decode(small)
    ctx.close()
    return out, dom


def build():
    from playwright.sync_api import sync_playwright
    rng = random.Random(SEED)
    (HERE / "images").mkdir(exist_ok=True)
    (HERE / "pages").mkdir(exist_ok=True)
    articles = [article(rng, i) for i in range(N)]
    cases, shots = [], {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--font-render-hinting=none"], executable_path=os.environ.get("CHROMIUM_BIN") or None)
        meta = {"browser": "chromium " + browser.version, "playwright": "1.63.0", "seed": SEED}
        for i, a in enumerate(articles):
            layout = LAYOUTS[i % N]
            forged, crop, where = forge(rng, a)
            real, dom = shoot(browser, page_html(a, layout), layout, crop)
            fake, _ = shoot(browser, page_html(forged, layout), layout, crop)
            page_file = f"pages/{a['id']}.html"
            (HERE / page_file).write_text(dom, encoding="utf-8")
            info = {"page": page_file, "page_sha256": sha(dom.encode("utf-8")), "article": a["id"], "width": layout[0],
                    "dpr": layout[1], "font": f"{layout[2]} {layout[3]}px", "short": a["short"]}
            for kind, imgs in (("honest", real), ("forgery", fake)):
                for (view, fmt), data in sorted(imgs.items()):
                    ext = "png" if fmt == "png" else "jpg"
                    name = f"{a['id']}-{kind}-{view}-{ext}"
                    (HERE / "images" / f"{name}.{ext}").write_bytes(data)
                    case = dict(info, name=name, kind=kind, view=view, format=ext, image=f"images/{name}.{ext}", image_sha256=sha(data))
                    if kind == "forgery":
                        case["replaced"] = where
                    cases.append(case)
                    if kind == "honest":
                        shots[(a["id"], view, ext)] = case
        browser.close()
    for i, a in enumerate(articles):
        other = articles[(i + 5) % N]
        view, ext = (("full", "png"), ("crop", "jpg"))[i % 2]
        src = shots[(other["id"], view, ext)]
        mine = next(c for c in cases if c["article"] == a["id"])
        cases.append({"page": mine["page"], "page_sha256": mine["page_sha256"], "article": a["id"], "width": src["width"],
                      "dpr": src["dpr"], "font": src["font"], "short": a["short"], "name": f"{a['id']}-unrelated-{other['id']}-{view}-{ext}",
                      "kind": "unrelated", "view": view, "format": ext, "image": src["image"],
                      "image_sha256": src["image_sha256"], "image_of": other["id"]})
    return {"meta": meta, "cases": cases}


if __name__ == "__main__":
    doc = build()
    out = HERE / "cases.json"
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out}: {len(doc['cases'])} cases, {doc['meta']}")
