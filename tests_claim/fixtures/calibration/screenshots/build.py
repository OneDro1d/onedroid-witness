#!/usr/bin/env python3
"""The match.screenshot calibration set (SPEC §9.3, §11): real Chromium screenshots of article pages, compared with the
pages' own text. It sets T and F for match.screenshot. Deterministic (fixed seed, pinned browser):

    python3 -m venv /tmp/pw && /tmp/pw/bin/pip install playwright==1.49.1 && /tmp/pw/bin/playwright install chromium
    /tmp/pw/bin/python tests_claim/fixtures/calibration/screenshots/build.py   # writes cases.json, pages/, images/

The images are committed, because a screenshot depends on the browser build and the fonts (this set: Playwright 1.49.1,
Chromium 131.0.6778.33 headless shell, DejaVu Serif and DejaVu Sans); cases.json holds every file's sha256, and
measure.py checks them before it reads anything. measured.json is written by measure.py run INSIDE the claim-witness
image (the same Tesseract, language data and command line as the witness): see README_CLAIM.md, match.screenshot.

Pages: 8 articles (title, byline, 4 to 6 paragraphs of 2 or 3 sentences, a navigation bar and a footer), each rendered in
one of four layouts: width 1280 at device scale 1 or width 390 at device scale 2 (a phone), DejaVu Serif 18px or DejaVu
Sans 14px. The page side of a case is the browser's DOM after load (page.content()), i.e. what the fetcher stores as
rendered.html; match.screenshot compares with its text.canonical.txt (canon/1, rendered layer).

Cases (each image is compared with the page named by the case):
  honest     a screenshot of the page: full page or a crop (the box of two consecutive body paragraphs, the full width of
             the window), PNG or JPEG (quality 80)  -> 8 pages x 2 views x 2 formats = 32
  forgery    a screenshot of the same page with exactly one sentence (inside the cropped paragraphs) replaced by a sentence
             of similar length (within 3 words) that is not in the page, compared with the ORIGINAL page  -> 32
  unrelated  an honest screenshot of another article, compared with this page  -> 8 (one per page)
"""
import hashlib
import json
import pathlib
import random
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from build import SENTENCES  # noqa: E402  the match.text calibration's sentence bank

SEED = 20261124
LAYOUTS = [  # (width, device scale factor, font family, font size px, line height)
    (1280, 1, "DejaVu Serif", 18, 1.5),
    (1280, 1, "DejaVu Sans", 14, 1.4),
    (390, 2, "DejaVu Serif", 18, 1.5),
    (390, 2, "DejaVu Sans", 14, 1.4),
]
NAV = ["Home", "World", "Business", "Science", "Travel", "Weather", "Contact"]
SECTIONS = ["Local news", "Technology", "Travel", "Health", "Culture", "Sport", "Weather", "Business"]
EXTRA = [
    "The harbour ferry now runs every forty minutes in summer.",
    "The new reading room seats sixty people and has quiet booths.",
    "A second clinic will open on the east side of town in spring.",
    "The orchestra will tour six cities before returning in March.",
    "Most of the old station building will become a public market.",
    "The council will publish the full survey results next week.",
    "Night buses will stop at the hospital and the university campus.",
    "The town hall clock was repaired by a team of local volunteers.",
    "Cyclists asked for a protected lane along the main shopping street.",
    "The swimming pool closes for three weeks of maintenance in July.",
    "Online booking for the summer camps opens on the first of May.",
    "The water company plans to replace twelve kilometres of old pipes.",
]
BANK = SENTENCES + EXTRA


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def article(rng, i):
    title = rng.choice(SECTIONS) + ": " + rng.choice(BANK).split(" ", 2)[-1].rstrip(".")[:48].rstrip()
    sentences = rng.sample(BANK, 18)
    paras, k = [], 0
    for _ in range(rng.randint(4, 6)):
        n = rng.randint(2, 3)
        paras.append(sentences[k:k + n])
        k += n
    return {"id": f"a{i + 1}", "title": title, "byline": f"By the newsroom, {rng.randint(1, 28)} November 2026", "paras": paras}


def page_html(a, layout):
    _, _, family, size, lh = layout
    style = (f"body{{margin:0;font-family:'{family}';font-size:{size}px;line-height:{lh};color:#1a1a1a;background:#fff}}"
             "header{background:#f2f2f2;border-bottom:1px solid #ccc;padding:8px 16px}"
             "header .brand{font-weight:bold;margin-right:16px}nav a{margin-right:12px;color:#0645ad;text-decoration:none}"
             "main{max-width:760px;margin:0 auto;padding:16px}h1{font-size:1.6em;line-height:1.25;margin:0.4em 0}"
             ".byline{color:#555}footer{border-top:1px solid #ccc;padding:12px 16px;color:#555;margin-top:24px}")
    nav = "".join(f"<a href='/{n.lower()}'>{n}</a>" for n in NAV)
    body = "".join(f"<p id='p{j}'>{esc(' '.join(p))}</p>" for j, p in enumerate(a["paras"]))
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
            f"<title>{esc(a['title'])}</title><style>{style}</style></head><body><header><span class='brand'>Example News</span>"
            f"<nav>{nav}</nav></header><main><article><h1>{esc(a['title'])}</h1><p class='byline'>{esc(a['byline'])}</p>{body}"
            "</article></main><footer><p>Example News, 1 Harbour Street. Corrections: desk@example.org</p></footer>"
            "</body></html>")


def forge(rng, a):
    """The article with exactly one sentence replaced, inside paragraphs crop..crop+1: (forged article, crop, where)."""
    crop = rng.randrange(len(a["paras"]) - 1)
    spots = [(j, s) for j in (crop, crop + 1) for s in range(len(a["paras"][j]))]
    j, s = rng.choice(spots)
    old = a["paras"][j][s]
    used = {x for p in a["paras"] for x in p}
    pool = [x for x in BANK if x not in used and abs(len(x.split()) - len(old.split())) <= 3]
    new = rng.choice(pool)
    paras = [list(p) for p in a["paras"]]
    paras[j][s] = new
    return dict(a, paras=paras), crop, {"paragraph": j, "sentence": s, "old": old, "new": new}


def sha(b):
    return hashlib.sha256(b).hexdigest()


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
    return out, dom


def build():
    from playwright.sync_api import sync_playwright
    rng = random.Random(SEED)
    (HERE / "images").mkdir(exist_ok=True)
    (HERE / "pages").mkdir(exist_ok=True)
    articles = [article(rng, i) for i in range(8)]
    cases, shots = [], {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--font-render-hinting=none"])
        meta = {"browser": "chromium " + browser.version, "playwright": "1.49.1", "seed": SEED}
        for i, a in enumerate(articles):
            layout = LAYOUTS[i % 4]
            forged, crop, where = forge(rng, a)
            real, dom = shoot(browser, page_html(a, layout), layout, crop)
            fake, _ = shoot(browser, page_html(forged, layout), layout, crop)
            page_file = f"pages/{a['id']}.html"
            (HERE / page_file).write_text(dom, encoding="utf-8")
            info = {"page": page_file, "page_sha256": sha(dom.encode("utf-8")), "article": a["id"], "width": layout[0],
                    "dpr": layout[1], "font": f"{layout[2]} {layout[3]}px"}
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
    # unrelated: another article's honest screenshot against this page (alternating full png / crop jpg)
    for i, a in enumerate(articles):
        other = articles[(i + 3) % len(articles)]
        view, ext = (("full", "png"), ("crop", "jpg"))[i % 2]
        src = shots[(other["id"], view, ext)]
        mine = next(c for c in cases if c["article"] == a["id"])
        cases.append({"page": mine["page"], "page_sha256": mine["page_sha256"], "article": a["id"], "width": src["width"],
                      "dpr": src["dpr"], "font": src["font"], "name": f"{a['id']}-unrelated-{other['id']}-{view}-{ext}",
                      "kind": "unrelated", "view": view, "format": ext, "image": src["image"],
                      "image_sha256": src["image_sha256"], "image_of": other["id"]})
    return {"meta": meta, "cases": cases}


if __name__ == "__main__":
    doc = build()
    out = HERE / "cases.json"
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out}: {len(doc['cases'])} cases, {doc['meta']}")
