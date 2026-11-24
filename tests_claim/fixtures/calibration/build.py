#!/usr/bin/env python3
"""The match.text calibration set (SPEC §9.3, §11): 20 honest copies of dynamic, script-rendered and CSS-hidden-menu pages,
and 20 one-paragraph forgeries of the same pages. It sets T and F for match.text 1.0.0. Deterministic (fixed seed):

    python3 tests_claim/fixtures/calibration/build.py      # writes cases.json next to this file

Each case: {name, group, kind: honest|forgery, page: {response_body, response_media_type, rendered_html, hidden},
submitted: {data, media_type}}. The page is what the fetcher would return (rendered.html with data-witness-hidden marks on
the elements a browser does not show); the submitted text is what a person saved or copied from their own browser earlier.

Groups (5 pages each):
  script   the server HTML is an app shell, the text comes from script; the copy is the visible text (text/plain), taken
           earlier: a view counter and a relative time differ
  menu     a navigation drawer hidden by a stylesheet class (so present in the server HTML, absent from the screen); the copy
           is the visible text (text/plain), one "trending" item differs
  saved    "save page as" HTML (text/html) from earlier: another CSRF token, another sponsored line, another clock time
  static   a static article copied as text (text/plain), with typographic quotes and dashes and a different "checked" date
A forgery is the honest copy with one body paragraph replaced by a paragraph of similar length from elsewhere.
"""
import json
import pathlib
import random

HERE = pathlib.Path(__file__).resolve().parent

SENTENCES = [
    "The council approved the new budget after a long debate on Tuesday evening.",
    "Residents asked for more frequent buses on the northern routes during winter.",
    "The library will extend its opening hours on weekends starting next month.",
    "A local bakery won the regional award for its sourdough bread this year.",
    "Engineers found that the old bridge needs repairs before the spring floods.",
    "The school board said the new science wing should open in September.",
    "Volunteers planted more than four hundred trees along the river path.",
    "The museum is showing a collection of maps drawn by early sailors.",
    "Our support team answers most requests within one working day.",
    "Refunds are paid to the original card within fourteen days of the return.",
    "Every plan includes unlimited projects and a shared team workspace.",
    "You can export your data at any time as a single archive file.",
    "The service keeps daily backups for thirty days in two separate regions.",
    "We never sell personal information to advertisers or data brokers.",
    "The free tier allows three members and five gigabytes of storage.",
    "Two-factor sign-in is required for every administrator account.",
    "The trail climbs steadily for two kilometres before reaching the ridge.",
    "Bring water and a warm layer, because the weather changes quickly up there.",
    "Parking at the visitor centre fills up early on sunny Saturdays.",
    "Dogs are welcome on the lower paths but must be kept on a lead.",
    "The recipe needs flour, butter, a pinch of salt and cold water.",
    "Rest the dough in the fridge for at least an hour before rolling it out.",
    "Bake the tart until the edges are golden and the filling has set.",
    "Leftovers keep well in an airtight container for up to three days.",
    "The new firmware fixes a bug that drained the battery overnight.",
    "Users reported that the update also improved the speed of the camera app.",
    "The company says a second patch will follow before the end of the quarter.",
    "Older models will keep receiving security updates for two more years.",
    "Ticket prices rise by ten percent for the summer season.",
    "Children under five travel free when accompanied by an adult.",
    "The ferry runs every forty minutes between the harbour and the island.",
    "Delays are expected on the coastal line while the track is renewed.",
    "The study followed twelve hundred patients over a period of five years.",
    "Researchers found no link between the supplement and lower blood pressure.",
    "The authors call for a larger trial before any change to the guidelines.",
    "Funding for the project came from a public grant and two foundations.",
    "The festival returns to the old market square on the first weekend of June.",
    "Local bands will play on two stages from noon until late evening.",
    "Food stalls will offer dishes from more than twenty countries.",
    "Entry is free, but a donation to the community fund is welcome.",
    "The startup raised its first round from a group of angel investors.",
    "Its founders previously built payment tools for small online shops.",
    "The product checks invoices against purchase orders automatically.",
    "The team plans to hire ten engineers in the coming year.",
    "Heavy rain is forecast for the west of the region on Thursday.",
    "Temperatures will stay below average for the rest of the week.",
    "Farmers are advised to delay the harvest until the fields dry out.",
    "A yellow warning for wind is in place along the exposed coast.",
    "The club signed a young defender on a three-year contract.",
    "The coach praised the squad's discipline after the narrow away win.",
    "Season tickets for the new stadium go on sale in early August.",
    "The match on Sunday kicks off an hour earlier than usual.",
    "Please read the safety notes before you assemble the shelf.",
    "Tighten each screw by hand first and then use the supplied key.",
    "Do not place more than twenty kilograms on a single shelf.",
    "Contact the shop if any part is missing from the box.",
]
MENU = ["Home", "News", "Sport", "Weather", "Culture", "Business", "Contact", "Sign in", "Subscribe", "Archive"]
TRENDING = ["Bridge repairs", "Summer timetable", "New stadium", "Festival line-up", "Budget vote", "Flood warning",
            "Library hours", "Ferry delays"]
GROUPS = ("script", "menu", "saved", "static")


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def paragraphs(rng, n):
    return [" ".join(rng.sample(SENTENCES, rng.randint(2, 4))) for _ in range(n)]


def forged_paragraph(rng, original, used):
    """A paragraph of similar length made of sentences that are not in the page."""
    pool = [s for s in SENTENCES if s not in used]
    out, words = [], len(original.split())
    while len(" ".join(out).split()) < words - 4:
        out.append(pool.pop(rng.randrange(len(pool))))
    return " ".join(out)


def article(rng, i, group):
    title = f"{rng.choice(['Update', 'Notice', 'Report', 'Guide', 'Story'])} {i + 1}: " + rng.choice(SENTENCES).split(" ", 3)[-1][:40]
    paras = paragraphs(rng, rng.randint(3, 10))
    return {"title": title, "paras": paras, "group": group}


def visible_text(a, views, ago, trending, checked):
    lines = [a["title"], f"{views} views · Updated {ago}"]
    lines += a["paras"]
    lines += ["Trending", *trending, f"Last checked {checked}", "© 2026 Example News"]
    return lines


def rendered_html(a, views, ago, trending, checked, menu_hidden=True):
    nav = "".join(f"<li><a href='/{m.lower()}'>{m}</a></li>" for m in MENU)
    hid = ' data-witness-hidden="1"' if menu_hidden else ""
    body = (f"<header><nav class='drawer'{hid}><ul>{nav}</ul></nav></header><main><article><h1>{esc(a['title'])}</h1>"
            f"<p class='meta'>{views} views · Updated {ago}</p>" + "".join(f"<p>{esc(p)}</p>" for p in a["paras"]) +
            "</article><aside><h2>Trending</h2><ul>" + "".join(f"<li>{esc(t)}</li>" for t in trending) + "</ul></aside></main>"
            f"<footer><p>Last checked {checked}</p><p>© 2026 Example News</p></footer>")
    return f"<!doctype html><html><head><title>{esc(a['title'])}</title></head><body>{body}</body></html>"


def server_html(a, views, ago, trending, checked, csrf, sponsor, clock):
    nav = "".join(f"<li><a href='/{m.lower()}'>{m}</a></li>" for m in MENU)
    return ("<!doctype html><html><head><title>" + esc(a["title"]) + "</title><style>.drawer{display:none}</style>"
            f"<meta name='csrf' content='{csrf}'></head><body><header><nav class='drawer'><ul>{nav}</ul></nav></header>"
            f"<main><article><h1>{esc(a['title'])}</h1><p class='meta'>{views} views · Updated {ago}</p>"
            + "".join(f"<p>{esc(p)}</p>" for p in a["paras"]) +
            f"</article><aside><p>Sponsored: {esc(sponsor)}</p><h2>Trending</h2><ul>" + "".join(f"<li>{esc(t)}</li>" for t in trending)
            + f"</ul></aside></main><footer><p>Last checked {checked}</p><p>Page generated at {clock}</p>"
            "<p>© 2026 Example News</p></footer></body></html>")


def typographic(s):
    return s.replace(" - ", " – ").replace("'", "’")


def build():
    rng = random.Random(20261124)
    cases = []
    for gi, group in enumerate(GROUPS):
        for k in range(5):
            i = gi * 5 + k
            a = article(rng, i, group)
            trending = rng.sample(TRENDING, 4)
            views = rng.randint(1000, 90000)
            page_state = dict(views=f"{views:,}", ago=f"{rng.randint(2, 50)} minutes ago", trending=trending, checked="24 Nov 2026")
            copy_trending = list(trending)
            copy_trending[rng.randrange(4)] = rng.choice([t for t in TRENDING if t not in trending])
            copy_state = dict(views=f"{views - rng.randint(3, 400):,}", ago=f"{rng.randint(1, 9)} hours ago",
                              trending=copy_trending if group == "menu" else trending,
                              checked="23 Nov 2026" if group == "static" else "24 Nov 2026")
            hidden = [{"xpath": "/html/body/header/nav", "excerpt": " ".join(MENU), "sha256": "0" * 64, "reason": "display"}]
            if group == "script":
                response = ("<!doctype html><html><head><title>Loading…</title><script>window.__STATE__={\"id\":%d}</script>"
                            "</head><body><div id='root'></div><noscript>Enable JavaScript.</noscript>"
                            "<script src='/app.js'></script></body></html>" % i)
            else:
                response = server_html(a, csrf=f"{rng.getrandbits(64):016x}", sponsor="Save on winter tyres",
                                       clock="09:14:03", **page_state)
            pg = {"response_body": response, "response_media_type": "text/html",
                  "rendered_html": rendered_html(a, **page_state), "hidden": hidden}

            def submitted(article_):
                if group == "saved":
                    return {"data": server_html(article_, csrf=f"{rng.getrandbits(64):016x}", sponsor="Fresh coffee delivered",
                                                clock="08:51:47", **copy_state), "media_type": "text/html"}
                lines = visible_text(article_, **copy_state)
                if group == "static":
                    lines = [typographic(x) for x in lines]
                return {"data": "\n\n".join(lines) + "\n", "media_type": "text/plain"}

            cases.append({"name": f"{group}-{k + 1}-honest", "group": group, "kind": "honest", "page": pg, "submitted": submitted(a)})
            j = rng.randrange(len(a["paras"]))
            used = set(" ".join(a["paras"]).split(". "))
            forged = dict(a, paras=list(a["paras"]))
            forged["paras"][j] = forged_paragraph(rng, a["paras"][j], {s for s in SENTENCES if s in " ".join(a["paras"])} | used)
            cases.append({"name": f"{group}-{k + 1}-forgery", "group": group, "kind": "forgery", "page": pg,
                          "submitted": submitted(forged), "changed_paragraph": j})
    return cases


if __name__ == "__main__":
    out = HERE / "cases.json"
    out.write_text(json.dumps(build(), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out}")
