#!/usr/bin/env python3
"""
privacy_scanner.py - find data-broker / people-search sites that list you,
and get a report with a direct opt-out link for each one.

SETUP
    pip install ddgs            # free search backend, no API key needed

USAGE
    python privacy_scanner.py                       # interactive prompts
    python privacy_scanner.py --name "Jane Q Doe" --city Bluffton --state SC \
        --email jane@example.com --phone 843-555-0123 --deep

    Optional: set BRAVE_API_KEY and add --engine brave for a more reliable
    backend than DuckDuckGo (Brave Search API has a free tier).

HOW IT WORKS
    1. Builds search queries from your name / city / email / phone / street.
    2. Runs them through a search engine (--deep also runs a site: query
       against every broker in the built-in directory).
    3. Matches result domains against a directory of known brokers, scores how
       likely each hit is really you, and writes privacy_report.html + .json.

PRIVACY NOTES
    * Nothing is sent anywhere except your search queries to the search engine.
      Those queries contain your info - that is unavoidable for any search.
    * The report contains your personal data. Keep it local, delete it when done.
    * Opt-out URLs change often. Verify each page before submitting anything.
"""
import argparse
import datetime
import html
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

# --------------------------------------------------------------------------
# Broker directory: domain -> (display name, opt-out URL, note)
# Verify links before relying on them; brokers move these pages regularly.
# --------------------------------------------------------------------------
PEOPLECONNECT = "https://suppression.peopleconnect.us/login"
BROKERS = {
    "spokeo.com": ("Spokeo", "https://www.spokeo.com/optout", "Paste your listing URL into the form, then confirm via email."),
    "whitepages.com": ("Whitepages", "https://www.whitepages.com/suppression-requests", "Find your listing, then verify by phone."),
    "beenverified.com": ("BeenVerified", "https://www.beenverified.com/app/optout/search", "Search for your record, then confirm via email."),
    "peoplelooker.com": ("PeopleLooker", "https://www.peoplelooker.com/f/optout/search", "Same parent company as BeenVerified; opt out separately."),
    "intelius.com": ("Intelius", PEOPLECONNECT, "PeopleConnect suppression center covers several brands."),
    "instantcheckmate.com": ("Instant Checkmate", PEOPLECONNECT, "PeopleConnect suppression center."),
    "truthfinder.com": ("TruthFinder", PEOPLECONNECT, "PeopleConnect suppression center."),
    "ussearch.com": ("US Search", PEOPLECONNECT, "PeopleConnect suppression center."),
    "truepeoplesearch.com": ("TruePeopleSearch", "https://www.truepeoplesearch.com/removal", "Find your record, then click Remove This Record."),
    "fastpeoplesearch.com": ("FastPeopleSearch", "https://www.fastpeoplesearch.com/removal", "Search for your record, then submit removal."),
    "radaris.com": ("Radaris", "https://radaris.com/control/privacy", "Account may be required; remove each profile."),
    "peoplefinders.com": ("PeopleFinders", "https://www.peoplefinders.com/opt-out", "Locate your record, then submit."),
    "thatsthem.com": ("ThatsThem", "https://thatsthem.com/optout", "Opt out by listing URL."),
    "nuwber.com": ("Nuwber", "https://nuwber.com/removal/link", "Submit the profile link."),
    "zabasearch.com": ("ZabaSearch", "https://www.zabasearch.com/block_records/", "Requires a copy of ID in some cases."),
    "clustrmaps.com": ("ClustrMaps", "https://clustrmaps.com/bl/opt-out", "Submit the listing URL."),
    "smartbackgroundchecks.com": ("SmartBackgroundChecks", "https://www.smartbackgroundchecks.com/optout", "Find your record, then remove."),
    "advancedbackgroundchecks.com": ("AdvancedBackgroundChecks", "https://www.advancedbackgroundchecks.com/removal", "Submit the listing URL."),
    "cyberbackgroundchecks.com": ("CyberBackgroundChecks", "https://www.cyberbackgroundchecks.com/removal", "Submit the listing URL."),
    "checkpeople.com": ("CheckPeople", "https://www.checkpeople.com/opt-out", "Locate your record, then submit."),
    "usphonebook.com": ("USPhoneBook", "https://www.usphonebook.com/opt-out", "Find your listing, then opt out."),
    "spydialer.com": ("Spy Dialer", "https://www.spydialer.com/optout.aspx", "Phone-number based removal."),
    "peekyou.com": ("PeekYou", "https://www.peekyou.com/about/contact/optout/", "Submit your profile URL."),
    "privateeye.com": ("PrivateEye", "https://www.privateeye.com/static/view/optout/", "Opt-out form."),
    "mylife.com": ("MyLife", "https://www.mylife.com/ccpa/index.pubview", "Privacy request form; may require follow-up."),
    "pipl.com": ("Pipl", "https://pipl.com/personal-information-removal-request", "Removal request form."),
    "acxiom.com": ("Acxiom", "https://isapps.acxiom.com/optout/optout.aspx", "Marketing-data broker opt-out."),
}

EXTRA_RESOURCES = [
    ("Google: Results about you", "https://myaccount.google.com/results-about-you",
     "Ask Google to hide search results containing your phone, address, or email."),
    ("Google: Remove outdated content", "https://search.google.com/search-console/remove-outdated-content",
     "After a site deletes your info, make Google drop the cached copy."),
    ("FTC: Identity theft resources", "https://www.identitytheft.gov/",
     "If you see signs your data is being misused."),
]

BROKER_HINTS = ("people", "person", "finder", "lookup", "records", "background",
                "whitepages", "phonebook", "reverse", "checks", "search", "public",
                "address", "find", "who", "profile")

CONF_ORDER = {"high": 0, "medium": 1, "low": 2}

# --------------------------------------------------------------------------
# Search backends
# --------------------------------------------------------------------------
def search_ddg(query, max_results):
    try:
        from ddgs import DDGS
    except ImportError:
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            sys.exit("Missing dependency. Run: pip install ddgs")
    with DDGS() as d:
        rows = d.text(query, max_results=max_results) or []
    return [{"title": r.get("title", ""), "url": r.get("href") or r.get("url", ""),
             "snippet": r.get("body", "")} for r in rows]


def search_brave(query, max_results):
    key = os.environ.get("BRAVE_API_KEY")
    if not key:
        sys.exit("Set the BRAVE_API_KEY environment variable to use --engine brave.")
    url = "https://api.search.brave.com/res/v1/web/search?" + urllib.parse.urlencode(
        {"q": query, "count": min(max_results, 20)})
    req = urllib.request.Request(url, headers={"X-Subscription-Token": key, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    return [{"title": r.get("title", ""), "url": r.get("url", ""),
             "snippet": r.get("description", "")} for r in data.get("web", {}).get("results", [])]


def run_search(engine, query, max_results, retries=2):
    fn = search_brave if engine == "brave" else search_ddg
    for attempt in range(retries + 1):
        try:
            return fn(query, max_results)
        except SystemExit:
            raise
        except Exception as exc:  # rate limits, network hiccups
            if attempt == retries:
                print("   ! search failed (%s)" % exc)
                return []
            time.sleep(3 * (attempt + 1))
    return []

# --------------------------------------------------------------------------
# Matching and scoring
# --------------------------------------------------------------------------
def hostname(url):
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def match_broker(host):
    for domain in BROKERS:
        if host == domain or host.endswith("." + domain):
            return domain
    return None


def looks_like_broker(host):
    return any(h in host for h in BROKER_HINTS)


def digits(s):
    return re.sub(r"\D", "", s or "")


def score(result, profile):
    text = " ".join([result["title"], result["snippet"], result["url"]]).lower()
    pts = 0
    first, last = profile["first"].lower(), profile["last"].lower()
    if first in text and last in text:
        pts += 2
    elif last in text:
        pts += 1
    if profile["city"] and profile["city"].lower() in text:
        pts += 1
    text_digits = digits(text)
    for phone in profile["phones"]:
        p = digits(phone)[-10:]
        if p and p in text_digits:
            pts += 3
    for email in profile["emails"]:
        if email.lower() in text:
            pts += 3
    if profile["street"] and profile["street"].lower() in text:
        pts += 3
    return "high" if pts >= 4 else "medium" if pts >= 2 else "low", pts


def build_queries(profile, deep):
    qs = []
    for name in profile["names"]:
        loc = " ".join(x for x in (profile["city"], profile["state"]) if x)
        qs.append('"%s" %s' % (name, loc))
        qs.append('"%s" %s age address phone relatives' % (name, profile["state"]))
        if profile["street"]:
            qs.append('"%s" "%s"' % (name, profile["street"]))
    for phone in profile["phones"]:
        qs.append('"%s"' % phone)
    for email in profile["emails"]:
        qs.append('"%s"' % email)
    if deep:
        name, loc = profile["names"][0], profile["city"]
        for domain in BROKERS:
            qs.append('site:%s "%s" %s' % (domain, name, loc))
    seen, out = set(), []
    for q in qs:
        if q not in seen:
            seen.add(q)
            out.append(q)
    return out

# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------
CSS = """
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--card:#f6f6f4;--bd:#ddd;--acc:#0b5fff;--hi:#c62828;--md:#b26a00;--lo:#555}
@media(prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee;--mut:#9a9a9a;--card:#222;--bd:#383838;--acc:#6ea0ff;--hi:#ef6b6b;--md:#e8a33d;--lo:#999}}
body{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:860px;margin:0 auto;padding:24px}
h1{font-size:22px}h2{font-size:17px;margin-top:32px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;margin:12px 0}
.row{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}
.tag{font-size:12px;font-weight:600;text-transform:uppercase}
.high{color:var(--hi)}.medium{color:var(--md)}.low{color:var(--lo)}
a{color:var(--acc)}.btn{display:inline-block;padding:6px 12px;border:1px solid var(--acc);border-radius:6px;text-decoration:none;font-weight:600}
.mut{color:var(--mut);font-size:13px}ul{margin:6px 0;padding-left:20px;overflow-wrap:anywhere}
details{margin-top:12px}summary{cursor:pointer}
"""

JS = """
document.querySelectorAll('input[data-k]').forEach(function(b){
 try{b.checked=localStorage.getItem('ps:'+b.dataset.k)==='1'}catch(e){}
 b.addEventListener('change',function(){try{localStorage.setItem('ps:'+b.dataset.k,b.checked?'1':'0')}catch(e){}});
});
"""


def esc(s):
    return html.escape(s or "", quote=True)


def broker_card(domain, info):
    name, optout, note = info["name"], info["optout"], info["note"]
    hits = "".join(
        '<li><a href="%s" target="_blank" rel="noopener">%s</a> <span class="mut">(%s)</span></li>'
        % (esc(h["url"]), esc(h["title"] or h["url"]), h["conf"]) for h in info["hits"][:6])
    btn = ('<a class="btn" href="%s" target="_blank" rel="noopener">Opt out</a>' % esc(optout)
           if optout else '<span class="mut">No known opt-out link: check the site footer for "Do Not Sell" / "Opt Out"</span>')
    return ('<div class="card"><div class="row"><div><strong>%s</strong> '
            '<span class="tag %s">%s match</span></div>'
            '<label><input type="checkbox" data-k="%s"> removed</label></div>'
            '<ul>%s</ul><div class="row"><span class="mut">%s</span>%s</div></div>'
            % (esc(name), info["best"], info["best"], esc(domain), hits, esc(note), btn))


def render_report(profile, found, possible, unchecked, queries_run):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    parts = ['<!doctype html><meta charset="utf-8"><title>Privacy scan report</title>'
             '<meta name="viewport" content="width=device-width,initial-scale=1"><style>%s</style>' % CSS,
             "<h1>Privacy scan report</h1>",
             '<p class="mut">%s &middot; %d queries &middot; searched for %s. Contains personal data: keep it local.</p>'
             % (now, queries_run, esc(", ".join(profile["names"])))]

    parts.append("<h2>Known data brokers that appear to list you (%d)</h2>" % len(found))
    if found:
        ordered = sorted(found.items(), key=lambda kv: (CONF_ORDER[kv[1]["best"]], kv[1]["name"]))
        parts += [broker_card(d, i) for d, i in ordered]
    else:
        parts.append('<p class="mut">None found via search. Brokers often hide listings from search engines, so check the list below too.</p>')

    if possible:
        parts.append("<h2>Unrecognized sites that may be people-search brokers (%d)</h2>" % len(possible))
        parts += [broker_card(d, i) for d, i in sorted(possible.items())]

    parts.append("<h2>Other resources</h2>")
    for title, url, note in EXTRA_RESOURCES:
        parts.append('<div class="card"><a href="%s" target="_blank" rel="noopener">%s</a><div class="mut">%s</div></div>'
                     % (esc(url), esc(title), esc(note)))

    parts.append("<details><summary>Brokers not found in search, but worth checking (%d)</summary>" % len(unchecked))
    for d, (name, optout, note) in sorted(unchecked.items(), key=lambda kv: kv[1][0]):
        parts.append('<div class="card"><div class="row"><div><strong>%s</strong><div class="mut">%s</div></div>'
                     '<div><label><input type="checkbox" data-k="%s"> done</label> '
                     '<a class="btn" href="%s" target="_blank" rel="noopener">Check / opt out</a></div></div></div>'
                     % (esc(name), esc(note), esc(d), esc(optout)))
    parts.append("</details>")
    parts.append('<p class="mut">Opt-out pages change. Verify each one, and re-scan every few months since brokers re-list data.</p>')
    parts.append("<script>%s</script>" % JS)
    return "\n".join(parts)

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def ask(prompt, default=""):
    val = input("%s%s: " % (prompt, " [%s]" % default if default else "")).strip()
    return val or default


def get_profile(args):
    name = args.name or ask("Full name")
    if not name or len(name.split()) < 2:
        sys.exit("Please provide at least a first and last name.")
    interactive = not args.name
    city = args.city if args.city is not None else (ask("City", "") if interactive else "")
    state = args.state if args.state is not None else (ask("State (2-letter)", "") if interactive else "")
    emails = args.email or ([e for e in ask("Email(s), comma-separated").split(",") if e.strip()] if interactive else [])
    phones = args.phone or ([p for p in ask("Phone(s), comma-separated").split(",") if p.strip()] if interactive else [])
    street = args.street if args.street is not None else (ask("Street address (optional)") if interactive else "")
    parts = name.split()
    return {"names": [name] + (args.aka or []), "first": parts[0], "last": parts[-1],
            "city": city.strip(), "state": state.strip(), "street": street.strip(),
            "emails": [e.strip() for e in emails], "phones": [p.strip() for p in phones]}


def main():
    ap = argparse.ArgumentParser(description="Find sites that list your personal info and get opt-out links.")
    ap.add_argument("--name"); ap.add_argument("--aka", action="append", help="alternate name (repeatable)")
    ap.add_argument("--city"); ap.add_argument("--state"); ap.add_argument("--street")
    ap.add_argument("--email", action="append"); ap.add_argument("--phone", action="append")
    ap.add_argument("--deep", action="store_true", help="also run a site: query against every known broker")
    ap.add_argument("--engine", choices=["ddg", "brave"], default="ddg")
    ap.add_argument("--max-results", type=int, default=20)
    ap.add_argument("--delay", type=float, default=2.5, help="seconds between queries")
    ap.add_argument("--out", default="privacy_report", help="output file prefix")
    ap.add_argument("--open", action="store_true", help="open the HTML report when done")
    args = ap.parse_args()

    profile = get_profile(args)
    queries = build_queries(profile, args.deep)
    print("Running %d searches (this can take a few minutes)..." % len(queries))

    found, possible, seen_urls = {}, {}, set()
    for i, q in enumerate(queries, 1):
        print("[%d/%d] %s" % (i, len(queries), q))
        for r in run_search(args.engine, q, args.max_results):
            if not r["url"] or r["url"] in seen_urls:
                continue
            seen_urls.add(r["url"])
            host = hostname(r["url"])
            conf, pts = score(r, profile)
            domain = match_broker(host)
            if domain:
                name, optout, note = BROKERS[domain]
                bucket, key = found, domain
            elif looks_like_broker(host) and pts >= 2:
                name, optout, note = host, None, "Unrecognized site; looks like a people-search broker."
                bucket, key = possible, host
            else:
                continue
            entry = bucket.setdefault(key, {"name": name, "optout": optout, "note": note,
                                            "hits": [], "best": "low"})
            entry["hits"].append({"title": r["title"], "url": r["url"], "conf": conf})
            if CONF_ORDER[conf] < CONF_ORDER[entry["best"]]:
                entry["best"] = conf
        time.sleep(args.delay)

    # drop broker entries whose only hits are unrelated to you
    found = {d: e for d, e in found.items() if any(h["conf"] != "low" for h in e["hits"]) or args.deep}
    unchecked = {d: v for d, v in BROKERS.items() if d not in found}

    report = render_report(profile, found, possible, unchecked, len(queries))
    html_path, json_path = args.out + ".html", args.out + ".json"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(report)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"found": found, "possible": possible}, f, indent=2)

    print("\nDone. %d known brokers matched, %d possible unrecognized." % (len(found), len(possible)))
    print("Report: %s" % os.path.abspath(html_path))
    if args.open:
        import webbrowser
        webbrowser.open("file://" + os.path.abspath(html_path))


if __name__ == "__main__":
    main()
