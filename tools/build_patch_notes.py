"""Build PATCH_NOTES.pdf from the public bug registry (records with status "patched" and a "release_notes" field).

python tools/build_patch_notes.py [out.pdf]     (default: dist/PATCH_NOTES.pdf)
Only public records are read (never _su_extract/patch_internal).
"""
import collections, datetime, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registry as R
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from xml.sax.saxutils import escape

SECTIONS = ["Relics", "Traits", "Perks", "Spells", "Spell gems & items", "Cards", "Conditions & minions",
            "Combat rules", "Bosses & Nether bosses", "Realm", "Interface text"]
FLAG_TEXT = {"heavy": "heavy", "partial": "partial", "boss": "boss", "text": "text fix"}


def clean(s):
    """Plain text safe for the built-in PDF fonts (WinAnsi)."""
    rep = {"−": "-", "→": "->", "←": "<-", "≤": "<=", "≥": ">=", "≈": "~", "…": "...",
           "‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": " - ", " ": " "}
    for a, b in rep.items():
        s = s.replace(a, b)
    return escape(s.encode("cp1252", "replace").decode("cp1252"))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(R.ROOT, "dist", "PATCH_NOTES.pdf")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    version = open(os.path.join(R.ROOT, "loader", "VERSION")).read().strip()
    build = json.load(open(R.PATCHES, encoding="utf-8"))["build"]["name"]
    recs = [r for r in R.load().values() if r["status"] == "patched" and r.get("release_notes")]
    missing = [r["id"] for r in R.load().values() if r["status"] == "patched" and not r.get("release_notes")]
    if missing:
        raise SystemExit("records without release_notes: %s" % ", ".join(missing))

    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontName="Helvetica", fontSize=7.6, leading=9.4, alignment=TA_LEFT)
    bold = ParagraphStyle("bb", parent=body, fontName="Helvetica-Bold")
    head = ParagraphStyle("h", parent=body, fontName="Helvetica-Bold", textColor=colors.white)
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=22, leading=26)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=13, spaceBefore=4, spaceAfter=6)
    txt = ParagraphStyle("t", parent=ss["BodyText"], fontName="Helvetica", fontSize=10, leading=13.5)

    by = collections.defaultdict(list)
    for r in recs:
        by[r["release_notes"]["section"]].append(r)
    impact = collections.Counter(r["release_notes"].get("impact", "neutral") for r in recs)

    story = [Paragraph("Siralim Ultimate - Unofficial Community Patch", h1),
             Paragraph("Patch notes - version %s" % clean(version), h2),
             Paragraph("For %s. Generated %s." % (clean(build), datetime.date.today().isoformat()), txt), Spacer(1, 10),
             Paragraph("Every fix below makes an effect work the way its in-game description says. Some make an effect "
                       "stronger than it was while bugged, some weaker. Each fix has an id (SU-xxxx); every fix can be "
                       "switched on or off by that id in <b>suucp.ini</b>.", txt), Spacer(1, 10)]
    summary = [[Paragraph("<b>Section</b>", txt), Paragraph("<b>Fixes</b>", txt)]]
    for s in SECTIONS:
        if by.get(s):
            summary.append([Paragraph(clean(s), txt), Paragraph(str(len(by[s])), txt)])
    summary.append([Paragraph("<b>Total</b>", txt), Paragraph("<b>%d</b>" % len(recs), txt)])
    t = Table(summary, colWidths=[2.6 * inch, 0.8 * inch])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
    story += [t, Spacer(1, 12),
              Paragraph("<b>Compared with the bugged version:</b> %d stronger, %d weaker, %d neutral." % (
                  impact.get("stronger", 0), impact.get("weaker", 0), impact.get("neutral", 0)), txt), Spacer(1, 8),
              Paragraph("<b>Flags:</b> <i>heavy</i> = a larger rebuild of core battle code, in the <b>heavy</b> group "
                        "(<b>[groups] heavy=0</b> turns these off together); <i>partial</i> = a known part is not covered "
                        "yet (described in the row); <i>boss</i> = affects enemies or bosses; <i>text fix</i> = only "
                        "the in-game text changes.", txt), PageBreak()]

    widths = [0.62 * inch, 1.45 * inch, 2.2 * inch, 2.2 * inch, 3.4 * inch]
    for s in SECTIONS:
        rows = by.get(s)
        if not rows:
            continue
        story.append(Paragraph(clean(s), h2))
        data = [[Paragraph(x, head) for x in ("ID", "Effect", "What it's supposed to do",
                                              "What it was actually doing", "What the fix corrects and how")]]
        for r in sorted(rows, key=lambda r: r["release_notes"]["effect"].lower()):
            n = r["release_notes"]
            tags = [FLAG_TEXT[f] for f in n.get("flags", []) if f in FLAG_TEXT]
            imp = n.get("impact", "neutral")
            eff = "<b>%s</b><br/><font size=6.5 color='#555555'>%s%s</font>" % (
                clean(n["effect"]), clean(imp), (" - " + clean(", ".join(tags))) if tags else "")
            data.append([Paragraph(clean(r["id"]), bold), Paragraph(eff, body), Paragraph(clean(n["intended"]), body),
                         Paragraph(clean(n["actual"]), body), Paragraph(clean(n["fix"]), body)])
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3b4a6b")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#b8bfcc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f4f8")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        story += [t, Spacer(1, 10)]

    def footer(c, d):
        c.saveState(); c.setFont("Helvetica", 7); c.setFillColor(colors.grey)
        c.drawString(0.5 * inch, 0.35 * inch, "Siralim Ultimate Unofficial Community Patch %s - unofficial, not affiliated "
                     "with Thylacine Studios" % version)
        c.drawRightString(10.5 * inch, 0.35 * inch, "page %d" % d.page); c.restoreState()

    doc = SimpleDocTemplate(out, pagesize=landscape(letter), leftMargin=0.5 * inch, rightMargin=0.5 * inch,
                            topMargin=0.5 * inch, bottomMargin=0.55 * inch, title="SUUCP patch notes %s" % version,
                            author="Siralim Ultimate Unofficial Community Patch")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print("wrote %s (%d fixes)" % (out, len(recs)))


if __name__ == "__main__":
    main()
