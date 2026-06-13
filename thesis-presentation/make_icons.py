"""Generate a consistent custom icon set for the defense deck.

Every icon is drawn on the same 0..100 canvas, with the same stroke weight and
round caps/joins, so the set is visually uniform (unlike the previous emoji,
which rendered as mismatched colour clipart). Each line icon is exported in two
palettes — navy (for light cards) and light (for navy cards) — plus three status
markers (check / partial / cross) for the comparison matrices.

Run:  .venv/bin/python make_icons.py
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import patches

ICON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icons")
os.makedirs(ICON_DIR, exist_ok=True)

NAVY = "#0B1428"
LIGHT = "#FFFFFF"
ACCENT = "#FCA311"
GREEN = "#2E8B57"
AMBER = "#E9A100"
RED = "#C9184A"

LW = 7.0  # global stroke weight on the 0..100 canvas


# ---- primitives -------------------------------------------------------------
def _line(ax, x1, y1, x2, y2, c, lw=LW):
    ax.plot([x1, x2], [y1, y2], color=c, lw=lw,
            solid_capstyle="round", solid_joinstyle="round", zorder=3)


def _poly(ax, pts, c, lw=LW, closed=False):
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    if closed:
        xs.append(pts[0][0]); ys.append(pts[0][1])
    ax.plot(xs, ys, color=c, lw=lw, solid_capstyle="round",
            solid_joinstyle="round", zorder=3)


def _circle(ax, cx, cy, r, c, lw=LW, fill=False):
    ax.add_patch(patches.Circle((cx, cy), r, fill=fill, facecolor=(c if fill else "none"),
                 edgecolor=c, lw=(0 if fill else lw), zorder=3))


def _dot(ax, cx, cy, r, c):
    ax.add_patch(patches.Circle((cx, cy), r, color=c, zorder=4))


def _arc(ax, cx, cy, r, t1, t2, c, lw=LW):
    ax.add_patch(patches.Arc((cx, cy), 2 * r, 2 * r, theta1=t1, theta2=t2,
                 edgecolor=c, lw=lw, zorder=3, capstyle="round"))


def _rr(ax, x, y, w, h, c, lw=LW, pad=0.10, fill=False):
    ax.add_patch(patches.FancyBboxPatch((x, y), w, h,
                 boxstyle=f"round,pad=0,rounding_size={pad*min(w,h)}",
                 fill=fill, facecolor=(c if fill else "none"),
                 edgecolor=c, lw=(0 if fill else lw),
                 mutation_aspect=1, zorder=3))


# ---- line icons (each: fn(ax, color)) --------------------------------------
def i_lock(ax, c):
    _rr(ax, 26, 16, 48, 38, c, pad=0.14)
    _arc(ax, 50, 54, 16, 0, 180, c)
    _line(ax, 34, 54, 34, 47, c); _line(ax, 66, 54, 66, 47, c)
    _dot(ax, 50, 38, 5, c); _line(ax, 50, 38, 50, 28, c)


def i_book(ax, c):
    _rr(ax, 24, 18, 52, 64, c, pad=0.10)
    _line(ax, 38, 22, 38, 78, c)
    _line(ax, 48, 34, 66, 34, c); _line(ax, 48, 50, 66, 50, c); _line(ax, 48, 66, 66, 66, c)


def i_wrench(ax, c):
    _arc(ax, 34, 66, 14, 120, 360, c)
    _line(ax, 34, 66, 30, 70, c)
    _poly(ax, [(40, 60), (70, 30)], c)
    _line(ax, 64, 24, 76, 36, c)


def i_bolt(ax, c):
    _poly(ax, [(56, 86), (32, 50), (50, 50), (44, 14), (70, 52), (52, 52)], c, closed=True)


def i_folder(ax, c):
    _rr(ax, 20, 22, 60, 40, c, pad=0.10)                       # body
    _poly(ax, [(30, 62), (36, 71), (52, 71), (58, 62)], c)     # tab on top-left


def i_chat(ax, c):
    _rr(ax, 18, 30, 64, 46, c, pad=0.18)
    _poly(ax, [(34, 30), (30, 16), (46, 30)], c)
    _dot(ax, 38, 53, 4, c); _dot(ax, 50, 53, 4, c); _dot(ax, 62, 53, 4, c)


def i_layers(ax, c):
    _poly(ax, [(50, 78), (20, 60), (50, 42), (80, 60)], c, closed=True)
    _poly(ax, [(24, 50), (50, 34), (76, 50)], c)
    _poly(ax, [(24, 40), (50, 24), (76, 40)], c)


def i_search(ax, c):
    _circle(ax, 44, 56, 22, c)
    _line(ax, 60, 40, 80, 20, c)


def i_shield(ax, c):
    _poly(ax, [(50, 14), (22, 28), (22, 54), (50, 86), (78, 54), (78, 28)], c, closed=True)
    _poly(ax, [(37, 50), (46, 40), (64, 62)], c)


def i_cube(ax, c):
    _poly(ax, [(50, 14), (80, 30), (80, 66), (50, 84), (20, 66), (20, 30)], c, closed=True)
    _poly(ax, [(20, 30), (50, 48), (80, 30)], c)
    _line(ax, 50, 48, 50, 84, c)


def i_seal(ax, c):
    # award medallion + two ribbon tails = "signed / certified"
    _circle(ax, 50, 58, 20, c)
    _poly(ax, [(40, 57), (47, 48), (62, 66)], c)
    _line(ax, 43, 42, 40, 20, c); _line(ax, 40, 20, 47, 26, c)
    _line(ax, 57, 42, 60, 20, c); _line(ax, 60, 20, 53, 26, c)


def i_flask(ax, c):
    _poly(ax, [(42, 82), (42, 52), (24, 22), (76, 22), (58, 52), (58, 82)], c, closed=True)
    _line(ax, 38, 16, 62, 16, c)
    _line(ax, 33, 36, 67, 36, c)


def i_ruler(ax, c):
    _rr(ax, 22, 34, 56, 28, c, pad=0.10)
    # rotate-look ticks
    for tx in (34, 46, 58, 70):
        _line(ax, tx, 62, tx, 52, c)


def i_globe(ax, c):
    _circle(ax, 50, 50, 30, c)
    _line(ax, 20, 50, 80, 50, c)
    ax.add_patch(patches.Arc((50, 50), 32, 60, theta1=0, theta2=360,
                 edgecolor=c, lw=LW, zorder=3))


def i_gear(ax, c):
    _circle(ax, 50, 50, 16, c)
    import math
    for k in range(8):
        a = math.radians(k * 45)
        x1 = 50 + 22 * math.cos(a); y1 = 50 + 22 * math.sin(a)
        x2 = 50 + 30 * math.cos(a); y2 = 50 + 30 * math.sin(a)
        _line(ax, x1, y1, x2, y2, c, lw=LW + 1)


def i_user(ax, c):
    _circle(ax, 50, 66, 13, c)
    _arc(ax, 50, 28, 24, 20, 160, c)


def i_users(ax, c):
    _circle(ax, 40, 64, 11, c)
    _arc(ax, 40, 30, 20, 25, 155, c)
    _circle(ax, 66, 66, 9, c)
    _arc(ax, 68, 36, 16, 30, 150, c)


def i_chip(ax, c):
    _rr(ax, 30, 30, 40, 40, c, pad=0.12)
    _rr(ax, 42, 42, 16, 16, c, pad=0.16)
    for t in (40, 50, 60):
        _line(ax, t, 30, t, 22, c); _line(ax, t, 70, t, 78, c)
        _line(ax, 30, t, 22, t, c); _line(ax, 70, t, 78, t, c)


def i_refresh(ax, c):
    _arc(ax, 50, 50, 26, 60, 330, c)
    _poly(ax, [(64, 78), (74, 72), (70, 84)], c, closed=True)


def i_cloud(ax, c):
    _arc(ax, 40, 50, 16, 60, 300, c)
    _arc(ax, 60, 52, 14, 300, 200, c)
    _line(ax, 30, 38, 66, 38, c)
    _arc(ax, 40, 54, 16, 180, 270, c)


def i_target(ax, c):
    _circle(ax, 50, 50, 28, c)
    _circle(ax, 50, 50, 15, c)
    _dot(ax, 50, 50, 5, c)


def i_dice(ax, c):
    _rr(ax, 24, 24, 52, 52, c, pad=0.14)
    _dot(ax, 38, 62, 4.5, c); _dot(ax, 50, 50, 4.5, c); _dot(ax, 62, 38, 4.5, c)


def i_building(ax, c):
    # two buildings = multi-project / scale-out
    _rr(ax, 26, 18, 20, 64, c, pad=0.06)
    _rr(ax, 52, 34, 22, 48, c, pad=0.06)
    for yy in (66, 52, 38):
        _dot(ax, 33, yy, 2.6, c); _dot(ax, 40, yy, 2.6, c)
    for yy in (66, 52):
        _dot(ax, 60, yy, 2.6, c); _dot(ax, 67, yy, 2.6, c)


def i_compass(ax, c):
    _circle(ax, 50, 50, 30, c)
    _poly(ax, [(50, 50), (62, 38), (50, 50), (38, 62)], c)
    _poly(ax, [(62, 38), (44, 44), (56, 56)], c, closed=True)


def i_link(ax, c):
    # two connected nodes = structured contract between stages
    _circle(ax, 32, 50, 13, c)
    _circle(ax, 68, 50, 13, c)
    _line(ax, 45, 50, 55, 50, c)


def i_barchart(ax, c):
    _line(ax, 24, 22, 24, 78, c); _line(ax, 24, 78, 80, 78, c)
    _rr(ax, 34, 56, 10, 22, c, pad=0.0, lw=LW - 1)
    _rr(ax, 50, 44, 10, 34, c, pad=0.0, lw=LW - 1)
    _rr(ax, 66, 32, 10, 46, c, pad=0.0, lw=LW - 1)


def i_trophy(ax, c):
    _poly(ax, [(34, 78), (34, 52), (66, 52), (66, 78)], c)
    _arc(ax, 50, 60, 16, 200, 340, c)
    _line(ax, 34, 70, 22, 60, c); _arc(ax, 26, 62, 8, 90, 270, c)
    _line(ax, 66, 70, 78, 60, c); _arc(ax, 74, 62, 8, 270, 90, c)
    _line(ax, 40, 84, 60, 84, c); _line(ax, 50, 78, 50, 84, c)


def i_x(ax, c):
    _line(ax, 30, 30, 70, 70, c, lw=LW + 2)
    _line(ax, 70, 30, 30, 70, c, lw=LW + 2)


def i_mouse(ax, c):
    _rr(ax, 34, 18, 32, 64, c, pad=0.45)
    _line(ax, 50, 24, 50, 40, c)


def i_doc(ax, c):
    _poly(ax, [(30, 16), (30, 84), (70, 84), (70, 32), (54, 16), (30, 16)], c, closed=True)
    _poly(ax, [(54, 16), (54, 32), (70, 32)], c)
    _line(ax, 38, 50, 62, 50, c); _line(ax, 38, 62, 62, 62, c); _line(ax, 38, 74, 56, 74, c)


LINE_ICONS = {
    "lock": i_lock, "book": i_book, "wrench": i_wrench, "bolt": i_bolt,
    "folder": i_folder, "chat": i_chat, "layers": i_layers, "search": i_search,
    "shield": i_shield, "cube": i_cube, "seal": i_seal, "flask": i_flask,
    "ruler": i_ruler, "globe": i_globe, "gear": i_gear, "user": i_user,
    "users": i_users, "chip": i_chip, "refresh": i_refresh, "cloud": i_cloud,
    "target": i_target, "dice": i_dice, "building": i_building,
    "compass": i_compass, "link": i_link, "barchart": i_barchart,
    "trophy": i_trophy, "x": i_x, "mouse": i_mouse, "doc": i_doc,
}


def _new_ax():
    fig = plt.figure(figsize=(2.56, 2.56), dpi=200)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100); ax.set_ylim(0, 100)
    ax.set_aspect("equal"); ax.axis("off")
    return fig, ax


def _center(path, margin=0.14):
    """Crop transparent margins and re-centre the glyph in a square canvas, so
    every icon's visible content shares the same centre and padding."""
    from PIL import Image
    im = Image.open(path).convert("RGBA")
    bbox = im.getbbox()
    if not bbox:
        return
    crop = im.crop(bbox)
    w, h = crop.size
    side = int(round(max(w, h) * (1 + 2 * margin)))
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.paste(crop, ((side - w) // 2, (side - h) // 2), crop)
    canvas.save(path)


def _save(fig, name):
    path = os.path.join(ICON_DIR, name)
    fig.savefig(path, transparent=True)
    plt.close(fig)
    _center(path)


def status_marker(name, color, glyph):
    fig, ax = _new_ax()
    _circle(ax, 50, 50, 38, color, fill=True)
    if glyph == "check":
        _poly(ax, [(33, 51), (45, 39), (68, 64)], LIGHT, lw=10)
    elif glyph == "cross":
        _line(ax, 36, 36, 64, 64, LIGHT, lw=10)
        _line(ax, 64, 36, 36, 64, LIGHT, lw=10)
    elif glyph == "partial":
        _line(ax, 36, 50, 64, 50, LIGHT, lw=10)
    _save(fig, name)


def build():
    for name, fn in LINE_ICONS.items():
        for key, col in (("navy", NAVY), ("light", LIGHT), ("accent", ACCENT),
                         ("red", RED)):
            fig, ax = _new_ax()
            fn(ax, col)
            _save(fig, f"{name}-{key}.png")
    status_marker("st-check.png", GREEN, "check")
    status_marker("st-partial.png", AMBER, "partial")
    status_marker("st-cross.png", RED, "cross")
    print(f"wrote {len(LINE_ICONS)*3 + 3} icons to {ICON_DIR}")


def contact_sheet():
    names = list(LINE_ICONS.keys())
    cols = 8
    rows = (len(names) + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(cols * 1.4, rows * 1.5), dpi=110)
    axes = axes.flatten()
    for ax in axes:
        ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.set_aspect("equal"); ax.axis("off")
    for i, name in enumerate(names):
        ax = axes[i]
        ax.add_patch(patches.Rectangle((0, 0), 100, 100, color="#F6F7FB"))
        LINE_ICONS[name](ax, NAVY)
        ax.set_title(name, fontsize=9)
    for j in range(len(names), len(axes)):
        axes[j].axis("off")
    fig.tight_layout()
    fig.savefig("/tmp/icon_contact_sheet.png", dpi=110)
    plt.close(fig)
    print("contact sheet -> /tmp/icon_contact_sheet.png")


if __name__ == "__main__":
    build()
    contact_sheet()
