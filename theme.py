"""
theme.py
--------
Central color palette, fonts, and small drawing helpers shared across
the whole UI, so every screen looks like one consistent app instead of
default-Tkinter gray boxes.
"""

import os
import hashlib

# ---- Palette: warm cream base with a clay/orange accent (Claude-like) ----
BG = "#f7f4ef"           # app background - warm paper
SIDEBAR = "#f0ebe0"       # slightly deeper than BG, like macOS sidebar chrome
SURFACE = "#ffffff"       # cards / panels
SURFACE_HOVER = "#f0ebe1"
SIDEBAR_HOVER = "#e7e0d2"
SIDEBAR_SELECTED = "#ddd3c0"
BORDER = "#e6e0d4"
BORDER_STRONG = "#d9d1c0"
TEXT = "#30291f"
TEXT_MUTED = "#8a8171"
ACCENT = "#c15f3c"        # clay / terracotta
ACCENT_HOVER = "#a94f30"
ACCENT_SOFT = "#f3e3da"   # pale accent wash for selected/subtle highlights
ACCENT_TEXT = "#ffffff"
DANGER = "#b3493a"
DANGER_HOVER = "#963c30"
SUCCESS = "#5c7a52"
WARNING = "#b08a2e"
STAR_GOLD = "#c9962f"

FONT_FAMILY = "Segoe UI"
FONT_NORMAL = (FONT_FAMILY, 11)
FONT_SMALL = (FONT_FAMILY, 9)
FONT_MEDIUM = (FONT_FAMILY, 12)
FONT_BOLD = (FONT_FAMILY, 12, "bold")
FONT_HEADING = (FONT_FAMILY, 18, "bold")
FONT_TITLE = (FONT_FAMILY, 15, "bold")
FONT_MONO = ("Consolas", 12)

def initials(title: str) -> str:
    title = title.strip()
    if not title:
        return "?"
    parts = title.split()
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[1][0]).upper()


LOCK_GLYPH = "\U0001F512"    # 🔒
STAR_FILLED = "★"        # ★
STAR_OUTLINE = "☆"       # ☆
SHIELD_GLYPH = "\U0001F6E1"   # 🛡
ALL_ITEMS_GLYPH = "\U0001F511"  # 🔑


def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _rgb_to_hex(rgb: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*(max(0, min(255, c)) for c in rgb))


def animate_bg(widget, from_color: str, to_color: str, steps: int = 6, duration_ms: int = 110):
    """Smoothly interpolates a widget's background color over a short
    duration instead of swapping it instantly - the kind of subtle
    micro-interaction Apple's Passwords app uses on row hover. Tkinter
    has no real animation API, so this steps the color manually via
    repeated `after()` calls. Cheap and safe to call every hover event:
    if the widget is destroyed mid-animation (e.g. list refreshed while
    hovering), the scheduled step just fails silently via TclError.
    """
    try:
        from_rgb = _hex_to_rgb(from_color)
        to_rgb = _hex_to_rgb(to_color)
    except Exception:
        try:
            widget.configure(bg=to_color)
        except Exception:
            pass
        return

    def step(i):
        try:
            t = i / steps
            rgb = tuple(from_rgb[c] + (to_rgb[c] - from_rgb[c]) * t for c in range(3))
            widget.configure(bg=_rgb_to_hex(tuple(round(v) for v in rgb)))
        except Exception:
            return  # widget likely destroyed - stop the animation quietly
        if i < steps:
            widget.after(max(1, duration_ms // steps), lambda: step(i + 1))

    step(0)


def generate_icon_file(path: str) -> bool:
    """Render a clean padlock .ico for the taskbar/title bar using PIL
    (no Ghostscript/postscript dependency, unlike tkinter canvas export).
    Returns True on success, False if Pillow isn't installed - caller
    should treat that as a cosmetic no-op, never a hard failure."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return False

    accent = (193, 95, 60, 255)   # ACCENT
    sizes = [16, 24, 32, 48, 64, 128]
    images = []
    for s in sizes:
        img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        cx, cy = s / 2, s / 2
        shackle_w = s * 0.5
        width = max(2, round(s * 0.11))

        x0, x1 = cx - shackle_w / 2, cx + shackle_w / 2
        y0, y1 = cy - s * 0.38, cy + s * 0.08
        d.arc([x0, y0, x1, y1], start=180, end=360, fill=accent, width=width)

        body_w, body_h = s * 0.72, s * 0.46
        bx0, by0 = cx - body_w / 2, cy - s * 0.03
        bx1, by1 = cx + body_w / 2, by0 + body_h
        radius = max(1, s * 0.09)
        d.rounded_rectangle([bx0, by0, bx1, by1], radius=radius, fill=accent)
        images.append(img)

    try:
        images[-1].save(path, format="ICO", sizes=[(s, s) for s in sizes])
        return True
    except Exception:
        return False


def apply_ttk_theme(style):
    """Configure the ttk.Style object to match the dark palette."""
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(".", background=BG, foreground=TEXT, fieldbackground=SURFACE,
                     font=FONT_NORMAL, borderwidth=0)

    style.configure("TFrame", background=BG)
    style.configure("Surface.TFrame", background=SURFACE)

    style.configure("TLabel", background=BG, foreground=TEXT, font=FONT_NORMAL)
    style.configure("Muted.TLabel", background=BG, foreground=TEXT_MUTED, font=FONT_SMALL)
    style.configure("Heading.TLabel", background=BG, foreground=TEXT, font=FONT_HEADING)
    style.configure("Title.TLabel", background=BG, foreground=TEXT, font=FONT_TITLE)
    style.configure("Surface.TLabel", background=SURFACE, foreground=TEXT, font=FONT_NORMAL)
    style.configure("SurfaceMuted.TLabel", background=SURFACE, foreground=TEXT_MUTED, font=FONT_SMALL)

    style.configure("TEntry", fieldbackground=SURFACE, foreground=TEXT,
                     insertcolor=TEXT, bordercolor=BORDER, lightcolor=BORDER,
                     darkcolor=BORDER, padding=8)
    style.map("TEntry", bordercolor=[("focus", ACCENT)])

    # Primary accent button
    style.configure("Accent.TButton", background=ACCENT, foreground=ACCENT_TEXT,
                     font=FONT_BOLD, padding=(14, 9), borderwidth=0)
    style.map("Accent.TButton",
              background=[("active", ACCENT_HOVER), ("pressed", ACCENT_HOVER)])

    # Secondary / ghost button
    style.configure("Ghost.TButton", background=SURFACE, foreground=TEXT,
                     font=FONT_NORMAL, padding=(12, 8), borderwidth=1,
                     bordercolor=BORDER)
    style.map("Ghost.TButton",
              background=[("active", SURFACE_HOVER), ("pressed", SURFACE_HOVER)])

    # Danger button
    style.configure("Danger.TButton", background=DANGER, foreground="#ffffff",
                     font=FONT_NORMAL, padding=(12, 8), borderwidth=0)
    style.map("Danger.TButton",
              background=[("active", DANGER_HOVER), ("pressed", DANGER_HOVER)])

    style.configure("TCheckbutton", background=BG, foreground=TEXT, font=FONT_SMALL)
    style.map("TCheckbutton", background=[("active", BG)])

    style.configure("TSpinbox", fieldbackground=SURFACE, foreground=TEXT,
                     arrowcolor=TEXT, bordercolor=BORDER, padding=6)

    style.configure("Vertical.TScrollbar", background=SURFACE, troughcolor=BG,
                     bordercolor=BG, arrowcolor=TEXT_MUTED, width=12)
    style.map("Vertical.TScrollbar", background=[("active", SURFACE_HOVER)])
