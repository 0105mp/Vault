"""
app.py
------
Tkinter desktop UI for the password manager — dark themed, card-style
entry list, drawn lock icon, consistent styling across every screen.

Run with:  python3 app.py
Vault file defaults to ~/.local/share/password_manager/vault.json
(override with --vault /path/to/file.json)
"""

import os
import sys
import threading
import argparse
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from vault import Vault
import vault_crypto
import theme
import favicon
import security_scan
import self_destruct
import local_server
from password_generator import generate_password, generate_passphrase
from strength import estimate_strength
from breach_check import check_password_breach, BreachCheckError


def _enable_windows_dpi_awareness():
    """Without this, Windows treats a Tkinter window as a legacy app and
    upscales it as a bitmap on any scaled display (125%/150%/etc.) -
    everything looks soft/blurry even though nothing is actually drawn
    wrong. Declaring per-monitor DPI awareness tells Windows to hand the
    real pixel dimensions to Tk instead, so it renders at native sharpness."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PER_MONITOR_AWARE
    except Exception:
        try:
            import ctypes
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


_enable_windows_dpi_awareness()

DEFAULT_VAULT_DIR = os.path.expanduser("~/.local/share/password_manager")
DEFAULT_VAULT_PATH = os.path.join(DEFAULT_VAULT_DIR, "vault.json")

IDLE_LOCK_MS = 3 * 60 * 1000       # auto-lock after 3 minutes idle
CLIPBOARD_CLEAR_MS = 20 * 1000      # clear clipboard 20s after a copy


class PasswordManagerApp(tk.Tk):
    def __init__(self, vault_path: str):
        super().__init__()
        self._match_tk_scaling_to_system_dpi()
        self.title("Vault")
        self.geometry("780x560")
        self.minsize(620, 420)
        self.configure(bg=theme.BG)

        os.makedirs(os.path.dirname(vault_path), exist_ok=True)
        self.vault = Vault(vault_path)
        self._server = local_server.VaultServer(self.vault)

        self._idle_job = None
        self._clipboard_job = None

        self.style = ttk.Style(self)
        theme.apply_ttk_theme(self.style)
        self._set_window_icon()

        self._show_unlock_screen()

        for seq in ("<Key>", "<Button>", "<Motion>"):
            self.bind_all(seq, self._reset_idle_timer, add="+")
        self._reset_idle_timer()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- window chrome ----------------

    def _match_tk_scaling_to_system_dpi(self):
        """Tk's internal scaling (points -> pixels) defaults to 96 DPI.
        If Windows is actually running at 125%/150%/etc. and we've
        declared DPI awareness, Tk's own guess can undershoot, making
        every font and control render too small. Query the real system
        DPI and set Tk's scaling to match it exactly."""
        if sys.platform != "win32":
            return
        try:
            import ctypes
            dpi = ctypes.windll.user32.GetDpiForSystem()
            self.tk.call("tk", "scaling", dpi / 72)
        except Exception:
            pass  # Fall back to Tk's own default guess.

    def _set_window_icon(self):
        try:
            ico_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault_icon.ico")
            if theme.generate_icon_file(ico_path):
                self.iconbitmap(ico_path)
        except Exception:
            pass  # No icon is a cosmetic-only miss; never block app launch over it.

    # ---------------- idle / lock handling ----------------

    def _reset_idle_timer(self, event=None):
        if self._idle_job is not None:
            self.after_cancel(self._idle_job)
        self._idle_job = self.after(IDLE_LOCK_MS, self._auto_lock)

    def _auto_lock(self):
        if self.vault.unlocked:
            self._server.stop()
            self.vault.lock()
            messagebox.showinfo("Locked", "Vault auto-locked after inactivity.")
            self._show_unlock_screen()

    def _on_close(self):
        self._server.stop()
        self.vault.lock()
        self.destroy()

    # ---------------- screens ----------------

    def _clear_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

    def _show_unlock_screen(self):
        self._clear_screen()
        self.configure(bg=theme.BG)

        outer = tk.Frame(self, bg=theme.BG)
        outer.pack(expand=True)

        card = tk.Frame(outer, bg=theme.SURFACE, padx=56, pady=48,
                         highlightbackground=theme.BORDER, highlightthickness=1)
        card.pack(padx=20, pady=20)

        icon_wrap = tk.Frame(card, bg=theme.ACCENT_SOFT, width=64, height=64)
        icon_wrap.pack(pady=(0, 20))
        icon_wrap.pack_propagate(False)
        tk.Label(icon_wrap, text=theme.LOCK_GLYPH, bg=theme.ACCENT_SOFT,
                 font=(theme.FONT_FAMILY, 22)).place(relx=0.5, rely=0.5, anchor="center")

        is_new = not self.vault.exists()
        heading = "Create your vault" if is_new else "Welcome back"
        tk.Label(card, text=heading, bg=theme.SURFACE, fg=theme.TEXT,
                 font=theme.FONT_HEADING).pack(pady=(0, 6))

        if is_new:
            tk.Label(
                card,
                text="Choose a strong master password.\nThere is no recovery if you forget it —\nit's never stored anywhere.",
                justify="center", bg=theme.SURFACE, fg=theme.TEXT_MUTED, font=theme.FONT_SMALL,
            ).pack(pady=(0, 20))
        else:
            tk.Label(card, text="Enter your master password to unlock",
                     bg=theme.SURFACE, fg=theme.TEXT_MUTED, font=theme.FONT_SMALL).pack(pady=(0, 20))

        pw_var = tk.StringVar()
        entry = self._styled_entry(card, pw_var, show="•", width=30)
        entry.pack(pady=4, ipady=6)
        entry.focus_set()

        confirm_var = tk.StringVar()
        confirm_entry = None
        if is_new:
            tk.Label(card, text="Confirm master password", bg=theme.SURFACE, fg=theme.TEXT_MUTED,
                     font=theme.FONT_SMALL).pack(pady=(14, 4), anchor="w")
            confirm_entry = self._styled_entry(card, confirm_var, show="•", width=30)
            confirm_entry.pack(pady=4, ipady=6)

        error_var = tk.StringVar(value="")
        tk.Label(card, textvariable=error_var, bg=theme.SURFACE, fg=theme.DANGER,
                 font=theme.FONT_SMALL).pack(pady=(10, 0))

        def submit(event=None):
            pw = pw_var.get()
            if not pw:
                error_var.set("Enter a master password.")
                return
            if is_new:
                if len(pw) < 8:
                    error_var.set("Use at least 8 characters (longer is better).")
                    return
                if pw != confirm_var.get():
                    error_var.set("Passwords don't match.")
                    return
                self.vault.create_new(pw)
                self_destruct.reset_failed_attempts(self.vault.path)
                self._server.start()
                self._show_main_screen()
            else:
                try:
                    self.vault.unlock(pw)
                    self_destruct.reset_failed_attempts(self.vault.path)
                    self._server.start()
                    self._show_main_screen()
                except vault_crypto.VaultError:
                    remaining = self_destruct.record_failed_attempt(self.vault.path)
                    if remaining is None:
                        messagebox.showwarning(
                            "Vault wiped",
                            "Too many incorrect attempts. The vault has been permanently deleted.",
                        )
                        pw_var.set("")
                        self._show_unlock_screen()
                        return
                    left = self_destruct.MAX_FAILED_ATTEMPTS - remaining
                    error_var.set(f"Incorrect master password. {left} attempt(s) left before the vault self-destructs.")
                    pw_var.set("")

        entry.bind("<Return>", submit)
        if confirm_entry is not None:
            confirm_entry.bind("<Return>", submit)

        btn = tk.Button(card, text="Create Vault" if is_new else "Unlock", command=submit,
                         bg=theme.ACCENT, fg=theme.ACCENT_TEXT, activebackground=theme.ACCENT_HOVER,
                         activeforeground=theme.ACCENT_TEXT, font=theme.FONT_BOLD, bd=0,
                         relief="flat", padx=18, pady=10, cursor="hand2")
        btn.pack(pady=(20, 0), fill="x")

        if not is_new:
            wipe_link = tk.Label(card, text="Emergency wipe vault…", bg=theme.SURFACE, fg=theme.TEXT_MUTED,
                                  font=theme.FONT_SMALL, cursor="hand2")
            wipe_link.pack(pady=(14, 0))
            wipe_link.bind("<Button-1>", lambda _: self._open_panic_wipe_dialog())

    def _styled_entry(self, parent, textvar, show=None, width=30):
        kwargs = dict(textvariable=textvar, bg=theme.BG, fg=theme.TEXT,
                      insertbackground=theme.TEXT, relief="flat", font=theme.FONT_MEDIUM,
                      highlightthickness=1, highlightbackground=theme.BORDER,
                      highlightcolor=theme.ACCENT, width=width)
        if show:
            kwargs["show"] = show
        return tk.Entry(parent, **kwargs)

    def _show_main_screen(self):
        self._clear_screen()
        self.configure(bg=theme.BG)

        self._section = "all"          # "all" | "favorites" | "wifi" | "security"
        self._active_tag = None
        self._selected_id = None
        self._breach_cache = {}        # password -> breach count|None, reused across scans
        self._breach_results = {}      # entry_id -> breach count, filled in by background scan
        self._scanning_breaches = False

        # ---- top bar ----
        top = tk.Frame(self, bg=theme.BG, padx=20, pady=14)
        top.pack(fill="x")

        brand = tk.Frame(top, bg=theme.BG)
        brand.pack(side="left")
        tk.Label(brand, text=theme.LOCK_GLYPH, bg=theme.BG, font=(theme.FONT_FAMILY, 15)).pack(side="left", padx=(0, 8))
        tk.Label(brand, text="Vault", bg=theme.BG, fg=theme.TEXT, font=theme.FONT_TITLE).pack(side="left")

        right_btns = tk.Frame(top, bg=theme.BG)
        right_btns.pack(side="right")
        self._accent_button(right_btns, "+ Add entry", self._open_add_dialog).pack(side="right")
        self._ghost_button(right_btns, "Generate…", self._open_generator_dialog).pack(side="right", padx=(0, 10))
        self._ghost_button(right_btns, "Browser extension…", self._open_extension_dialog).pack(side="right", padx=(0, 10))
        self._ghost_button(right_btns, "Master password…", self._open_change_master_dialog).pack(side="right", padx=(0, 10))
        self._ghost_button(right_btns, "Lock", self._lock_now).pack(side="right", padx=(0, 10))

        wipe_link = tk.Label(top, text="Emergency wipe", bg=theme.BG, fg=theme.TEXT_MUTED,
                              font=theme.FONT_SMALL, cursor="hand2")
        wipe_link.pack(side="right", padx=(0, 16))
        wipe_link.bind("<Button-1>", lambda _: self._open_panic_wipe_dialog())

        tk.Frame(self, bg=theme.BORDER, height=1).pack(fill="x")

        # ---- three-pane body ----
        body = tk.Frame(self, bg=theme.BG)
        body.pack(fill="both", expand=True)

        self._build_sidebar(body)      # packs itself + divider on the left
        self._build_detail_pane(body)  # packs itself + divider on the right (reserves space first)
        self._build_list_pane(body)    # fills whatever remains in the middle

        self._status_var = tk.StringVar()
        tk.Label(self, textvariable=self._status_var, bg=theme.BG, fg=theme.TEXT_MUTED,
                 font=theme.FONT_SMALL, padx=20, pady=6).pack(anchor="w", fill="x")

        self._refresh_sidebar()
        self._refresh_list()
        self._render_detail(None)

    # ---------------- sidebar ----------------

    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=theme.SIDEBAR, width=210)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Frame(parent, bg=theme.BORDER, width=1).pack(side="left", fill="y")
        self._sidebar = sidebar

        search_wrap = tk.Frame(sidebar, bg=theme.SURFACE, highlightbackground=theme.BORDER,
                                highlightthickness=1)
        search_wrap.pack(fill="x", padx=14, pady=(16, 14))
        tk.Label(search_wrap, text="\U0001F50D", bg=theme.SURFACE, fg=theme.TEXT_MUTED,
                 font=theme.FONT_SMALL).pack(side="left", padx=(8, 4))
        self._search_var = tk.StringVar()
        search_entry = tk.Entry(search_wrap, textvariable=self._search_var, bg=theme.SURFACE, fg=theme.TEXT,
                                 insertbackground=theme.TEXT, relief="flat", font=theme.FONT_SMALL, bd=0)
        search_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self._search_var.trace_add("write", lambda *_: self._refresh_list())

        self._nav_items_frame = tk.Frame(sidebar, bg=theme.SIDEBAR)
        self._nav_items_frame.pack(fill="x")

        self._tags_frame = tk.Frame(sidebar, bg=theme.SIDEBAR)
        self._tags_frame.pack(fill="x", pady=(12, 0))

    def _refresh_sidebar(self):
        for w in self._nav_items_frame.winfo_children():
            w.destroy()
        for w in self._tags_frame.winfo_children():
            w.destroy()

        total = len(self.vault.entries)
        fav_count = len(self.vault.search("", favorites_only=True))
        wifi_count = len(self.vault.wifi_entries())

        weak_ids = {e["id"] for e in security_scan.weak_entries(self.vault)}
        reused_ids = {e["id"] for e in security_scan.reused_entries(self.vault)}
        breach_ids = set(self._breach_results.keys())
        issue_count = len(weak_ids | reused_ids | breach_ids)

        self._make_nav_item(self._nav_items_frame, theme.ALL_ITEMS_GLYPH, "All Items", total,
                             self._section == "all" and not self._active_tag,
                             lambda: self._select_section("all"))
        self._make_nav_item(self._nav_items_frame, theme.STAR_FILLED, "Favorites", fav_count,
                             self._section == "favorites",
                             lambda: self._select_section("favorites"))
        self._make_nav_item(self._nav_items_frame, "\U0001F4F6", "Wi-Fi", wifi_count,
                             self._section == "wifi",
                             lambda: self._select_section("wifi"))
        self._make_nav_item(self._nav_items_frame, theme.SHIELD_GLYPH, "Security",
                             issue_count, self._section == "security",
                             lambda: self._select_section("security"),
                             badge_color=theme.DANGER if issue_count else None)

        tags = self.vault.all_tags()
        if tags:
            tk.Label(self._tags_frame, text="TAGS", bg=theme.SIDEBAR, fg=theme.TEXT_MUTED,
                     font=theme.FONT_SMALL, anchor="w").pack(fill="x", padx=16, pady=(8, 4))
            for t in tags:
                self._make_nav_item(self._tags_frame, "#", t, None, self._active_tag == t,
                                     lambda t=t: self._select_tag(t), small=True)

    def _make_nav_item(self, parent, icon, label, count, selected, on_click, badge_color=None, small=False):
        bg = theme.SIDEBAR_SELECTED if selected else theme.SIDEBAR
        row = tk.Frame(parent, bg=bg, cursor="hand2")
        row.pack(fill="x", padx=8, pady=1)
        inner = tk.Frame(row, bg=bg, padx=10, pady=6)
        inner.pack(fill="x")
        icon_lbl = tk.Label(inner, text=icon, bg=bg, fg=theme.ACCENT if selected else theme.TEXT_MUTED,
                             font=(theme.FONT_FAMILY, 10 if small else 11))
        icon_lbl.pack(side="left", padx=(0, 8))
        text_lbl = tk.Label(inner, text=label, bg=bg, fg=theme.TEXT,
                             font=theme.FONT_SMALL if small else theme.FONT_NORMAL, anchor="w")
        text_lbl.pack(side="left", fill="x", expand=True)
        if count is not None:
            tk.Label(inner, text=str(count), bg=bg, fg=(badge_color or theme.TEXT_MUTED),
                     font=theme.FONT_SMALL).pack(side="right")

        widgets = [row, inner, icon_lbl, text_lbl]

        def on_enter(_=None):
            if not selected:
                for w in widgets:
                    theme.animate_bg(w, theme.SIDEBAR, theme.SIDEBAR_HOVER)

        def on_leave(_=None):
            if not selected:
                for w in widgets:
                    theme.animate_bg(w, theme.SIDEBAR_HOVER, theme.SIDEBAR)

        def click(_=None):
            on_click()

        for w in widgets:
            w.bind("<Enter>", on_enter)
            w.bind("<Leave>", on_leave)
            w.bind("<Button-1>", click)

    def _select_section(self, section):
        self._section = section
        self._active_tag = None
        self._selected_id = None
        self._refresh_sidebar()
        self._refresh_list()
        self._render_detail(None)
        if section == "security":
            self._start_breach_scan()

    def _start_breach_scan(self):
        """Checks every password in the vault against HaveIBeenPwned in the
        background and folds the results into the Security view. Safe to
        call repeatedly - already-checked passwords are served from cache
        instead of hitting the network again."""
        if self._scanning_breaches:
            return
        self._scanning_breaches = True
        if hasattr(self, "_list_header_var"):
            self._list_header_var.set("Scanning for breached passwords…")

        def worker():
            try:
                results = security_scan.breach_scan(self.vault, self._breach_cache)
            except Exception:
                results = {}

            def done():
                self._scanning_breaches = False
                self._breach_results = results
                self._refresh_sidebar()
                if self._section == "security":
                    self._refresh_list()
            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def _select_tag(self, tag):
        self._active_tag = tag
        self._section = "all"
        self._selected_id = None
        self._refresh_sidebar()
        self._refresh_list()
        self._render_detail(None)

    def _accent_button(self, parent, text, command):
        return tk.Button(parent, text=text, command=command, bg=theme.ACCENT, fg=theme.ACCENT_TEXT,
                          activebackground=theme.ACCENT_HOVER, activeforeground=theme.ACCENT_TEXT,
                          font=theme.FONT_BOLD, bd=0, relief="flat", padx=14, pady=8, cursor="hand2")

    def _ghost_button(self, parent, text, command):
        btn = tk.Button(parent, text=text, command=command, bg=theme.SURFACE, fg=theme.TEXT,
                         activebackground=theme.SURFACE_HOVER, activeforeground=theme.TEXT,
                         font=theme.FONT_NORMAL, bd=0, relief="flat", padx=12, pady=8, cursor="hand2",
                         highlightbackground=theme.BORDER, highlightthickness=1)
        return btn

    def _danger_button(self, parent, text, command):
        return tk.Button(parent, text=text, command=command, bg=theme.DANGER, fg="#ffffff",
                          activebackground=theme.DANGER_HOVER, activeforeground="#ffffff",
                          font=theme.FONT_NORMAL, bd=0, relief="flat", padx=10, pady=6, cursor="hand2")

    def _lock_now(self):
        self._server.stop()
        self.vault.lock()
        self._show_unlock_screen()

    def _open_panic_wipe_dialog(self):
        confirm = simpledialog.askstring(
            "Emergency wipe",
            "This permanently deletes the vault file. There is no undo and no backup.\n\n"
            "Type DELETE to confirm:",
            parent=self,
        )
        if confirm != "DELETE":
            return
        self._server.stop()
        self.vault.lock()
        self_destruct.panic_wipe(self.vault.path)
        messagebox.showinfo("Vault wiped", "The vault has been permanently deleted.")
        self._show_unlock_screen()

    def _open_extension_dialog(self):
        win = tk.Toplevel(self)
        win.title("Browser extension")
        win.configure(bg=theme.BG)
        win.transient(self)
        win.grab_set()
        win.geometry("420x320")
        win.minsize(360, 280)

        pad = {"padx": 20}
        tk.Label(win, text="Vault Quick Copy", bg=theme.BG, fg=theme.TEXT,
                 font=theme.FONT_HEADING).pack(anchor="w", padx=20, pady=(20, 4))
        tk.Label(win, text="A small Chrome extension that lists your entries and copies a\n"
                            "password on click, while this app is running and unlocked.",
                 bg=theme.BG, fg=theme.TEXT_MUTED, font=theme.FONT_SMALL, justify="left").pack(
            anchor="w", **pad)

        tk.Label(win, text="1. In Chrome, go to chrome://extensions, enable Developer mode,\n"
                            "   then \"Load unpacked\" and select the browser_extension folder\n"
                            "   next to this app.\n"
                            "2. Click the extension's icon, open its Options, and paste the\n"
                            "   pairing token below.", bg=theme.BG, fg=theme.TEXT,
                 font=theme.FONT_SMALL, justify="left").pack(anchor="w", padx=20, pady=(14, 10))

        tk.Label(win, text="Pairing token", bg=theme.BG, fg=theme.TEXT_MUTED,
                 font=theme.FONT_SMALL).pack(anchor="w", padx=20)
        token_row = tk.Frame(win, bg=theme.BG)
        token_row.pack(fill="x", padx=20, pady=(2, 10))
        token_var = tk.StringVar(value=self._server.token)
        token_entry = tk.Entry(token_row, textvariable=token_var, bg=theme.SURFACE, fg=theme.TEXT,
                                relief="flat", font=theme.FONT_MONO, state="readonly",
                                readonlybackground=theme.SURFACE, highlightthickness=1,
                                highlightbackground=theme.BORDER)
        token_entry.pack(side="left", fill="x", expand=True, ipady=6)

        def copy_token():
            self._copy_to_clipboard(token_var.get(), "Pairing token")
        self._ghost_button(token_row, "Copy", copy_token).pack(side="left", padx=(8, 0))

        status = "Running" if self._server.running else "Not running (unlock the vault first)"
        tk.Label(win, text=f"Local server: {status} - 127.0.0.1:{local_server.PORT}",
                 bg=theme.BG, fg=theme.TEXT_MUTED, font=theme.FONT_SMALL).pack(anchor="w", padx=20)

        self._ghost_button(win, "Close", win.destroy).pack(pady=16)

    # ---------------- middle list pane ----------------

    def _build_list_pane(self, parent):
        pane = tk.Frame(parent, bg=theme.BG)
        pane.pack(side="left", fill="both", expand=True)

        header = tk.Frame(pane, bg=theme.BG, padx=16, pady=12)
        header.pack(fill="x")
        self._list_header_var = tk.StringVar(value="")
        tk.Label(header, textvariable=self._list_header_var, bg=theme.BG, fg=theme.TEXT_MUTED,
                 font=theme.FONT_SMALL).pack(anchor="w")

        list_outer = tk.Frame(pane, bg=theme.BG, padx=10)
        list_outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(list_outer, bg=theme.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(list_outer, orient="vertical", command=canvas.yview)
        self._list_frame = tk.Frame(canvas, bg=theme.BG)

        self._list_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas_window = canvas.create_window((0, 0), window=self._list_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def on_canvas_resize(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind("<Configure>", on_canvas_resize)

        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", on_mousewheel)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self._canvas = canvas

    def _refresh_list(self):
        for w in self._list_frame.winfo_children():
            w.destroy()

        query = self._search_var.get()
        reasons = {}

        if self._section == "security":
            reasons = {}
            for e in security_scan.weak_entries(self.vault):
                reasons.setdefault(e["id"], []).append("Weak")
            for e in security_scan.reused_entries(self.vault):
                reasons.setdefault(e["id"], []).append("Reused")
            for eid in self._breach_results:
                reasons.setdefault(eid, []).append("Breached")
            results = [e for e in self.vault.entries if e["id"] in reasons]
            q = query.lower().strip()
            if q:
                results = [e for e in results if q in e["title"].lower()]
        else:
            favorites_only = (self._section == "favorites")
            kind = "wifi" if self._section == "wifi" else None
            results = self.vault.search(query, tag=self._active_tag, favorites_only=favorites_only, kind=kind)

        results = sorted(results, key=lambda x: x["title"].lower())
        self._list_header_var.set(f"{len(results)} item" + ("" if len(results) == 1 else "s"))

        if not results:
            if query or self._active_tag or self._section != "all":
                msg = "No entries match."
            else:
                msg = "No entries yet. Click “+ Add entry” to get started."
            tk.Label(self._list_frame, text=msg, bg=theme.BG, fg=theme.TEXT_MUTED,
                     font=theme.FONT_NORMAL, pady=40, wraplength=260).pack(fill="x")
            return

        for e in results:
            self._build_list_row(self._list_frame, e, reasons.get(e["id"]))

    def _build_list_row(self, parent, entry, reason_tags=None):
        is_selected = (entry["id"] == self._selected_id)
        bg = theme.ACCENT_SOFT if is_selected else theme.BG
        row = tk.Frame(parent, bg=bg, cursor="hand2")
        row.pack(fill="x", pady=1)
        inner = tk.Frame(row, bg=bg, padx=10, pady=8)
        inner.pack(fill="x")

        is_wifi = entry.get("kind") == "wifi"
        avatar = tk.Canvas(inner, width=32, height=32, bg=bg, highlightthickness=0)
        avatar.pack(side="left", padx=(0, 10))
        oval_id = avatar.create_oval(1, 1, 31, 31, fill=theme.ACCENT_SOFT, outline="")
        avatar_glyph = "\U0001F4F6" if is_wifi else theme.initials(entry["title"])
        text_id = avatar.create_text(16, 16, text=avatar_glyph, fill=theme.ACCENT,
                                      font=theme.FONT_SMALL)

        text_col = tk.Frame(inner, bg=bg)
        text_col.pack(side="left", fill="x", expand=True)
        title_row = tk.Frame(text_col, bg=bg)
        title_row.pack(fill="x")
        tk.Label(title_row, text=entry["title"], bg=bg, fg=theme.TEXT, font=theme.FONT_NORMAL,
                 anchor="w").pack(side="left")
        if entry.get("favorite"):
            tk.Label(title_row, text=theme.STAR_FILLED, bg=bg, fg=theme.STAR_GOLD,
                     font=theme.FONT_SMALL).pack(side="left", padx=(6, 0))
        subtitle = entry.get("username") or entry.get("url") or ""
        tk.Label(text_col, text=subtitle, bg=bg, fg=theme.TEXT_MUTED, font=theme.FONT_SMALL,
                 anchor="w").pack(fill="x")

        if reason_tags:
            badges = tk.Frame(text_col, bg=bg)
            badges.pack(fill="x", pady=(3, 0), anchor="w")
            for r in reason_tags:
                color = theme.DANGER if r in ("Weak", "Breached") else theme.WARNING
                tk.Label(badges, text=r, bg=color, fg="#ffffff", font=theme.FONT_SMALL,
                         padx=6, pady=1).pack(side="left", padx=(0, 4))

        def select(_=None):
            self._selected_id = entry["id"]
            self._refresh_list()
            self._render_detail(entry["id"])

        clickable = [row, inner, avatar, text_col] + list(text_col.winfo_children())
        for w in clickable:
            w.bind("<Button-1>", select)

        if not is_selected:
            hover_targets = [row, inner, text_col]

            def on_enter(_=None):
                for w in hover_targets:
                    theme.animate_bg(w, theme.BG, theme.SURFACE_HOVER)

            def on_leave(_=None):
                for w in hover_targets:
                    theme.animate_bg(w, theme.SURFACE_HOVER, theme.BG)

            for w in hover_targets:
                w.bind("<Enter>", on_enter)
                w.bind("<Leave>", on_leave)

        if not is_wifi:
            domain_source = entry.get("url") or entry.get("title")
            self._load_favicon_async(domain_source, lambda photo: self._apply_favicon(avatar, oval_id, text_id, photo))

    # ---------------- favicon loading ----------------

    def _load_favicon_async(self, source, callback):
        if not source:
            return

        def worker():
            path = favicon.fetch_favicon_path(source)
            if not path:
                return

            def on_main():
                try:
                    photo = tk.PhotoImage(file=path)
                except Exception:
                    return
                callback(photo)
            self.after(0, on_main)

        threading.Thread(target=worker, daemon=True).start()

    def _apply_favicon(self, canvas, oval_id, text_id, photo):
        try:
            if not canvas.winfo_exists():
                return
            size = int(canvas["width"])
            display = photo
            if size <= 32:
                try:
                    display = photo.subsample(2, 2)
                except Exception:
                    display = photo
            canvas.delete(oval_id)
            canvas.delete(text_id)
            canvas.create_image(size // 2, size // 2, image=display)
            canvas.image = display  # keep a reference alive - Tk drops GC'd PhotoImages
        except tk.TclError:
            pass

    # ---------------- right detail pane ----------------

    def _build_detail_pane(self, parent):
        tk.Frame(parent, bg=theme.BORDER, width=1).pack(side="right", fill="y")
        detail = tk.Frame(parent, bg=theme.SURFACE, width=340)
        detail.pack(side="right", fill="y")
        detail.pack_propagate(False)
        self._detail_frame = detail

    def _render_detail(self, entry_id):
        for w in self._detail_frame.winfo_children():
            w.destroy()

        if not entry_id:
            wrap = tk.Frame(self._detail_frame, bg=theme.SURFACE)
            wrap.place(relx=0.5, rely=0.4, anchor="center")
            tk.Label(wrap, text=theme.LOCK_GLYPH, bg=theme.SURFACE, font=(theme.FONT_FAMILY, 28),
                     fg=theme.TEXT_MUTED).pack(pady=(0, 10))
            tk.Label(wrap, text="Select an item to view its details", bg=theme.SURFACE,
                     fg=theme.TEXT_MUTED, font=theme.FONT_SMALL).pack()
            return

        entry = next((e for e in self.vault.entries if e["id"] == entry_id), None)
        if not entry:
            self._selected_id = None
            self._render_detail(None)
            return

        is_wifi = entry.get("kind") == "wifi"

        header = tk.Frame(self._detail_frame, bg=theme.SURFACE, padx=24, pady=24)
        header.pack(fill="x")

        icon_canvas = tk.Canvas(header, width=56, height=56, bg=theme.SURFACE, highlightthickness=0)
        icon_canvas.pack()
        oval_id = icon_canvas.create_oval(2, 2, 54, 54, fill=theme.ACCENT_SOFT, outline="")
        icon_glyph = "\U0001F4F6" if is_wifi else theme.initials(entry["title"])
        text_id = icon_canvas.create_text(28, 28, text=icon_glyph, fill=theme.ACCENT,
                                           font=(theme.FONT_FAMILY, 16, "bold"))
        if not is_wifi:
            domain_source = entry.get("url") or entry.get("title")
            self._load_favicon_async(domain_source, lambda photo: self._apply_favicon(icon_canvas, oval_id, text_id, photo))

        title_row = tk.Frame(header, bg=theme.SURFACE)
        title_row.pack(pady=(10, 0))
        tk.Label(title_row, text=entry["title"], bg=theme.SURFACE, fg=theme.TEXT,
                 font=theme.FONT_HEADING).pack(side="left")

        star_btn = tk.Label(title_row, text=theme.STAR_FILLED if entry.get("favorite") else theme.STAR_OUTLINE,
                             bg=theme.SURFACE, fg=theme.STAR_GOLD if entry.get("favorite") else theme.TEXT_MUTED,
                             font=(theme.FONT_FAMILY, 14), cursor="hand2")
        star_btn.pack(side="left", padx=(8, 0))

        def toggle_fav(_=None):
            self.vault.toggle_favorite(entry["id"])
            self._refresh_sidebar()
            self._refresh_list()
            self._render_detail(entry["id"])
        star_btn.bind("<Button-1>", toggle_fav)

        body = tk.Frame(self._detail_frame, bg=theme.SURFACE, padx=24)
        body.pack(fill="both", expand=True)

        def field_row(label_text, value, copy_value=None, secret=False):
            wrap = tk.Frame(body, bg=theme.SURFACE)
            wrap.pack(fill="x", pady=(0, 14))
            tk.Label(wrap, text=label_text, bg=theme.SURFACE, fg=theme.TEXT_MUTED,
                     font=theme.FONT_SMALL, anchor="w").pack(fill="x")
            row = tk.Frame(wrap, bg=theme.SURFACE)
            row.pack(fill="x", pady=(2, 0))
            display_var = tk.StringVar(value=("•" * min(len(value), 16)) if secret else value)
            tk.Label(row, textvariable=display_var, bg=theme.SURFACE, fg=theme.TEXT,
                     font=theme.FONT_NORMAL, anchor="w").pack(side="left", fill="x", expand=True)
            if secret:
                state = {"shown": False}
                eye_btn = tk.Label(row, text="Show", bg=theme.SURFACE, fg=theme.ACCENT,
                                    font=theme.FONT_SMALL, cursor="hand2")

                def toggle_show(_=None):
                    state["shown"] = not state["shown"]
                    display_var.set(value if state["shown"] else "•" * min(len(value), 16))
                    eye_btn.config(text="Hide" if state["shown"] else "Show")
                eye_btn.bind("<Button-1>", toggle_show)
                eye_btn.pack(side="right", padx=(8, 0))
            if copy_value is not None:
                copy_btn = tk.Label(row, text="Copy", bg=theme.SURFACE, fg=theme.ACCENT,
                                     font=theme.FONT_SMALL, cursor="hand2")
                copy_btn.bind("<Button-1>", lambda _: self._copy_to_clipboard(copy_value, label_text))
                copy_btn.pack(side="right", padx=(8, 0))

        if entry.get("username"):
            field_row("Username", entry["username"], copy_value=entry["username"])

        field_row("Password", entry["password"], copy_value=entry["password"], secret=True)

        score, label = estimate_strength(entry["password"])
        color = STRENGTH_COLORS[score]
        meter_wrap = tk.Frame(body, bg=theme.SURFACE)
        meter_wrap.pack(fill="x", pady=(0, 6))
        meter_bg = tk.Frame(meter_wrap, bg=theme.BORDER, height=5)
        meter_bg.pack(fill="x")
        meter_fill = tk.Frame(meter_bg, bg=color, height=5)
        meter_fill.place(x=0, y=0, relheight=1, relwidth=(score + 1) / 5)
        tk.Label(meter_wrap, text=label, bg=theme.SURFACE, fg=color, font=theme.FONT_SMALL,
                 anchor="w").pack(fill="x", pady=(4, 0))

        if entry["id"] in self.vault.duplicate_password_ids():
            tk.Label(body, text="⚠ Reused on another entry", bg=theme.SURFACE, fg=theme.WARNING,
                     font=theme.FONT_SMALL, anchor="w").pack(fill="x", pady=(0, 10))
        if entry["id"] in self._breach_results:
            count = self._breach_results[entry["id"]]
            tk.Label(body, text=f"⚠ Found in {count:,} known breaches", bg=theme.SURFACE,
                     fg=theme.DANGER, font=theme.FONT_SMALL, anchor="w").pack(fill="x", pady=(0, 10))
        if not (entry["id"] in self.vault.duplicate_password_ids() or entry["id"] in self._breach_results):
            tk.Frame(body, bg=theme.SURFACE, height=4).pack()

        if is_wifi and entry.get("security_type"):
            field_row("Security type", entry["security_type"])

        breach_row = tk.Frame(body, bg=theme.SURFACE)
        breach_row.pack(fill="x", pady=(0, 14))
        self._ghost_button(breach_row, "Check breach history",
                            lambda: self._run_detail_breach_check(entry, breach_label)).pack(side="left")
        breach_label = tk.Label(breach_row, text="", bg=theme.SURFACE, fg=theme.TEXT_MUTED, font=theme.FONT_SMALL)
        breach_label.pack(side="left", padx=10)

        if entry.get("url"):
            field_row("Website", entry["url"], copy_value=entry["url"])

        if entry.get("tags"):
            tk.Label(body, text="Tags", bg=theme.SURFACE, fg=theme.TEXT_MUTED, font=theme.FONT_SMALL,
                     anchor="w").pack(fill="x", pady=(0, 4))
            tag_wrap = tk.Frame(body, bg=theme.SURFACE)
            tag_wrap.pack(fill="x", pady=(0, 14), anchor="w")
            for t in entry["tags"]:
                tk.Label(tag_wrap, text=t, bg=theme.ACCENT_SOFT, fg=theme.ACCENT, font=theme.FONT_SMALL,
                         padx=7, pady=1).pack(side="left", padx=(0, 4))

        if entry.get("notes"):
            tk.Label(body, text="Notes", bg=theme.SURFACE, fg=theme.TEXT_MUTED, font=theme.FONT_SMALL,
                     anchor="w").pack(fill="x", pady=(0, 4))
            tk.Label(body, text=entry["notes"], bg=theme.SURFACE, fg=theme.TEXT, font=theme.FONT_NORMAL,
                     anchor="w", justify="left", wraplength=280).pack(fill="x", pady=(0, 14))

        actions = tk.Frame(self._detail_frame, bg=theme.SURFACE, padx=24, pady=16)
        actions.pack(fill="x", side="bottom")

        def edit():
            EntryDialog(self, self.vault, entry=entry, on_saved=self._on_entry_saved)

        def delete():
            if messagebox.askyesno("Delete entry", f"Delete '{entry['title']}'? This cannot be undone."):
                self.vault.delete_entry(entry["id"])
                self._selected_id = None
                self._on_entry_saved()

        self._danger_button(actions, "Delete", delete).pack(side="right")
        self._ghost_button(actions, "Edit", edit).pack(side="right", padx=(0, 8))

    def _run_detail_breach_check(self, entry, label_widget):
        pw = entry["password"]
        label_widget.config(text="Checking…", fg=theme.TEXT_MUTED)

        def worker():
            try:
                count = check_password_breach(pw)
                if count > 0:
                    text, color = f"Found in {count:,} breaches", theme.DANGER
                else:
                    text, color = "Not found in known breaches", theme.SUCCESS
            except BreachCheckError:
                text, color = "Couldn't check (offline)", theme.TEXT_MUTED
            self.after(0, lambda: label_widget.config(text=text, fg=color) if label_widget.winfo_exists() else None)

        threading.Thread(target=worker, daemon=True).start()

    # ---------------- clipboard ----------------

    def _copy_to_clipboard(self, text, label):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        if self._clipboard_job is not None:
            self.after_cancel(self._clipboard_job)
        self._clipboard_job = self.after(CLIPBOARD_CLEAR_MS, self._clear_clipboard)
        self._flash_status(f"{label} copied — clipboard clears in 20s")

    def _clear_clipboard(self):
        try:
            self.clipboard_clear()
        except tk.TclError:
            pass

    def _flash_status(self, msg):
        if hasattr(self, "_status_var"):
            old = self._status_var.get()
            self._status_var.set(msg)
            self.after(2500, lambda: self._status_var.set(old))

    # ---------------- dialogs ----------------

    def _on_entry_saved(self):
        self._refresh_sidebar()
        self._refresh_list()
        self._render_detail(self._selected_id)

    def _open_add_dialog(self):
        EntryDialog(self, self.vault, on_saved=self._on_entry_saved)

    def _open_generator_dialog(self):
        GeneratorDialog(self)

    def _open_change_master_dialog(self):
        current = simpledialog.askstring("Verify identity", "Enter current master password:", show="•", parent=self)
        if current is None:
            return
        if current != self.vault.master_password:
            messagebox.showerror("Incorrect", "Current master password is incorrect.")
            return
        new_pw = simpledialog.askstring("New master password", "Enter new master password (8+ chars):", show="•", parent=self)
        if not new_pw:
            return
        if len(new_pw) < 8:
            messagebox.showerror("Too short", "Use at least 8 characters.")
            return
        confirm = simpledialog.askstring("Confirm", "Confirm new master password:", show="•", parent=self)
        if confirm != new_pw:
            messagebox.showerror("Mismatch", "Passwords did not match. Nothing was changed.")
            return
        self.vault.change_master_password(new_pw)
        messagebox.showinfo("Done", "Master password changed.")


class StyledDialog(tk.Toplevel):
    """Base class giving every dialog the same dark theme."""
    def __init__(self, parent, title, w, h):
        super().__init__(parent)
        self.configure(bg=theme.BG)
        self.title(title)
        self.geometry(f"{w}x{h}")
        self.minsize(360, 280)
        self.resizable(True, True)
        self.transient(parent)
        self.grab_set()

    def make_scrollable_body(self):
        """Returns a Frame to pack form widgets into. The dialog scrolls
        with the mouse wheel and resizes/shrinks gracefully instead of
        clipping content on small screens or high DPI scaling - fixes
        fields/buttons becoming unreachable with no way to get to them."""
        container = tk.Frame(self, bg=theme.BG)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container, bg=theme.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        body = tk.Frame(canvas, bg=theme.BG)

        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        window = canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def on_canvas_resize(event):
            canvas.itemconfig(window, width=event.width)
        canvas.bind("<Configure>", on_canvas_resize)

        def on_wheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        # Bound on the dialog itself (part of the default bindtag chain for
        # every widget inside it), not bind_all - so it's automatically
        # scoped to this dialog and cleaned up when the dialog closes.
        self.bind("<MouseWheel>", on_wheel)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return body

    def label(self, parent, text, muted=False):
        return tk.Label(parent, text=text, bg=theme.BG, fg=theme.TEXT_MUTED if muted else theme.TEXT,
                         font=theme.FONT_SMALL if muted else theme.FONT_NORMAL, anchor="w")

    def entry(self, parent, var, show=None):
        kwargs = dict(textvariable=var, bg=theme.SURFACE, fg=theme.TEXT, insertbackground=theme.TEXT,
                      relief="flat", font=theme.FONT_NORMAL, highlightthickness=1,
                      highlightbackground=theme.BORDER, highlightcolor=theme.ACCENT)
        if show:
            kwargs["show"] = show
        return tk.Entry(parent, **kwargs)

    def accent_button(self, parent, text, command):
        return tk.Button(parent, text=text, command=command, bg=theme.ACCENT, fg=theme.ACCENT_TEXT,
                          activebackground=theme.ACCENT_HOVER, activeforeground=theme.ACCENT_TEXT,
                          font=theme.FONT_BOLD, bd=0, relief="flat", padx=16, pady=8, cursor="hand2")

    def ghost_button(self, parent, text, command):
        return tk.Button(parent, text=text, command=command, bg=theme.SURFACE, fg=theme.TEXT,
                          activebackground=theme.SURFACE_HOVER, activeforeground=theme.TEXT,
                          font=theme.FONT_NORMAL, bd=0, relief="flat", padx=14, pady=8, cursor="hand2")


STRENGTH_COLORS = {
    0: theme.DANGER, 1: theme.DANGER, 2: "#b08a2e", 3: theme.SUCCESS, 4: theme.SUCCESS,
}


class EntryDialog(StyledDialog):
    def __init__(self, parent, vault: Vault, entry=None, on_saved=None):
        super().__init__(parent, "Edit entry" if entry else "Add entry", 460, 560)
        self.vault = vault
        self.entry_data = entry
        self.on_saved = on_saved

        # Button bar is packed FIRST so it claims its space at the bottom;
        # the scrollable body (packed after) fills whatever remains. Packing
        # order the other way would let the expanding body consume the
        # whole window before the buttons get a chance to reserve room.
        btns = tk.Frame(self, bg=theme.BG)
        btns.pack(fill="x", padx=20, pady=16, side="bottom")
        self.accent_button(btns, "Save", self._save).pack(side="right")
        self.ghost_button(btns, "Cancel", self.destroy).pack(side="right", padx=(0, 8))

        body = self.make_scrollable_body()
        pad = {"padx": 20, "pady": (14, 4)}

        self.title_var = tk.StringVar(value=entry["title"] if entry else "")
        self.username_var = tk.StringVar(value=entry.get("username", "") if entry else "")
        self.password_var = tk.StringVar(value=entry.get("password", "") if entry else "")
        self.url_var = tk.StringVar(value=entry.get("url", "") if entry else "")
        self.notes_var = tk.StringVar(value=entry.get("notes", "") if entry else "")
        self.tags_var = tk.StringVar(value=", ".join(entry.get("tags", [])) if entry else "")
        self.favorite_var = tk.BooleanVar(value=bool(entry.get("favorite")) if entry else False)
        self.kind_var = tk.StringVar(value=entry.get("kind", "login") if entry else "login")
        self.security_type_var = tk.StringVar(
            value=entry.get("security_type", "WPA2/WPA3") if entry else "WPA2/WPA3")

        kind_row = tk.Frame(body, bg=theme.BG)
        kind_row.pack(fill="x", padx=20, pady=(16, 10))
        self._kind_buttons = {}
        for value, label in (("login", "Login"), ("wifi", "Wi-Fi network")):
            def make_cmd(v=value):
                return lambda: self._set_kind(v)
            btn = tk.Button(kind_row, text=label, command=make_cmd(), bd=0, relief="flat",
                             font=theme.FONT_SMALL, padx=12, pady=6, cursor="hand2")
            btn.pack(side="left", padx=(0, 6))
            self._kind_buttons[value] = btn

        title_row = tk.Frame(body, bg=theme.BG)
        title_row.pack(fill="x", padx=20, pady=(10, 4))
        self._title_label = self.label(title_row, "Title")
        self._title_label.pack(side="left")
        tk.Checkbutton(title_row, text=f"{theme.STAR_FILLED} Favorite", variable=self.favorite_var,
                       bg=theme.BG, fg=theme.TEXT_MUTED, selectcolor=theme.SURFACE,
                       activebackground=theme.BG, font=theme.FONT_SMALL).pack(side="right")
        self.entry(body, self.title_var).pack(fill="x", padx=20, ipady=6)

        # A single fixed slot packed once, right after the title - its
        # contents are rebuilt (not pack_forget'd) on kind toggle, since
        # re-packing a forgotten widget would otherwise jump it to the end
        # of the layout instead of back into this spot.
        self._dynamic_slot = tk.Frame(body, bg=theme.BG)
        self._dynamic_slot.pack(fill="x", padx=20)

        self.label(body, "Password").pack(fill="x", **pad)
        pw_frame = tk.Frame(body, bg=theme.BG)
        pw_frame.pack(fill="x", padx=20)
        self.show_pw = tk.BooleanVar(value=False)
        pw_entry = self.entry(pw_frame, self.password_var, show="•")
        pw_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self._pw_entry = pw_entry

        def toggle_show():
            pw_entry.config(show="" if self.show_pw.get() else "•")
        tk.Checkbutton(pw_frame, text="show", variable=self.show_pw, command=toggle_show,
                       bg=theme.BG, fg=theme.TEXT_MUTED, selectcolor=theme.SURFACE,
                       activebackground=theme.BG, font=theme.FONT_SMALL).pack(side="left", padx=6)
        self.ghost_button(pw_frame, "Gen", self._generate_into_field).pack(side="left")

        # ---- strength meter ----
        meter_frame = tk.Frame(body, bg=theme.BG)
        meter_frame.pack(fill="x", padx=20, pady=(6, 0))
        self._meter_bar_bg = tk.Frame(meter_frame, bg=theme.BORDER, height=5)
        self._meter_bar_bg.pack(fill="x")
        self._meter_fill = tk.Frame(self._meter_bar_bg, bg=theme.BORDER, height=5)
        self._meter_fill.place(x=0, y=0, relheight=1, relwidth=0)
        self._strength_label = tk.Label(meter_frame, text="", bg=theme.BG, fg=theme.TEXT_MUTED,
                                         font=theme.FONT_SMALL, anchor="w")
        self._strength_label.pack(fill="x", pady=(4, 0))

        self.password_var.trace_add("write", lambda *_: self._update_strength())
        self._update_strength()

        # ---- breach check ----
        breach_row = tk.Frame(body, bg=theme.BG)
        breach_row.pack(fill="x", padx=20, pady=(8, 0))
        self.ghost_button(breach_row, "Check breach history", self._run_breach_check).pack(side="left")
        self._breach_label = tk.Label(breach_row, text="", bg=theme.BG, fg=theme.TEXT_MUTED,
                                       font=theme.FONT_SMALL)
        self._breach_label.pack(side="left", padx=10)

        self.label(body, "URL (optional)").pack(fill="x", **pad)
        self.entry(body, self.url_var).pack(fill="x", padx=20, ipady=6)

        self.label(body, "Tags (comma-separated, optional)").pack(fill="x", **pad)
        self.entry(body, self.tags_var).pack(fill="x", padx=20, ipady=6)

        self.label(body, "Notes (optional)").pack(fill="x", **pad)
        self.entry(body, self.notes_var).pack(fill="x", padx=20, ipady=6)
        tk.Frame(body, bg=theme.BG, height=16).pack()  # bottom breathing room

        self._set_kind(self.kind_var.get())

    def _set_kind(self, value):
        self.kind_var.set(value)
        for v, btn in self._kind_buttons.items():
            active = v == value
            btn.configure(bg=theme.ACCENT if active else theme.SURFACE,
                          fg=theme.ACCENT_TEXT if active else theme.TEXT)

        for w in self._dynamic_slot.winfo_children():
            w.destroy()

        if value == "wifi":
            self._title_label.configure(text="Network name (SSID)")
            self.label(self._dynamic_slot, "Security type").pack(fill="x", pady=(0, 4))
            sec_menu = tk.OptionMenu(self._dynamic_slot, self.security_type_var,
                                      "WPA2/WPA3", "WPA3", "WPA2", "WEP", "Open")
            sec_menu.configure(bg=theme.SURFACE, fg=theme.TEXT, activebackground=theme.SURFACE_HOVER,
                                font=theme.FONT_NORMAL, bd=0, relief="flat", highlightthickness=1,
                                highlightbackground=theme.BORDER, anchor="w")
            sec_menu.pack(fill="x", ipady=4)
        else:
            self._title_label.configure(text="Title")
            self.label(self._dynamic_slot, "Username / email").pack(fill="x", pady=(0, 4))
            self.entry(self._dynamic_slot, self.username_var).pack(fill="x", ipady=6)

    def _update_strength(self):
        pw = self.password_var.get()
        if not pw:
            self._meter_fill.place(relwidth=0)
            self._strength_label.config(text="")
            return
        score, label = estimate_strength(pw)
        color = STRENGTH_COLORS[score]
        self._meter_fill.configure(bg=color)
        self._meter_fill.place(relwidth=(score + 1) / 5)
        self._strength_label.config(text=label, fg=color)

    def _run_breach_check(self):
        pw = self.password_var.get()
        if not pw:
            messagebox.showinfo("No password", "Enter a password first.")
            return
        self._breach_label.config(text="Checking…", fg=theme.TEXT_MUTED)

        def worker():
            try:
                count = check_password_breach(pw)
                if count > 0:
                    text, color = f"Found in {count:,} breaches — change it", theme.DANGER
                else:
                    text, color = "Not found in known breaches", theme.SUCCESS
            except BreachCheckError:
                text, color = "Couldn't check (offline or service unavailable)", theme.TEXT_MUTED
            self.after(0, lambda: self._breach_label.config(text=text, fg=color))

        threading.Thread(target=worker, daemon=True).start()

    def _generate_into_field(self):
        pw = generate_password(length=20)
        self.password_var.set(pw)
        self.show_pw.set(True)
        self._pw_entry.config(show="")

    def _parse_tags(self) -> list[str]:
        return [t.strip() for t in self.tags_var.get().split(",") if t.strip()]

    def _save(self):
        title = self.title_var.get().strip()
        if not title:
            messagebox.showerror("Missing title", "Title is required.")
            return
        if not self.password_var.get():
            messagebox.showerror("Missing password", "Password is required.")
            return

        kind = self.kind_var.get()
        username = "" if kind == "wifi" else self.username_var.get().strip()
        security_type = self.security_type_var.get() if kind == "wifi" else ""

        if self.entry_data:
            self.vault.update_entry(
                self.entry_data["id"], title=title, username=username,
                password=self.password_var.get(), url=self.url_var.get().strip(),
                notes=self.notes_var.get().strip(), tags=self._parse_tags(),
                favorite=self.favorite_var.get(), kind=kind, security_type=security_type,
            )
        else:
            self.vault.add_entry(
                title=title, username=username,
                password=self.password_var.get(), url=self.url_var.get().strip(),
                notes=self.notes_var.get().strip(), tags=self._parse_tags(),
                favorite=self.favorite_var.get(), kind=kind, security_type=security_type,
            )
        if self.on_saved:
            self.on_saved()
        self.destroy()


class GeneratorDialog(StyledDialog):
    def __init__(self, parent):
        super().__init__(parent, "Password generator", 440, 440)
        self.result_var = tk.StringVar()

        btns = tk.Frame(self, bg=theme.BG)
        btns.pack(fill="x", padx=20, pady=16, side="bottom")
        self.ghost_button(btns, "Passphrase", self._regen_phrase).pack(side="left")
        self.ghost_button(btns, "Regenerate", self._regen).pack(side="left", padx=8)
        self.accent_button(btns, "Copy", self._copy).pack(side="right")

        body = self.make_scrollable_body()

        self.label(body, "Generated value").pack(fill="x", padx=20, pady=(20, 4))
        result_entry = tk.Entry(body, textvariable=self.result_var, bg=theme.SURFACE, fg=theme.ACCENT,
                                 insertbackground=theme.TEXT, relief="flat", font=theme.FONT_MONO,
                                 highlightthickness=1, highlightbackground=theme.BORDER)
        result_entry.pack(fill="x", padx=20, ipady=8)

        meter_frame = tk.Frame(body, bg=theme.BG)
        meter_frame.pack(fill="x", padx=20, pady=(8, 0))
        meter_bg = tk.Frame(meter_frame, bg=theme.BORDER, height=5)
        meter_bg.pack(fill="x")
        self._meter_fill = tk.Frame(meter_bg, bg=theme.BORDER, height=5)
        self._meter_fill.place(x=0, y=0, relheight=1, relwidth=0)
        self._strength_label = tk.Label(meter_frame, text="", bg=theme.BG, fg=theme.TEXT_MUTED,
                                         font=theme.FONT_SMALL, anchor="w")
        self._strength_label.pack(fill="x", pady=(4, 0))
        self.result_var.trace_add("write", lambda *_: self._update_strength())

        self.length_var = tk.IntVar(value=20)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.avoid_ambiguous = tk.BooleanVar(value=True)

        opts = tk.Frame(body, bg=theme.BG)
        opts.pack(fill="x", padx=20, pady=16)

        length_row = tk.Frame(opts, bg=theme.BG)
        length_row.pack(fill="x", pady=(0, 10))
        self.label(length_row, "Length").pack(side="left")
        tk.Spinbox(length_row, from_=8, to=64, textvariable=self.length_var, width=6,
                   bg=theme.SURFACE, fg=theme.TEXT, relief="flat", buttonbackground=theme.SURFACE,
                   insertbackground=theme.TEXT).pack(side="left", padx=10)

        def chk(parent, text, var):
            return tk.Checkbutton(parent, text=text, variable=var, bg=theme.BG, fg=theme.TEXT,
                                   selectcolor=theme.SURFACE, activebackground=theme.BG,
                                   font=theme.FONT_SMALL)

        grid = tk.Frame(opts, bg=theme.BG)
        grid.pack(fill="x")
        chk(grid, "Uppercase", self.use_upper).grid(row=0, column=0, sticky="w", pady=2)
        chk(grid, "Lowercase", self.use_lower).grid(row=0, column=1, sticky="w", pady=2)
        chk(grid, "Digits", self.use_digits).grid(row=1, column=0, sticky="w", pady=2)
        chk(grid, "Symbols", self.use_symbols).grid(row=1, column=1, sticky="w", pady=2)
        chk(grid, "Avoid ambiguous (l/I/1/O/0)", self.avoid_ambiguous).grid(row=2, column=0, columnspan=2, sticky="w", pady=2)
        tk.Frame(body, bg=theme.BG, height=16).pack()  # bottom breathing room

        self._regen()

    def _regen(self):
        try:
            pw = generate_password(
                length=self.length_var.get(), use_upper=self.use_upper.get(),
                use_lower=self.use_lower.get(), use_digits=self.use_digits.get(),
                use_symbols=self.use_symbols.get(), avoid_ambiguous=self.avoid_ambiguous.get(),
            )
            self.result_var.set(pw)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def _regen_phrase(self):
        self.result_var.set(generate_passphrase(4))

    def _update_strength(self):
        pw = self.result_var.get()
        if not pw:
            self._meter_fill.place(relwidth=0)
            self._strength_label.config(text="")
            return
        score, label = estimate_strength(pw)
        color = STRENGTH_COLORS[score]
        self._meter_fill.configure(bg=color)
        self._meter_fill.place(relwidth=(score + 1) / 5)
        self._strength_label.config(text=label, fg=color)

    def _copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.result_var.get())
        self.update()
        messagebox.showinfo("Copied", "Copied to clipboard.")


def main():
    parser = argparse.ArgumentParser(description="Local encrypted password manager")
    parser.add_argument("--vault", default=DEFAULT_VAULT_PATH, help="Path to vault file")
    args = parser.parse_args()

    app = PasswordManagerApp(args.vault)
    app.mainloop()


if __name__ == "__main__":
    main()
