"""LeftoverSweeper: GUI to find and remove the leftovers of uninstalled programs."""
import ctypes
import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cleaner  # noqa: E402
import qsearch  # noqa: E402
import rules  # noqa: E402
import scanner  # noqa: E402
from winutil import is_admin  # noqa: E402

CONF_LABEL = {"high": "High", "medium": "Medium", "low": "Low"}
CONF_ORDER = {"high": 0, "medium": 1, "low": 2}
KIND_LABEL = {"folder": "Folder", "file": "File", "regkey": "Key", "regvalue": "Value"}
CHECKED, UNCHECKED = "☑", "☐"
IGNORE_FILE = os.path.join(rules.DATA_DIR, "ignored.json")


def human_size(n, truncated=False):
    if not n:
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            text = f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            return ("≥ " if truncated else "") + text
        n /= 1024


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


class IgnoreList:
    def __init__(self):
        try:
            with open(IGNORE_FILE, encoding="utf-8") as f:
                self.keys = set(json.load(f))
        except (OSError, ValueError):
            self.keys = set()

    def add(self, keys):
        self.keys.update(keys)
        try:
            os.makedirs(rules.DATA_DIR, exist_ok=True)
            with open(IGNORE_FILE, "w", encoding="utf-8") as f:
                json.dump(sorted(self.keys), f, ensure_ascii=False, indent=1)
        except OSError:
            pass


class ResultsView(ttk.Frame):
    """Results table with checkboxes, a confidence filter and a context menu."""

    COLUMNS = (("sel", "", 34), ("conf", "Confidence", 85), ("kind", "Type", 70), ("cat", "Category", 230),
               ("path", "Location", 520), ("size", "Size", 80))

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.items = {}
        self.checked = set()
        self.filter = "all"

        self.tree = ttk.Treeview(self, columns=[c[0] for c in self.COLUMNS], show="headings", selectmode="extended")
        for col, title, width in self.COLUMNS:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, stretch=col in ("path", "cat"),
                             anchor="center" if col in ("sel", "conf", "kind") else "w")
        self.tree.column("size", anchor="e")
        self.tree.tag_configure("high", foreground="#1a7f37")
        self.tree.tag_configure("medium", foreground="#9a6700")
        self.tree.tag_configure("low", foreground="#6e7781")
        ys = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")

        self.detail = ttk.Label(self, text="", wraplength=900, justify="left", foreground="#444")
        self.detail.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.bind("<Configure>", lambda e: self.detail.configure(wraplength=max(300, e.width - 20)))

        self.tree.bind("<Button-1>", self._on_click)
        self.tree.bind("<space>", lambda e: self._toggle_selection())
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self._open_location())
        self.tree.bind("<Button-3>", self._on_right_click)

        self.menu = tk.Menu(self, tearoff=False)
        self.menu.add_command(label="Tick / untick", command=self._toggle_selection)
        self.menu.add_command(label="Open location", command=self._open_location)
        self.menu.add_command(label="Copy path", command=self._copy_path)
        self.menu.add_separator()
        self.menu.add_command(label="Not a leftover (always ignore)", command=self._ignore)

    # -------------------------------------------------- data

    def set_items(self, items, preselect=("high",)):
        self.items = {}
        for i, it in enumerate(sorted(items, key=lambda x: (CONF_ORDER[x.confidence], x.category, x.path.lower()))):
            self.items[str(i)] = it
        self.checked = {iid for iid, it in self.items.items() if it.confidence in preselect}
        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for iid, it in self.items.items():
            if self.filter != "all" and it.confidence != self.filter:
                continue
            self.tree.insert("", "end", iid=iid, tags=(it.confidence,), values=(
                CHECKED if iid in self.checked else UNCHECKED, CONF_LABEL[it.confidence], KIND_LABEL[it.kind],
                it.category, it.display_path, human_size(it.size, it.size_truncated)))
        self.app.update_summary()

    def set_filter(self, value):
        self.filter = value
        self.refresh()

    def visible_ids(self):
        return list(self.tree.get_children())

    def mark(self, predicate):
        self.checked = {iid for iid in self.visible_ids() if predicate(self.items[iid])} | {
            iid for iid in self.checked if iid not in self.visible_ids()}
        self.refresh()

    def checked_items(self):
        return [self.items[i] for i in self.checked if i in self.items]

    def remove(self, items):
        keys = {it.key for it in items}
        for iid in [i for i, it in self.items.items() if it.key in keys]:
            del self.items[iid]
            self.checked.discard(iid)
        self.refresh()

    def stats(self):
        checked = self.checked_items()
        return len(self.items), len(checked), sum(i.size for i in checked)

    # -------------------------------------------------- events

    def _set_checked(self, iid, value):
        (self.checked.add if value else self.checked.discard)(iid)
        self.tree.set(iid, "sel", CHECKED if value else UNCHECKED)

    def _on_click(self, event):
        if self.tree.identify_region(event.x, event.y) == "cell" and self.tree.identify_column(event.x) == "#1":
            iid = self.tree.identify_row(event.y)
            if iid:
                self._set_checked(iid, iid not in self.checked)
                self.app.update_summary()
                return "break"

    def _toggle_selection(self):
        sel = self.tree.selection()
        if sel:
            value = not all(i in self.checked for i in sel)
            for iid in sel:
                self._set_checked(iid, value)
            self.app.update_summary()

    def _on_select(self, _event):
        sel = self.tree.selection()
        if sel:
            it = self.items[sel[0]]
            admin = " · Requires administrator." if rules.requires_admin(it) else ""
            self.detail.configure(text=f"{it.display_path}\n{it.reason}{admin}")

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            if iid not in self.tree.selection():
                self.tree.selection_set(iid)
            self.menu.tk_popup(event.x_root, event.y_root)

    def _focused(self):
        sel = self.tree.selection()
        return self.items[sel[0]] if sel else None

    def _open_location(self):
        it = self._focused()
        if not it:
            return
        if it.kind in ("folder", "file"):
            if os.path.exists(it.path):
                subprocess.Popen(["explorer", "/select,", it.path])
        else:
            self._copy_path()
            messagebox.showinfo(rules.APP_NAME, "Registry path copied to the clipboard.\n"
                                "Paste it into the address bar of the Registry Editor (regedit).", parent=self)

    def _copy_path(self):
        it = self._focused()
        if it:
            self.clipboard_clear()
            self.clipboard_append(it.path)

    def _ignore(self):
        items = [self.items[i] for i in self.tree.selection()]
        if items:
            self.app.ignored.add(it.key for it in items)
            self.remove(items)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{rules.APP_NAME} {rules.APP_VERSION} — Uninstall leftover cleaner")
        self.geometry("1180x700")
        self.minsize(820, 480)
        try:
            self.iconbitmap(resource("icon.ico"))
        except tk.TclError:
            pass
        self.ignored = IgnoreList()
        self.events = queue.Queue()
        self.busy = False
        self.action_buttons = []

        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        line = tkfont.nametofont("TkDefaultFont").metrics("linespace")
        style.configure("Treeview", rowheight=line + 8)
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 15))
        style.configure("Warn.TLabel", foreground="#b42318")

        self._build_header()
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(6, 0))
        self._build_scan_tab()
        self._build_search_tab()
        self._build_quarantine_tab()
        self._build_status()
        self.notebook.bind("<<NotebookTabChanged>>", lambda e: self.update_summary())
        self.after(100, self._poll)
        self.refresh_quarantine()

    # -------------------------------------------------- layout

    def _build_header(self):
        top = ttk.Frame(self, padding=(12, 10, 12, 0))
        top.pack(fill="x")
        ttk.Label(top, text=rules.APP_NAME, style="Title.TLabel").pack(side="left")
        ttk.Label(top, text="  Finds and removes what programs leave behind when uninstalled. "
                            "Everything goes through the quarantine and can be restored.").pack(side="left")
        if is_admin():
            ttk.Label(top, text="✔ Administrator", foreground="#1a7f37").pack(side="right")
        else:
            ttk.Button(top, text="Restart as administrator", command=self.relaunch_as_admin).pack(side="right")
            ttk.Label(top, text="No administrator rights  ", style="Warn.TLabel").pack(side="right")

    def _marking_bar(self, parent, view):
        bar = ttk.Frame(parent)
        ttk.Label(bar, text="Tick:").pack(side="left")
        ttk.Button(bar, text="High confidence", command=lambda: view.mark(lambda i: i.confidence == "high")
                   ).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="All visible", command=lambda: view.mark(lambda i: True)).pack(side="left", padx=4)
        ttk.Button(bar, text="None", command=lambda: view.mark(lambda i: False)).pack(side="left")
        ttk.Label(bar, text="   Show:").pack(side="left")
        combo = ttk.Combobox(bar, state="readonly", width=12, values=["All", "High", "Medium", "Low"])
        combo.current(0)
        combo.bind("<<ComboboxSelected>>", lambda e: view.set_filter(combo.get().lower()))
        combo.pack(side="left", padx=(6, 0))
        btn = ttk.Button(bar, text="Move to quarantine", command=lambda: self.clean(view))
        btn.pack(side="right")
        self.action_buttons.append(btn)
        btn = ttk.Button(bar, text="Tick all and move to quarantine…", command=lambda: self.clean_all(view))
        btn.pack(side="right", padx=6)
        self.action_buttons.append(btn)
        return bar

    def _build_scan_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  Full scan  ")
        top = ttk.Frame(tab)
        top.pack(fill="x")
        btn = ttk.Button(top, text="Scan this PC", command=self.start_scan)
        btn.pack(side="left")
        self.action_buttons.append(btn)
        ttk.Label(top, text="  Looks for folders, registry keys, shortcuts and startup entries with no owning "
                            "program. Only high-confidence items are ticked by default.").pack(side="left")
        self.scan_view = ResultsView(tab, self)
        self.scan_view.pack(fill="both", expand=True, pady=8)
        self._marking_bar(tab, self.scan_view).pack(fill="x")

    def _build_search_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  Search by name  ")
        top = ttk.Frame(tab)
        top.pack(fill="x")
        ttk.Label(top, text="Name of the uninstalled program:").pack(side="left")
        self.search_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.search_var, width=36)
        entry.pack(side="left", padx=6)
        entry.bind("<Return>", lambda e: self.start_search())
        btn = ttk.Button(top, text="Find leftovers", command=self.start_search)
        btn.pack(side="left")
        self.action_buttons.append(btn)
        self.search_warning = ttk.Label(tab, text="", style="Warn.TLabel", wraplength=1000)
        self.search_warning.pack(fill="x", pady=(6, 0))
        self.search_view = ResultsView(tab, self)
        self.search_view.pack(fill="both", expand=True, pady=8)
        self._marking_bar(tab, self.search_view).pack(fill="x")

    def _build_quarantine_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  Quarantine  ")
        ttk.Label(tab, text="Removed items. You can put them back or delete them for good once you have "
                            "checked that everything works.").pack(fill="x")

        find = ttk.Frame(tab)
        find.pack(fill="x", pady=(8, 0))
        ttk.Label(find, text="Find:").pack(side="left")
        self.qsearch_var = tk.StringVar()
        entry = ttk.Entry(find, textvariable=self.qsearch_var)
        entry.pack(side="left", fill="x", expand=True, padx=6)
        entry.bind("<KeyRelease>", lambda e: self._schedule_qfilter())
        entry.bind("<<Paste>>", lambda e: self.after(10, self._schedule_qfilter))
        entry.bind("<Escape>", lambda e: self._clear_qsearch())
        ttk.Button(find, text="Clear", command=self._clear_qsearch).pack(side="left")
        ttk.Label(tab, text="Type the program name, a file name (e.g. app.dll) or paste the full error message "
                            "the program showed you. Best matches come first.", foreground="#666"
                  ).pack(fill="x", pady=(2, 0))

        frame = ttk.Frame(tab)
        frame.pack(fill="both", expand=True, pady=8)
        cols = (("date", "Date", 140), ("kind", "Type", 70), ("path", "Original location", 560),
                ("match", "Why it matches", 260), ("size", "Size", 80))
        self.qtree = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings", selectmode="extended")
        for col, title, width in cols:
            self.qtree.heading(col, text=title)
            self.qtree.column(col, width=width, stretch=col in ("path", "match"), anchor="e" if col == "size" else "w")
        self.qtree.tag_configure("best", foreground="#1a7f37")
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.qtree.yview)
        self.qtree.configure(yscrollcommand=ys.set)
        self.qtree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.qtree.bind("<<TreeviewSelect>>", self._on_qselect)
        self.qdetail = ttk.Label(tab, text="", justify="left", foreground="#444", wraplength=1000)
        self.qdetail.pack(fill="x", pady=(0, 6))
        tab.bind("<Configure>", lambda e: self.qdetail.configure(wraplength=max(300, e.width - 30)))

        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        ttk.Button(bar, text="Refresh", command=self.refresh_quarantine).pack(side="left")
        ttk.Button(bar, text="Select all shown", command=lambda: self.qtree.selection_set(self.qtree.get_children())
                   ).pack(side="left", padx=6)
        ttk.Button(bar, text="Open quarantine folder", command=self.open_quarantine_dir).pack(side="left")
        for text, cmd in (("Delete permanently", self.purge_selected), ("Restore", self.restore_selected)):
            btn = ttk.Button(bar, text=text, command=cmd)
            btn.pack(side="right", padx=(6, 0))
            self.action_buttons.append(btn)
        self.qentries = {}
        self.qall = []
        self.qindex = {}
        self.qreasons = {}
        self._qfilter_job = None

    def _build_status(self):
        bar = ttk.Frame(self, padding=(12, 6))
        bar.pack(fill="x")
        self.status = ttk.Label(bar, text="Ready.")
        self.status.pack(side="left", fill="x", expand=True)
        self.summary = ttk.Label(bar, text="")
        self.summary.pack(side="right")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)

    # -------------------------------------------------- background tasks

    def run_task(self, work, on_done):
        if self.busy:
            return
        self.busy = True
        for b in self.action_buttons:
            b.state(["disabled"])
        self.progress.pack(side="right", padx=8)
        self.progress.start(12)

        def runner():
            try:
                result = work(lambda msg: self.events.put(("msg", msg)))
                self.events.put(("done", on_done, result))
            except Exception as e:  # shown to the user
                self.events.put(("error", e))

        threading.Thread(target=runner, daemon=True).start()

    def _poll(self):
        try:
            while True:
                ev = self.events.get_nowait()
                if ev[0] == "msg":
                    self.status.configure(text=ev[1])
                    continue
                self.busy = False
                for b in self.action_buttons:
                    b.state(["!disabled"])
                self.progress.stop()
                self.progress.pack_forget()
                if ev[0] == "done":
                    ev[1](ev[2])
                else:
                    self.status.configure(text="Error.")
                    messagebox.showerror(rules.APP_NAME, str(ev[1]), parent=self)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _without_ignored(self, items):
        return [i for i in items if i.key not in self.ignored.keys]

    # -------------------------------------------------- actions

    def start_scan(self):
        def done(items):
            items = self._without_ignored(items)
            self.scan_view.set_items(items)
            self.status.configure(text=f"Scan finished: {plural(len(items), 'possible leftover')}.")
        self.run_task(scanner.scan, done)

    def start_search(self):
        term = self.search_var.get().strip()
        if not term:
            return

        def done(result):
            items, installed = result
            items = self._without_ignored(items)
            self.search_view.set_items(items, preselect=("high", "medium"))
            self.search_warning.configure(text=(
                f"⚠ This still seems to be installed: {', '.join(installed[:5])}. Uninstall it first from "
                "Settings › Apps; matching results are marked as low confidence." if installed else ""))
            self.status.configure(text=f"Search finished: {plural(len(items), 'item')} related to \"{term}\".")
        self.run_task(lambda p: scanner.search(term, p), done)

    def _clean_warnings(self, items):
        msg = ""
        low = [i for i in items if i.confidence == "low"]
        if low:
            msg += (f"\n\n{len(low)} {'is' if len(low) == 1 else 'are'} LOW confidence: make sure they don't "
                    "belong to something you still use.")
        need_admin = [i for i in items if rules.requires_admin(i)]
        if need_admin and not is_admin():
            msg += (f"\n\n{len(need_admin)} require administrator rights and will fail. "
                    "Use \"Restart as administrator\" to include them.")
        return msg

    @staticmethod
    def _size_text(items):
        return human_size(sum(i.size for i in items)) if any(i.size for i in items) else "no files"

    def clean(self, view):
        items = view.checked_items()
        if not items:
            messagebox.showinfo(rules.APP_NAME, "Nothing is ticked.", parent=self)
            return
        msg = (f"{plural(len(items), 'item')} will be moved to the quarantine ({self._size_text(items)}).\n\n"
               "You can restore them from the \"Quarantine\" tab." + self._clean_warnings(items))
        if messagebox.askyesno(rules.APP_NAME, msg + "\n\nContinue?", parent=self):
            self._run_clean(view, items)

    def clean_all(self, view):
        visible = view.visible_ids()
        if not visible:
            messagebox.showinfo(rules.APP_NAME, "There are no results. Scan the PC or search for a program first.",
                                parent=self)
            return
        previous = set(view.checked)
        view.checked = set(visible)
        view.refresh()
        items = view.checked_items()

        def cancel():
            view.checked = previous
            view.refresh()
            self.status.configure(text="Cancelled: nothing was moved.")

        answer = messagebox.askyesnocancel(
            rules.APP_NAME,
            f"All {plural(len(items), 'item')} in the list ({self._size_text(items)}) have been ticked to be "
            f"moved to the quarantine.{self._clean_warnings(items)}\n\n"
            "Do you want to create a ZIP backup first?\n\n"
            "•  Yes: choose where to save it, then the items are moved.\n"
            "•  No: move them without an extra copy (they can still be restored from the quarantine).\n"
            "•  Cancel: do nothing.",
            icon="question", parent=self)
        if answer is None:
            cancel()
            return
        backup = None
        if answer:
            backup = self._ask_backup_path(items)
            if not backup:
                cancel()
                return
        self._run_clean(view, items, backup)

    def _ask_backup_path(self, items):
        os.makedirs(cleaner.BACKUP_DIR, exist_ok=True)
        while True:
            path = filedialog.asksaveasfilename(
                parent=self, title="Save backup", initialdir=cleaner.BACKUP_DIR,
                initialfile=cleaner.backup_name(len(items)), defaultextension=".zip",
                filetypes=[("ZIP archive", "*.zip")])
            if not path:
                try:
                    os.rmdir(cleaner.BACKUP_DIR)  # only if it was left empty
                except OSError:
                    pass
                return None
            path = os.path.normpath(path)
            inside = [i for i in items if i.kind == "folder"
                      and os.path.normcase(path).startswith(os.path.normcase(i.path) + os.sep)]
            if not inside:
                return path
            messagebox.showwarning(rules.APP_NAME, "Don't save the backup inside a folder that is about to be moved:\n"
                                   f"{inside[0].path}\n\nPick another location.", parent=self)

    def _run_clean(self, view, items, backup=None):
        def work(progress):
            skipped = []
            if backup:
                try:
                    skipped = cleaner.create_backup(items, backup, progress)
                except Exception:
                    if os.path.exists(backup):
                        os.remove(backup)
                    raise
            ok, errors = cleaner.clean(items, progress)
            return ok, errors, skipped

        def done(result):
            ok, errors, skipped = result
            view.remove(ok)
            self.refresh_quarantine()
            summary = f"{plural(len(ok), 'item')} moved to the quarantine."
            self.status.configure(text=summary)
            if backup:
                summary += f"\n\nBackup saved to:\n{backup}"
                if skipped:
                    summary += f"\n({plural(len(skipped), 'file')} in use could not be copied.)"
            if errors:
                self.show_errors(summary + f"\n\n{len(errors)} could not be moved:",
                                 [(i.display_path, e) for i, e in errors])
            elif backup:
                if messagebox.askyesno(rules.APP_NAME, summary + "\n\nOpen the backup folder?", parent=self):
                    subprocess.Popen(["explorer", "/select,", backup])
            else:
                messagebox.showinfo(rules.APP_NAME, "Done: " + summary, parent=self)
        self.run_task(work, done)

    def refresh_quarantine(self):
        self.qall = cleaner.list_quarantine()
        alive = {(sdir, rec["id"]) for sdir, rec in self.qall}
        self.qindex = {k: v for k, v in self.qindex.items() if k in alive}
        self.notebook.tab(2, text=f"  Quarantine ({len(self.qall)})  ")
        self._apply_qfilter()

    def _schedule_qfilter(self):
        if self._qfilter_job:
            self.after_cancel(self._qfilter_job)
        self._qfilter_job = self.after(300, self._apply_qfilter)

    def _clear_qsearch(self):
        self.qsearch_var.set("")
        self._apply_qfilter()

    def _apply_qfilter(self):
        self._qfilter_job = None
        query = self.qsearch_var.get()
        if query.strip() and qsearch.needs_indexing(self.qall, self.qindex):
            if self.busy:  # try again once the running task ends
                self._qfilter_job = self.after(500, self._apply_qfilter)
                return
            entries, index = list(self.qall), self.qindex

            def work(progress):
                progress("Indexing the quarantine contents…")
                return qsearch.search(entries, query, index)
            self.run_task(work, lambda results: self._show_quarantine(results, query))
            return
        self._show_quarantine(qsearch.search(self.qall, query, self.qindex), query)

    def _show_quarantine(self, results, query):
        if query != self.qsearch_var.get():  # the text changed while indexing
            self._apply_qfilter()
            return
        self.qtree.delete(*self.qtree.get_children())
        self.qentries, self.qreasons = {}, {}
        best = results[0][1] if results and results[0][1] > 0 else None
        for n, ((sdir, rec), score, why) in enumerate(results):
            iid = str(n)
            self.qentries[iid] = (sdir, rec)
            self.qreasons[iid] = why
            path = f"{rec['path']}  →  {rec['value']}" if rec["kind"] == "regvalue" else rec["path"]
            self.qtree.insert("", "end", iid=iid, tags=("best",) if best and score == best else (), values=(
                rec["date"], KIND_LABEL.get(rec["kind"], rec["kind"]), path, "; ".join(dict.fromkeys(why)),
                human_size(rec.get("size", 0))))
        self.qdetail.configure(text="")
        if query.strip() and not qsearch.parse_query(query):
            self.status.configure(text="Nothing specific to search for: include the program name, a file name "
                                       "or the full error message.")
        elif query.strip():
            self.status.configure(text=f"{len(results)} of {plural(len(self.qall), 'quarantined item')} match "
                                       "your search." if results else "Nothing in the quarantine matches your search.")

    def _on_qselect(self, _event):
        sel = self.qtree.selection()
        if not sel or sel[0] not in self.qentries:
            return
        _sdir, rec = self.qentries[sel[0]]
        why = list(dict.fromkeys(self.qreasons.get(sel[0], [])))
        text = f"{rec['path']}" + (f"  →  {rec['value']}" if rec["kind"] == "regvalue" else "")
        text += f"\nQuarantined on {rec['date']}. {rec.get('reason', '')}"
        if why:
            text += "\nMatches: " + "; ".join(why)
        self.qdetail.configure(text=text)

    def _selected_quarantine(self):
        return [self.qentries[i] for i in self.qtree.selection() if i in self.qentries]

    def restore_selected(self):
        entries = self._selected_quarantine()
        if not entries:
            messagebox.showinfo(rules.APP_NAME, "Select the items you want to restore.", parent=self)
            return
        if not messagebox.askyesno(rules.APP_NAME, f"Put {plural(len(entries), 'item')} back in their original "
                                   "location?", parent=self):
            return
        self.run_task(lambda p: cleaner.restore(entries, p), lambda r: self._after_quarantine_op("restored", r))

    def purge_selected(self):
        entries = self._selected_quarantine()
        if not entries:
            messagebox.showinfo(rules.APP_NAME, "Select the items you want to delete.", parent=self)
            return
        if not messagebox.askyesno(rules.APP_NAME, f"{plural(len(entries), 'item')} and their backups will be "
                                   "deleted PERMANENTLY. This cannot be undone.\n\nContinue?",
                                   icon="warning", parent=self):
            return
        self.run_task(lambda p: cleaner.purge(entries, p), lambda r: self._after_quarantine_op("deleted", r))

    def _after_quarantine_op(self, verb, result):
        ok, errors = result
        self.refresh_quarantine()
        self.status.configure(text=f"{plural(len(ok), 'item')} {verb}.")
        if errors:
            self.show_errors(f"{plural(len(ok), 'item')} {verb}. {len(errors)} failed:",
                             [(r["path"], e) for r, e in errors])

    def show_errors(self, title, rows):
        text = "\n".join(f"• {p}\n    {e}" for p, e in rows[:15])
        if len(rows) > 15:
            text += f"\n… and {len(rows) - 15} more."
        messagebox.showwarning(rules.APP_NAME, f"{title}\n\n{text}", parent=self)

    def open_quarantine_dir(self):
        os.makedirs(rules.QUARANTINE_DIR, exist_ok=True)
        os.startfile(rules.QUARANTINE_DIR)

    def update_summary(self):
        if not hasattr(self, "summary"):
            return
        idx = self.notebook.index("current")
        view = {0: self.scan_view, 1: self.search_view}.get(idx)
        if view is None:
            self.summary.configure(text="")
            return
        total, checked, size = view.stats()
        self.summary.configure(text=f"{total} found · {checked} ticked · {human_size(size)}")

    def relaunch_as_admin(self):
        exe = sys.executable
        if getattr(sys, "frozen", False):  # compiled build (.exe)
            params, cwd = "", os.path.dirname(exe)
        else:
            pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
            if os.path.exists(pyw):
                exe = pyw
            script = os.path.abspath(__file__)
            params, cwd = f'"{script}"', os.path.dirname(script)
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, cwd, 1)
        if r > 32:
            self.destroy()


def resource(name):
    """Path to a bundled resource, both when running the .py and the compiled .exe."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    App().mainloop()


if __name__ == "__main__":
    main()
