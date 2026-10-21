"""LimpiaResiduos: interfaz gráfica para encontrar y eliminar restos de programas desinstalados."""
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
import rules  # noqa: E402
import scanner  # noqa: E402
from winutil import is_admin  # noqa: E402

CONF_LABEL = {"alta": "Alta", "media": "Media", "baja": "Baja"}
CONF_ORDER = {"alta": 0, "media": 1, "baja": 2}
KIND_LABEL = {"folder": "Carpeta", "file": "Archivo", "regkey": "Clave", "regvalue": "Valor"}
CHECKED, UNCHECKED = "☑", "☐"
IGNORE_FILE = os.path.join(rules.DATA_DIR, "ignorados.json")


def human_size(n, truncated=False):
    if not n:
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            text = f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            return ("≥ " if truncated else "") + text
        n /= 1024


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
    """Tabla de resultados con casillas, filtro por confianza y menú contextual."""

    COLUMNS = (("sel", "", 34), ("conf", "Confianza", 80), ("kind", "Tipo", 70), ("cat", "Categoría", 230),
               ("path", "Ubicación", 520), ("size", "Tamaño", 80))

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.items = {}
        self.checked = set()
        self.filter = "todos"

        self.tree = ttk.Treeview(self, columns=[c[0] for c in self.COLUMNS], show="headings", selectmode="extended")
        for col, title, width in self.COLUMNS:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, stretch=col in ("path", "cat"),
                             anchor="center" if col in ("sel", "conf", "kind") else "w")
        self.tree.column("size", anchor="e")
        self.tree.tag_configure("alta", foreground="#1a7f37")
        self.tree.tag_configure("media", foreground="#9a6700")
        self.tree.tag_configure("baja", foreground="#6e7781")
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
        self.menu.add_command(label="Marcar / desmarcar", command=self._toggle_selection)
        self.menu.add_command(label="Abrir ubicación", command=self._open_location)
        self.menu.add_command(label="Copiar ruta", command=self._copy_path)
        self.menu.add_separator()
        self.menu.add_command(label="No es un residuo (ignorar siempre)", command=self._ignore)

    # -------------------------------------------------- datos

    def set_items(self, items, preselect=("alta",)):
        self.items = {}
        for i, it in enumerate(sorted(items, key=lambda x: (CONF_ORDER[x.confidence], x.category, x.path.lower()))):
            self.items[str(i)] = it
        self.checked = {iid for iid, it in self.items.items() if it.confidence in preselect}
        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for iid, it in self.items.items():
            if self.filter != "todos" and it.confidence != self.filter:
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

    # -------------------------------------------------- eventos

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
            admin = " · Requiere administrador." if rules.requires_admin(it) else ""
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
            messagebox.showinfo(rules.APP_NAME, "Ruta del registro copiada al portapapeles.\n"
                                "Pégala en la barra de direcciones del Editor del Registro (regedit).", parent=self)

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
        self.title(f"{rules.APP_NAME} {rules.APP_VERSION} — Limpiador de restos de programas")
        self.geometry("1180x700")
        self.minsize(820, 480)
        try:
            self.iconbitmap(resource("icono.ico"))
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

    # -------------------------------------------------- construcción

    def _build_header(self):
        top = ttk.Frame(self, padding=(12, 10, 12, 0))
        top.pack(fill="x")
        ttk.Label(top, text=rules.APP_NAME, style="Title.TLabel").pack(side="left")
        ttk.Label(top, text="  Encuentra y elimina lo que dejan los programas al desinstalarse. "
                            "Todo pasa por la cuarentena y se puede restaurar.").pack(side="left")
        if is_admin():
            ttk.Label(top, text="✔ Administrador", foreground="#1a7f37").pack(side="right")
        else:
            ttk.Button(top, text="Reiniciar como administrador", command=self.relaunch_as_admin).pack(side="right")
            ttk.Label(top, text="Sin permisos de administrador  ", style="Warn.TLabel").pack(side="right")

    def _marking_bar(self, parent, view):
        bar = ttk.Frame(parent)
        ttk.Label(bar, text="Marcar:").pack(side="left")
        ttk.Button(bar, text="Confianza alta", command=lambda: view.mark(lambda i: i.confidence == "alta")
                   ).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Todo lo visible", command=lambda: view.mark(lambda i: True)).pack(side="left", padx=4)
        ttk.Button(bar, text="Nada", command=lambda: view.mark(lambda i: False)).pack(side="left")
        ttk.Label(bar, text="   Mostrar:").pack(side="left")
        combo = ttk.Combobox(bar, state="readonly", width=12, values=["Todos", "Alta", "Media", "Baja"])
        combo.current(0)
        combo.bind("<<ComboboxSelected>>", lambda e: view.set_filter(combo.get().lower()))
        combo.pack(side="left", padx=(6, 0))
        btn = ttk.Button(bar, text="Mover a cuarentena", command=lambda: self.clean(view))
        btn.pack(side="right")
        self.action_buttons.append(btn)
        btn = ttk.Button(bar, text="Marcar todo y mover a cuarentena…", command=lambda: self.clean_all(view))
        btn.pack(side="right", padx=6)
        self.action_buttons.append(btn)
        return bar

    def _build_scan_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  Escaneo completo  ")
        top = ttk.Frame(tab)
        top.pack(fill="x")
        btn = ttk.Button(top, text="Escanear el equipo", command=self.start_scan)
        btn.pack(side="left")
        self.action_buttons.append(btn)
        ttk.Label(top, text="  Busca carpetas, claves, accesos directos y entradas de inicio sin programa "
                            "asociado. Solo se marcan por defecto los de confianza alta.").pack(side="left")
        self.scan_view = ResultsView(tab, self)
        self.scan_view.pack(fill="both", expand=True, pady=8)
        self._marking_bar(tab, self.scan_view).pack(fill="x")

    def _build_search_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  Buscar por nombre  ")
        top = ttk.Frame(tab)
        top.pack(fill="x")
        ttk.Label(top, text="Nombre del programa desinstalado:").pack(side="left")
        self.search_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.search_var, width=36)
        entry.pack(side="left", padx=6)
        entry.bind("<Return>", lambda e: self.start_search())
        btn = ttk.Button(top, text="Buscar restos", command=self.start_search)
        btn.pack(side="left")
        self.action_buttons.append(btn)
        self.search_warning = ttk.Label(tab, text="", style="Warn.TLabel", wraplength=1000)
        self.search_warning.pack(fill="x", pady=(6, 0))
        self.search_view = ResultsView(tab, self)
        self.search_view.pack(fill="both", expand=True, pady=8)
        self._marking_bar(tab, self.search_view).pack(fill="x")

    def _build_quarantine_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="  Cuarentena  ")
        ttk.Label(tab, text="Elementos retirados. Puedes devolverlos a su sitio o eliminarlos para siempre "
                            "cuando compruebes que todo funciona bien.").pack(fill="x")
        frame = ttk.Frame(tab)
        frame.pack(fill="both", expand=True, pady=8)
        cols = (("date", "Fecha", 140), ("kind", "Tipo", 70), ("path", "Ubicación original", 680),
                ("size", "Tamaño", 80))
        self.qtree = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings", selectmode="extended")
        for col, title, width in cols:
            self.qtree.heading(col, text=title)
            self.qtree.column(col, width=width, stretch=col == "path", anchor="e" if col == "size" else "w")
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.qtree.yview)
        self.qtree.configure(yscrollcommand=ys.set)
        self.qtree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        ttk.Button(bar, text="Actualizar", command=self.refresh_quarantine).pack(side="left")
        ttk.Button(bar, text="Abrir carpeta de cuarentena", command=self.open_quarantine_dir).pack(side="left", padx=6)
        for text, cmd in (("Eliminar definitivamente", self.purge_selected), ("Restaurar", self.restore_selected)):
            btn = ttk.Button(bar, text=text, command=cmd)
            btn.pack(side="right", padx=(6, 0))
            self.action_buttons.append(btn)
        self.qentries = {}

    def _build_status(self):
        bar = ttk.Frame(self, padding=(12, 6))
        bar.pack(fill="x")
        self.status = ttk.Label(bar, text="Listo.")
        self.status.pack(side="left", fill="x", expand=True)
        self.summary = ttk.Label(bar, text="")
        self.summary.pack(side="right")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)

    # -------------------------------------------------- tareas en segundo plano

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
            except Exception as e:  # se muestra al usuario
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

    # -------------------------------------------------- acciones

    def start_scan(self):
        def done(items):
            items = self._without_ignored(items)
            self.scan_view.set_items(items)
            self.status.configure(text=f"Escaneo terminado: {len(items)} posibles residuos.")
        self.run_task(scanner.scan, done)

    def start_search(self):
        term = self.search_var.get().strip()
        if not term:
            return

        def done(result):
            items, installed = result
            items = self._without_ignored(items)
            self.search_view.set_items(items, preselect=("alta", "media"))
            self.search_warning.configure(text=(
                f"⚠ Parece que sigue instalado: {', '.join(installed[:5])}. Desinstálalo primero desde "
                "Configuración › Aplicaciones; los resultados se marcan con confianza baja." if installed else ""))
            self.status.configure(text=f"Búsqueda terminada: {len(items)} elementos relacionados con «{term}».")
        self.run_task(lambda p: scanner.search(term, p), done)

    def _clean_warnings(self, items):
        msg = ""
        low = [i for i in items if i.confidence == "baja"]
        if low:
            msg += f"\n\n{len(low)} son de confianza BAJA: revisa que no pertenezcan a algo que sigues usando."
        need_admin = [i for i in items if rules.requires_admin(i)]
        if need_admin and not is_admin():
            msg += (f"\n\n{len(need_admin)} requieren permisos de administrador y fallarán. "
                    "Usa «Reiniciar como administrador» para incluirlos.")
        return msg

    @staticmethod
    def _size_text(items):
        return human_size(sum(i.size for i in items)) if any(i.size for i in items) else "sin archivos"

    def clean(self, view):
        items = view.checked_items()
        if not items:
            messagebox.showinfo(rules.APP_NAME, "No hay elementos marcados.", parent=self)
            return
        msg = (f"Se moverán {len(items)} elemento(s) a la cuarentena ({self._size_text(items)}).\n\n"
               "Podrás restaurarlos desde la pestaña «Cuarentena»." + self._clean_warnings(items))
        if messagebox.askyesno(rules.APP_NAME, msg + "\n\n¿Continuar?", parent=self):
            self._run_clean(view, items)

    def clean_all(self, view):
        visible = view.visible_ids()
        if not visible:
            messagebox.showinfo(rules.APP_NAME, "No hay resultados. Primero escanea el equipo o busca un programa.",
                                parent=self)
            return
        previous = set(view.checked)
        view.checked = set(visible)
        view.refresh()
        items = view.checked_items()

        def cancel():
            view.checked = previous
            view.refresh()
            self.status.configure(text="Cancelado: no se ha movido nada.")

        answer = messagebox.askyesnocancel(
            rules.APP_NAME,
            f"Se han marcado los {len(items)} elementos de la lista ({self._size_text(items)}) para moverlos "
            f"a la cuarentena.{self._clean_warnings(items)}\n\n"
            "¿Quieres crear antes una copia de seguridad en un archivo ZIP?\n\n"
            "•  Sí: eliges dónde guardarla y después se mueven.\n"
            "•  No: se mueven sin copia extra (desde la cuarentena se pueden restaurar igualmente).\n"
            "•  Cancelar: no se hace nada.",
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
                parent=self, title="Guardar copia de seguridad", initialdir=cleaner.BACKUP_DIR,
                initialfile=cleaner.backup_name(len(items)), defaultextension=".zip",
                filetypes=[("Archivo ZIP", "*.zip")])
            if not path:
                try:
                    os.rmdir(cleaner.BACKUP_DIR)  # solo si quedó vacía
                except OSError:
                    pass
                return None
            path = os.path.normpath(path)
            inside = [i for i in items if i.kind == "folder"
                      and os.path.normcase(path).startswith(os.path.normcase(i.path) + os.sep)]
            if not inside:
                return path
            messagebox.showwarning(rules.APP_NAME, "No guardes la copia dentro de una carpeta que se va a mover:\n"
                                   f"{inside[0].path}\n\nElige otra ubicación.", parent=self)

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
            self.status.configure(text=f"{len(ok)} elemento(s) movidos a la cuarentena.")
            summary = f"{len(ok)} elemento(s) movidos a la cuarentena."
            if backup:
                summary += f"\n\nCopia de seguridad guardada en:\n{backup}"
                if skipped:
                    summary += f"\n({len(skipped)} archivo(s) en uso no se pudieron copiar.)"
            if errors:
                self.show_errors(summary + f"\n\n{len(errors)} no se pudieron mover:",
                                 [(i.display_path, e) for i, e in errors])
            elif backup:
                if messagebox.askyesno(rules.APP_NAME, summary + "\n\n¿Abrir la carpeta de la copia?", parent=self):
                    subprocess.Popen(["explorer", "/select,", backup])
            else:
                messagebox.showinfo(rules.APP_NAME, "Listo: " + summary, parent=self)
        self.run_task(work, done)

    def refresh_quarantine(self):
        self.qtree.delete(*self.qtree.get_children())
        self.qentries = {}
        for n, (sdir, rec) in enumerate(cleaner.list_quarantine()):
            iid = str(n)
            self.qentries[iid] = (sdir, rec)
            path = f"{rec['path']}  →  {rec['value']}" if rec["kind"] == "regvalue" else rec["path"]
            self.qtree.insert("", "end", iid=iid, values=(rec["date"], KIND_LABEL.get(rec["kind"], rec["kind"]),
                                                          path, human_size(rec.get("size", 0))))
        self.notebook.tab(2, text=f"  Cuarentena ({len(self.qentries)})  ")

    def _selected_quarantine(self):
        return [self.qentries[i] for i in self.qtree.selection() if i in self.qentries]

    def restore_selected(self):
        entries = self._selected_quarantine()
        if not entries:
            messagebox.showinfo(rules.APP_NAME, "Selecciona los elementos que quieres restaurar.", parent=self)
            return
        if not messagebox.askyesno(rules.APP_NAME, f"¿Devolver {len(entries)} elemento(s) a su ubicación original?",
                                   parent=self):
            return
        self.run_task(lambda p: cleaner.restore(entries, p), lambda r: self._after_quarantine_op("restaurados", r))

    def purge_selected(self):
        entries = self._selected_quarantine()
        if not entries:
            messagebox.showinfo(rules.APP_NAME, "Selecciona los elementos que quieres eliminar.", parent=self)
            return
        if not messagebox.askyesno(rules.APP_NAME, f"Se eliminarán DEFINITIVAMENTE {len(entries)} elemento(s) "
                                   "y sus copias de seguridad. Esto no se puede deshacer.\n\n¿Continuar?",
                                   icon="warning", parent=self):
            return
        self.run_task(lambda p: cleaner.purge(entries, p), lambda r: self._after_quarantine_op("eliminados", r))

    def _after_quarantine_op(self, verb, result):
        ok, errors = result
        self.refresh_quarantine()
        self.status.configure(text=f"{len(ok)} elemento(s) {verb}.")
        if errors:
            self.show_errors(f"{len(ok)} {verb}. {len(errors)} con error:", [(r["path"], e) for r, e in errors])

    def show_errors(self, title, rows):
        text = "\n".join(f"• {p}\n    {e}" for p, e in rows[:15])
        if len(rows) > 15:
            text += f"\n… y {len(rows) - 15} más."
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
        self.summary.configure(text=f"{total} encontrados · {checked} marcados · {human_size(size)}")

    def relaunch_as_admin(self):
        exe = sys.executable
        if getattr(sys, "frozen", False):  # versión compilada (.exe)
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
    """Ruta a un recurso, tanto ejecutando el .py como desde el .exe compilado."""
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
