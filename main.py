"""
Entry point for the Network Packet Sniffer & IDS desktop application.
"""

import sys
import os
import traceback


def _project_root() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _ensure_on_path() -> None:
    root = _project_root()
    if root not in sys.path:
        sys.path.insert(0, root)


def _single_instance_guard():
    """Prevent multiple app instances (avoids confusing relaunch behaviour)."""
    if not getattr(sys, "frozen", False):
        return
    lock_dir = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") \
        or os.path.expanduser("~")
    lock_file = os.path.join(lock_dir, "NetworkSnifferIDS", "app.lock")
    try:
        os.makedirs(os.path.dirname(lock_file), exist_ok=True)
        fd = os.open(lock_file, os.O_CREAT | os.O_RDWR)
        try:
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            os.close(fd)
            try:
                import tkinter as tk
                from tkinter import messagebox
                _root = tk.Tk()
                _root.withdraw()
                messagebox.showinfo(
                    "Already Running",
                    "The Network Packet Sniffer is already running.\n\n"
                    "Check the taskbar / system tray for the existing window.",
                )
                _root.destroy()
            except Exception:
                pass
            sys.exit(0)
        global _LOCK_FD
        _LOCK_FD = fd
    except Exception:
        pass


def main() -> int:
    _ensure_on_path()
    _single_instance_guard()
    try:
        import tkinter as tk
    except Exception as e:
        sys.stderr.write(
            "Tkinter is required but could not be imported: {}\n".format(e))
        return 2
    try:
        from app.gui.main_window import MainWindow
        from app.logging.logger import setup_logging, log_application, log_error
        from app.utils.paths import ensure_all_directories
    except Exception as e:
        traceback.print_exc()
        sys.stderr.write("Failed to import application modules: {}\n".format(e))
        return 3

    ensure_all_directories()
    setup_logging()

    try:
        root = tk.Tk()
    except Exception as e:
        sys.stderr.write("Tk root creation failed: {}\n".format(e))
        return 4

    try:
        app = MainWindow(root)
    except Exception as e:
        log_error("MainWindow construction failed.", e)
        traceback.print_exc()
        try:
            messagebox.showerror("Startup Error",
                                 f"Fatal error while starting the application:\n{e}")
        except Exception:
            sys.stderr.write("Startup error: {}\n".format(e))
        return 5

    try:
        app.run()
        return 0
    except Exception as e:
        log_error("Fatal exception in mainloop.", e)
        traceback.print_exc()
        return 6


if __name__ == "__main__":
    sys.exit(main())
