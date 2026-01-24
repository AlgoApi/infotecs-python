from enum import IntEnum
import sys
import traceback
import threading
import asyncio
from datetime import datetime as dt
from typing import TextIO, Optional, Tuple


class LogLevel(IntEnum):
    debug = 1
    info = 2
    warn = 3
    err = 4
    fatal = 6
    success = 5

    def __str__(self):
        labels = {
            LogLevel.debug: "[DEBUG]",
            LogLevel.info: "[INFO]",
            LogLevel.warn: "[WARN]",
            LogLevel.err: "[[ERROR]]",
            LogLevel.fatal: "[[[FATAL]]]",
            LogLevel.success: "::: Success :::"
        }
        return labels[self]


class Logger:
    def __init__(self, name:str, out: TextIO = sys.stdout, loglevel: LogLevel = LogLevel.success, verbose: bool = False, quiet:bool = True) -> None:
        self.file = False
        if isinstance(out, str):
            try:
                self.stdout = open(out, "a", encoding="utf-8", errors="replace")
            except FileNotFoundError:
                # create new
                temp = open(out, "w", encoding="utf-8", errors="replace")
                temp.close()
                del temp
                self.stdout = open(out, "a", encoding="utf-8", errors="replace")
            self.file = True
        else:
            self.stdout = out
        self.loglevel = loglevel
        self.verbose = verbose
        self.name = name
        self.quiet = quiet

    def close(self):
        if self.file:
            # notice for user
            print("result written on file")
            self.stdout.close()
    
    def set_level(self, level:str):
        match level:
            case "debug":
                self.loglevel = LogLevel.debug
            case "info":
                self.loglevel = LogLevel.info
            case "warn":
                self.loglevel = LogLevel.warn
            case "err":
                self.loglevel = LogLevel.err
            case "fatal":
                self.loglevel = LogLevel.fatal
            case "success":
                self.loglevel = LogLevel.success

    def _now(self) -> str:
        return dt.now().strftime("%d.%m.%Y %H:%M:%S")

    def log(self, message: str, status: LogLevel) -> None:
        if status >= self.loglevel:
            if not self.quiet:
                self.stdout.write(f"{self.name} {self._now()} - {status} - '{message}'\n")
            else:
                self.stdout.write(f"{message}\n")
            self.stdout.flush()

    def _format_exc_summary(self, exc_type, exc_value, exc_tb) -> Tuple[str, str]:
        full_tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))

        extracted = traceback.extract_tb(exc_tb)
        if extracted:
            last = extracted[-1]
            short = f"{last.filename}:{last.lineno} in {last.name}: {exc_type.__name__}: {exc_value}"
        else:
            short = f"{exc_type.__name__}: {exc_value}"

        return short, full_tb

    def log_exception(self, exc_type, exc_value, exc_tb, status: LogLevel = LogLevel.err) -> None:
        short, full_tb = self._format_exc_summary(exc_type, exc_value, exc_tb)
        header = f"{self._now()} {__name__} - {status} - Uncaught exception: {short}"
        self.stdout.write(header + "\n")
        if self.verbose:
            self.stdout.write(full_tb)
        self.stdout.flush()


    def sys_hook(self) -> None:
        def hook(exc_type, exc_value, exc_tb):
            try:
                self.log_exception(exc_type, exc_value, exc_tb, status=LogLevel.fatal)
            except Exception:
                self.log("Uncaught exception while logging", LogLevel.warn)
                traceback.print_exception(exc_type, exc_value, exc_tb, file=self.stdout)
                self.stdout.flush()

        sys.excepthook = hook

    def threading_hook(self) -> None:
        def thread_hook(args):
            try:
                self.log_exception(args.exc_type, args.exc_value, args.exc_traceback, status=LogLevel.fatal)
            except Exception:
                traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback, file=self.stdout)
                self.stdout.flush()

        threading.excepthook = thread_hook

    def asyncio_handler(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        if loop is None:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                self.log("Loop not found, cannot log", LogLevel.warn)
                return

        def handle(loop, context):
            exc = context.get("exception")
            if exc is not None:
                self.log_exception(type(exc), exc, exc.__traceback__, status=LogLevel.fatal)
            else:
                msg = context.get("message", str(context))
                self.log(f"Asyncio error: {msg}", LogLevel.err)

        loop.set_exception_handler(handle)

    def init(self) -> None:
        self.sys_hook()
        self.threading_hook()
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                self.asyncio_handler(loop)
        except Exception:
            pass
