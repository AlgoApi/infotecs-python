import gc
import re
import subprocess
from aiohttp import ClientConnectorCertificateError, ClientConnectorSSLError, ClientError, ClientOSError, ClientPayloadError, ClientProxyConnectionError, ClientRequest, ClientResponseError, ClientSession, ClientTimeout, DigestAuthMiddleware, InvalidURL, NonHttpUrlClientError, ServerConnectionError, ServerDisconnectedError, ServerTimeoutError, TCPConnector, TraceConfig, TraceConnectionCreateStartParams, TraceDnsResolveHostStartParams, TraceRequestEndParams, TraceRequestExceptionParams, TraceRequestHeadersSentParams, TraceRequestRedirectParams, TraceRequestStartParams
import asyncio
from s21_logger import Logger, LogLevel
import time
import argparse
from dataclasses import dataclass, field
from collections import defaultdict
from getpass import getpass
from pathlib import Path
import os
import platform
import json
import itertools
from typing import Optional, Callable, Dict, List, Any
from aiohttp import TraceConfig, ClientRequest, ClientResponse, ClientSession

MAX_WORKERS_LIMIT = 100

@dataclass
class RequestStats:
    total: int = 0
    errors: int = 0
    by_status: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    durations: List[float] = field(default_factory=list)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def add(self, status: int, duration: float):
        async with self.lock:
            self.total += 1
            self.by_status[status] += 1
            self.durations.append(duration)

    def avg_time(self) -> float:
        return sum(self.durations) / len(self.durations) if self.durations else 0.0
    def get_min(self) -> float:
        return min(self.durations) if self.durations else 0.0
    def get_max(self) -> float:
        return max(self.durations) if self.durations else 0.0
    
def DebugTrace(logger: Logger, stats: RequestStats):
    stats_var = stats
    trace = TraceConfig()

    async def start(session: ClientSession, context, params: TraceRequestStartParams):
        context.start = time.perf_counter()
        context.host = params.url
        context.ip = None
        context.stats = stats_var
        logger.log(f"REQUEST {params.method} {params.url}", LogLevel.info)

    async def dns_start(session: ClientSession, context, params: TraceDnsResolveHostStartParams):
        logger.log(f"DNS resolve {context.host}", LogLevel.debug)

    async def connect_start(session: ClientSession, context, params: TraceConnectionCreateStartParams):
        logger.log(f"TCP connect {context.host}", LogLevel.debug)

    async def headers_sent(session: ClientSession, context, params: TraceRequestHeadersSentParams):
        logger.log(f"HEADERS sent {context.host}", LogLevel.debug)

    async def on_redirect(session: ClientSession, context, params: TraceRequestRedirectParams):
        target_url = str(params.url)
        logger.log(
            f"REDIRECT: {context.host} -> {target_url}",
            LogLevel.info
        )
        context.host = target_url

    async def end(session: ClientSession, context, params: TraceRequestEndParams):
        dur = time.perf_counter() - context.start
        await context.stats.add(status=params.response.status, duration=dur)
        logger.log(
            f"RESPONSE {params.response.status} for {context.host} {dur:.3f}s",
            LogLevel.info
        )

    async def exception(session: ClientSession, context, params: TraceRequestExceptionParams):
        logger.log(
            f"EXCEPTION {params.method} {context.host} {repr(params.headers)}: {repr(params.exception)}",
            LogLevel.debug
        )

    trace.on_request_start.append(start)
    trace.on_dns_resolvehost_start.append(dns_start)
    trace.on_connection_create_start.append(connect_start)
    trace.on_request_headers_sent.append(headers_sent)
    trace.on_request_redirect.append(on_redirect)
    trace.on_request_end.append(end)
    trace.on_request_exception.append(exception)
    
    return trace

def headers_middleware(default_headers: dict[str, str]):
    async def middleware(request: ClientRequest, handler):
        for k, v in default_headers.items():
            request.headers.setdefault(k, v)
        return await handler(request)
    return middleware

def cookies_middleware(cookies: dict[str, str]):
    async def middleware(request, handler):
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())

        if cookie_header:
            request.headers.setdefault("Cookie", cookie_header)

        return await handler(request)

    return middleware

def bearer_auth_middleware(token_provider):
    async def middleware(request: ClientRequest, handler):
        token = await token_provider()
        request.headers["Authorization"] = f"Bearer {token}"
        return await handler(request)
    return middleware

def _wipe_data(data: bytearray) -> None:
    if data:
        for i in range(len(data)):
            data[i] = 0

def pass_auth_middleware(pass_path: Path|None) -> DigestAuthMiddleware | None:
    if pass_path is not None and pass_path.exists():
        password_ba = None
        def secure_read():
            with open(pass_path, "rb") as f:
                password_ba = bytearray(f.read().strip())
                middleware = DigestAuthMiddleware(login="user", password=password_ba.decode("utf-8"))
                _wipe_data(password_ba)
                gc.collect()
            return middleware

        if platform.system() != "Windows":
            st = os.stat(pass_path)
            mode = oct(st.st_mode & 0o777)
            if mode == "0o600":
                return secure_read()
            else:
                raise RuntimeError("The passwords containing the file are insecure. Someone else has access to the file!")
        else:
            whoami = subprocess.check_output(["whoami"], text=True).strip().lower()
            icacls = subprocess.check_output(["icacls", pass_path], text=True)
            usernames = re.findall(r"(?:(?<=\s)|(?<=^))(.+?):\(", icacls)
            usernames = [e.strip().lower() for e in usernames]
            veto = {whoami, "system"}
            for entity in usernames:
                if entity not in veto:
                    raise RuntimeError("The passwords containing the file are insecure. Someone else has access to the file!")
            return secure_read()
    else:
        middleware = DigestAuthMiddleware(login="user", password=getpass("Digest password: "))
        gc.collect()
        return middleware
    
async def get_action(session: ClientSession, url: str, action: str, timeout: ClientTimeout, payload: dict|None):
    match action:
        case "get":
            action_func = session.get
        case "post":
            action_func = session.post
        case "put":
            action_func = session.put
        case "patch":
            action_func = session.patch
        case "delete":
            action_func = session.delete
        case "options":
            action_func = session.options
        case _:
            action_func = session.get

    return action_func
    
async def fetch_and_process(session: ClientSession, stats: RequestStats, url: str, logger: Logger, action: str, timeout: ClientTimeout, payload: dict|None, retryes:int=1):
    while retryes > 0:
        try:
            action_func = await get_action(session, url, action, timeout, payload)
            async with action_func(url, allow_redirects=True, timeout=timeout, json=payload) as resp:
                await resp.read()
        except (InvalidURL, NonHttpUrlClientError) as e:
            logger.log(f"Invalid URL: {repr(e)} for {url}", LogLevel.err)
            stats.errors += 1
        except ClientConnectorSSLError as e:
            logger.log(f"SSL connection error: {repr(e)} for {url}", LogLevel.err)
            stats.errors += 1
        except ClientConnectorCertificateError as e:
            logger.log(f"Certificate error: {repr(e)} for {url}", LogLevel.err)
            stats.errors += 1
        except ClientProxyConnectionError as e:
            logger.log(f"Proxy connection error: {repr(e)} for {url}", LogLevel.err)
            stats.errors += 1
        except ClientOSError as e:
            logger.log(f"OS connection error: {repr(e)} for {url}", LogLevel.err)
            stats.errors += 1
        except ServerDisconnectedError as e:
            logger.log(f"The server terminated the connection: {repr(e)} for {url}", LogLevel.err)
            stats.errors += 1
        except ServerTimeoutError as e:
            logger.log(f"Server or socket timeout for {url}", LogLevel.err)
            stats.errors += 1
        except ClientResponseError as e:
            logger.log(f"HTTP error {e.status} for {url} for {url}", LogLevel.err)
            stats.errors += 1
        except ClientPayloadError as e:
            logger.log(f"Error reading the response body: {repr(e)} for {url}", LogLevel.err)
            stats.errors += 1
        except ServerConnectionError as e:
            logger.log(f"Connection error: {repr(e)} for {url}", LogLevel.err)
            stats.errors += 1
        except TimeoutError:
            logger.log(f"Timeout for {url}", LogLevel.err)
            stats.errors += 1
        except ClientError as e:
            logger.log(f"Unexpected error: {repr(e)} for {url}", LogLevel.err)
            stats.errors += 1
        except Exception as e:
            logger.log(f"CRITICAL UNKNOWN: {repr(e)}", LogLevel.fatal)
        finally:
            gc.collect()
        retryes -= 1

    success = 0
    failed = 0

    for k, v in stats.by_status.items():
        if (k // 400) == 1 or (k // 500) == 1:
            failed += v
        else:
            success += v

    logger.log("\n{"+f"\n    Host={url}\n    Success={success}\n    Failed={failed}\n    Errors={stats.errors}\n    Min={stats.get_min():.4f}\n    Max={stats.get_max():.4f}\n    Avg={stats.avg_time():.4f}\n" + "}", LogLevel.success)
    stats.by_status.clear()
    stats.errors = 0

def _produce_batches_sync(path: str|None, items: list[str]|None, batch_size: int, queue_put: Callable[[Optional[List[str]]], None], num_workers: int):
    if items is not None:
        it = iter(items)

        while True:
            batch = list(itertools.islice(it, batch_size))
            if not batch:
                break
            queue_put(batch)

        for _ in range(num_workers):
            queue_put(None)
    elif path is not None:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            while True:
                batch = list(itertools.islice(f, batch_size))
                if not batch:
                    break
                queue_put([ln.rstrip("\n") for ln in batch])
        for _ in range(num_workers):
            queue_put(None)

async def run_requester(
    path: str|None,
    manual_hosts: List[str]|None,
    middlewares: List[Callable],
    trace_config: TraceConfig,
    stats: RequestStats,
    logger: Logger,
    payload: dict|None,
    timeout_val: int = 3,
    action: str = "get",
    batch_size: int = 5,
    num_workers: int = 8,
    qsize: int = 20,
    retryes: int = 1
):
    if logger is None:
        logger = Logger()
    
    queue: asyncio.Queue = asyncio.Queue(maxsize=qsize)
    loop = asyncio.get_running_loop()

    def _queue_put(item):
        fut = asyncio.run_coroutine_threadsafe(queue.put(item), loop)
        fut.result()

    conn_limit = num_workers + 20 
    connector = TCPConnector(limit=conn_limit, force_close=True, enable_cleanup_closed=True)

    timeout = ClientTimeout(total=timeout_val, connect=None, sock_connect=timeout_val, sock_read=timeout_val)
    async with ClientSession(
            connector=connector,
            middlewares=middlewares,
            trace_configs=[trace_config], timeout=timeout) as session:
        async def worker(worker_id: int):
            logger.log(f"worker {worker_id} started", LogLevel.debug)
            processed = 0
            while True:
                batch = await queue.get()
                try:
                    if batch is None:
                        break
                    coros = list()
                    for url in batch:
                        url = url.strip()
                        if not url:
                            continue
                        coros.append(fetch_and_process(session, stats, url, logger, action, timeout, payload, retryes))
                        processed += 1
                    await asyncio.gather(*coros, return_exceptions=True)
                    
                finally:
                    queue.task_done()
            logger.log(f"worker {worker_id} finished, processed={processed}", LogLevel.debug)

        async with asyncio.TaskGroup() as tg:
            tg.create_task(asyncio.to_thread(_produce_batches_sync, path, manual_hosts, batch_size, _queue_put, num_workers))
            for i in range(num_workers):
                tg.create_task(worker(i))

    await queue.join()

def count_lines(filepath: str) -> int:
    with open(filepath, "rb") as f:
        num_lines = 0
        while chunk := f.read(1024 * 1024):
            num_lines += chunk.count(b'\n')
        return num_lines

def main() -> int:
    parser = argparse.ArgumentParser(description="CLI for testing server availability over the HTTP protocol")
    parser.add_argument("--host", "-H", type=str, help="The host that the requests will be made to. Can specified multiple addresses separated by commas without spaces. Only one of the keys can be specified at a time –F or -H")
    parser.add_argument("--timeout", "-t", type=int, default=3, help="Timeout sec, default 3 sec")
    parser.add_argument("--count", "-C", type=int, default=1, help="The сount of requests that will be sent to each host to calculate the average value, default 1")
    parser.add_argument("--file", "-F", type=str, help="A file with a list of addresses divided into lines. Only one of the keys can be specified at a time –F or -H")
    parser.add_argument("--output", "-O", type=str, help="The path to the file where you want to save the output. If not specified, the output is sent to the console")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable detailed exception output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Disable detailed log data, default true")
    parser.add_argument("--cli-pass", "-l", action="store_true", help="Enable hidden password entry via the console")
    parser.add_argument("--file-pass", "-i", type=str, help="Enable password reading from a file")
    parser.add_argument("--headers", "-d", type=str, help="Include headers json in the request")
    parser.add_argument("--cookies", "-k", type=str, help="Include cookies json in the request")
    parser.add_argument("--bearer", "-b", type=str, help="Include bearer json in the headers request. If bearer is installed --file-pass and --cli-pass will be ignored")
    parser.add_argument("--payload", "-p", type=str, help="Json payload")
    parser.add_argument("--action", "-a", type=str, help="Request metod, available: get, post, put, patch, delete, options")
    parser.add_argument("--log-level", "-g", type=str, help="Log level, available: debug, info, warn, err, fatal, success")

    args = parser.parse_args()

    if args.output:
        logger = Logger(out=args.output, verbose=args.verbose, name=__name__, quiet=(not args.quiet))
    else:
        logger = Logger(verbose=args.verbose, name=__name__, quiet=(not args.quiet))

    logger.set_level(args.log_level)
    logger.init()

    stats = RequestStats()

    trace_config = DebugTrace(logger=logger, stats=stats)

    middlewares = []
    manual_hosts = None

    if args.file and args.host:
        raise RuntimeError("Only one of the keys can be specified at a time –F or -H")
    if not args.file and not args.host:
        raise RuntimeError("One of the keys required –F or -H")
    
    if args.host:
        manual_hosts = args.host.split(",")

    if args.headers:
        try:
            middlewares.append(headers_middleware(json.loads(args.headers)))
        except json.JSONDecodeError as e:
            raise RuntimeError("headers invalid")
    if args.cookies:
        try:
            middlewares.append(cookies_middleware(json.loads(args.cookies)))
        except json.JSONDecodeError as e:
            raise RuntimeError("bearer invalid")
    if args.bearer:
        try:
            middlewares.append(bearer_auth_middleware(json.loads(args.bearer)))
        except json.JSONDecodeError as e:
            raise RuntimeError("bearer invalid")
    elif args.cli_pass:
        middlewares.append(pass_auth_middleware(None))
    elif args.file_pass:
        middlewares.append(pass_auth_middleware(args.file_pass))

    if args.action:
        match args.action:
            case "get":
                pass
            case "post":
                pass
            case "put":
                pass
            case "patch":
                pass
            case "delete":
                pass
            case "options":
                pass
            case _:
                raise RuntimeError("action invalid")
    else:
        args.action = "get"

    total_urls = 0
    batch_size = 5
    
    if args.host:
        manual_hosts = args.host.split(",")
        total_urls = len(manual_hosts)
    elif args.file:
        total_urls = count_lines(args.file)

    if total_urls > 0:
        calculated_workers = (total_urls // batch_size + 1)
    else:
        calculated_workers = 1

    if calculated_workers > MAX_WORKERS_LIMIT:
        logger.log(f"Calculated workers {calculated_workers} exceeds limit. Capped to {MAX_WORKERS_LIMIT}", LogLevel.warn)
        calculated_workers = MAX_WORKERS_LIMIT
    
    logger.log(f"Total URLs: {total_urls}. Workers: {calculated_workers}. Batch size: {batch_size}", LogLevel.info)
    
    asyncio.run(run_requester(
        args.file,
        manual_hosts,
        middlewares,
        trace_config,
        stats,
        logger,
        args.payload,
        action=args.action,
        retryes=args.count,
        num_workers=calculated_workers,
        batch_size=batch_size,
        qsize=int(calculated_workers//0.8)
    ))
    
    return 0
    


if __name__ == "__main__":
    main()
    print("bye bye")
    