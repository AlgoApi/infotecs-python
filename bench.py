import gc
import re
import subprocess
from aiohttp import ClientConnectorCertificateError, ClientConnectorDNSError, ClientConnectorError, ClientConnectorSSLError, ClientError, ClientOSError, ClientPayloadError, ClientProxyConnectionError, ClientRequest, ClientResponseError, ClientSession, ClientTimeout, DigestAuthMiddleware, InvalidURL, NonHttpUrlClientError, ServerConnectionError, ServerDisconnectedError, ServerTimeoutError, TCPConnector, TraceConfig, TraceConnectionCreateStartParams, TraceDnsResolveHostStartParams, TraceRequestEndParams, TraceRequestExceptionParams, TraceRequestHeadersSentParams, TraceRequestRedirectParams, TraceRequestStartParams
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
BATCH_SIZE = 50

@dataclass
class RequestStats:
    url: str = field(default_factory=str)
    # total registrated stats
    total: int = field(default_factory=int)
    errors: int = field(default_factory=int)
    # total registrated http code -> code: count
    by_status: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    durations: List[float] = field(default_factory=list)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    # is what to substitute if it is not specified in hosts
    is_https: bool = field(default_factory=bool)

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
    
class DebugTrace():
    def __init__(self, logger_obj: Logger) -> None:
        self.logger: Logger = logger_obj
        # stats for worker -> "worker {id} - {url}"
        self.star_vars: Dict[str, RequestStats] = defaultdict(RequestStats)
        self.trace = TraceConfig()

    def init_trace(self):
        logger = self.logger
        
        async def start(session: ClientSession, context, params: TraceRequestStartParams):
            context.start = time.perf_counter()
            context.origin_url = str(params.url)
            context.target = ""
            context.stats = context.trace_request_ctx.get('stats')
            logger.log(f"REQUEST {params.method} {params.url}", LogLevel.info)

        async def dns_start(session: ClientSession, context, params: TraceDnsResolveHostStartParams):
            logger.log(f"DNS resolve {context.origin_url}", LogLevel.debug)

        async def connect_start(session: ClientSession, context, params: TraceConnectionCreateStartParams):
            logger.log(f"TCP connect {context.origin_url}", LogLevel.debug)

        async def headers_sent(session: ClientSession, context, params: TraceRequestHeadersSentParams):
            logger.log(f"HEADERS sent {context.origin_url}", LogLevel.debug)

        async def on_redirect(session: ClientSession, context, params: TraceRequestRedirectParams):
            target_url = str(params.url)
            logger.log(
                f"REDIRECT: {context.origin_url} -> {target_url}",
                LogLevel.info
            )
            context.target = target_url

        async def end(session: ClientSession, context, params: TraceRequestEndParams):
            dur = time.perf_counter() - context.start
            await context.stats.add(status=params.response.status, duration=dur)
            logger.log(
                f"RESPONSE {params.response.status} for {context.origin_url} {dur:.3f}s",
                LogLevel.info
            )

        async def exception(session: ClientSession, context, params: TraceRequestExceptionParams):
            logger.log(
                f"EXCEPTION {params.method} {context.origin_url} {repr(params.headers)}: {repr(params.exception)}",
                LogLevel.debug
            )

        self.trace.on_request_start.append(start)
        self.trace.on_dns_resolvehost_start.append(dns_start)
        self.trace.on_connection_create_start.append(connect_start)
        self.trace.on_request_headers_sent.append(headers_sent)
        self.trace.on_request_redirect.append(on_redirect)
        self.trace.on_request_end.append(end)
        self.trace.on_request_exception.append(exception)
        
        return self.trace

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

def bearer_auth_middleware(token):
    async def middleware(request: ClientRequest, handler):
        request.headers["Authorization"] = f"Bearer {token}"
        return await handler(request)
    return middleware

# wipe func for bytearray data in security reasons
def _wipe_data(data: bytearray) -> None:
    if data:
        for i in range(len(data)):
            data[i] = 0

def pass_auth_middleware(login:str, pass_path: Path|None, logger:Logger, force:bool=True) -> DigestAuthMiddleware | None:
    if pass_path is not None and pass_path.exists():
        def secure_read():
            with open(pass_path, "rb") as f:
                password_ba = bytearray(f.read().strip())
                middleware = DigestAuthMiddleware(login="user", password=password_ba.decode("utf-8"))
                _wipe_data(password_ba)
                # reducing the password lifetime on my side as much as possible
                gc.collect()
            return middleware
        
        # require secure file access settings for security purposes.
        if platform.system() != "Windows":
            st = os.stat(pass_path)
            mode = oct(st.st_mode & 0o777)
            if force or mode == "0o600":
                return secure_read()
            else:
                raise RuntimeError("The passwords containing the file are insecure. Someone else has access to the file!")
        else:
            whoami = subprocess.check_output(["whoami"], text=True).strip().lower()
            icacls_out = subprocess.check_output(["icacls", pass_path], text=True)
            parts = re.findall(r"([^\r\n]+?):\(", icacls_out)

            usernames = []
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                last = part.rsplit(None, 1)[-1]
                usernames.append(last.strip().lower())

            veto = {whoami, "system"}
            for entity in usernames:
                if entity not in veto:
                    raise RuntimeError("The passwords containing the file are insecure. Someone else has access to the file!")
            return secure_read()
    else:
        if pass_path is not None:
            logger.log("file not exist, using cli-pass", LogLevel.info)
        middleware = DigestAuthMiddleware(login="user", password=getpass("Digest password: "))
        gc.collect()
        return middleware
    
async def get_action(session: ClientSession, url: str, action: str):
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
    
async def fetch_and_process(session: ClientSession, 
                            stats: RequestStats, 
                            url: str, logger: Logger, 
                            action: str, 
                            timeout: ClientTimeout, 
                            payload: dict|None, 
                            retryes:int=1, 
                            verbose:bool=False):
    stats.url = url
    while retryes > 0:
        try:
            action_func = await get_action(session, url, action)
            async with action_func(url, allow_redirects=True, timeout=timeout, json=payload, trace_request_ctx={'stats': stats}) as resp:
                try:
                    logger.log(f"response: {(await resp.read()).decode('utf-8')[:50]} for {url}", LogLevel.debug)
                except Exception:
                    logger.log(f"binary response for {url}", LogLevel.debug)
        except (InvalidURL, NonHttpUrlClientError) as e:
            # trying to fix a user error
            logger.log(f"Invalid URL: {repr(e) if verbose else ""} for {url}", LogLevel.err)
            if (("https://" if stats.is_https else "http://") not in url):
                logger.log(f"'{"https://" if stats.is_https else "http://"}' part is missing, auto fixed, +1 retry: {repr(e) if verbose else ""} for {url}", LogLevel.err)
                url = ("https://" if stats.is_https else "http://") + url
                retryes += 1
                stats.errors -= 1
            stats.errors += 1
        except ClientConnectorSSLError as e:
            logger.log(f"SSL connection error: {repr(e) if verbose else ""} for {url}", LogLevel.err)
            stats.errors += 1
        except ClientConnectorCertificateError as e:
            logger.log(f"Certificate error: {repr(e) if verbose else ""} for {url}", LogLevel.err)
            stats.errors += 1
        except ClientProxyConnectionError as e:
            logger.log(f"Proxy connection error: {repr(e) if verbose else ""} for {url}", LogLevel.err)
            stats.errors += 1
        except ClientConnectorDNSError as e:
            logger.log(f"Name or service not known: {repr(e) if verbose else "" if verbose else ""} for {url}", LogLevel.err)
            stats.errors += 1
        except (ClientConnectorError, ConnectionRefusedError) as e:
            logger.log(f"Connect call failed: {repr(e) if verbose else ""} for {url}", LogLevel.err)
            stats.errors += 1
        except ClientOSError as e:
            logger.log(f"OS connection error: {repr(e) if verbose else ""} for {url}", LogLevel.err)
            stats.errors += 1
        except ServerDisconnectedError as e:
            logger.log(f"The server terminated the connection: {repr(e) if verbose else ""} for {url}", LogLevel.err)
            stats.errors += 1
        except ServerTimeoutError as e:
            logger.log(f"Server or socket timeout for {url}", LogLevel.err)
            stats.errors += 1
        except ClientResponseError as e:
            logger.log(f"HTTP error {e.status} for {url}", LogLevel.err)
            stats.errors += 1
        except ClientPayloadError as e:
            logger.log(f"Error reading the response body: {repr(e) if verbose else ""} for {url}", LogLevel.err)
            stats.errors += 1
        except ServerConnectionError as e:
            logger.log(f"Connection error: {repr(e) if verbose else ""} for {url}", LogLevel.err)
            stats.errors += 1
        except TimeoutError:
            logger.log(f"Timeout for {url}", LogLevel.err)
            if timeout.total:
                await stats.add(504, timeout.total)
            else:
                logger.log(f"Timeout for {url}, but not known about timeout size", LogLevel.fatal)
            stats.errors += 1
        except ClientError as e:
            logger.log(f"Unexpected error: {repr(e) if verbose else ""} for {url}", LogLevel.err)
            stats.errors += 1
        except Exception as e:
            logger.log(f"CRITICAL UNKNOWN: {repr(e) if verbose else ""}", LogLevel.fatal)
            stats.errors += 1
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

    logger.log("\n{"+f"\n    Host={stats.url}\n    Success={success}\n    Failed={failed}\n    Errors={stats.errors}\n    Min={stats.get_min():.4f}\n    Max={stats.get_max():.4f}\n    Avg={stats.avg_time():.4f}\n" + "}", LogLevel.success)
    del stats

def _produce_batches_sync(path: str|None, items: list[str]|None, batch_size: int, queue_put: Callable[[Optional[List[str]]], None], num_workers: int):
    if items is not None:
        it = iter(items)

        while True:
            batch = list(itertools.islice(it, batch_size))
            if not batch:
                break
            queue_put(batch)
        # stop markers
        for _ in range(num_workers):
            queue_put(None)
    elif path is not None:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            while True:
                batch = list(itertools.islice(f, batch_size))
                if not batch:
                    break
                queue_put([ln.rstrip("\n") for ln in batch])
        # stop markers
        for _ in range(num_workers):
            queue_put(None)

async def run_requester(
    path: str|None,
    manual_hosts: List[str]|None,
    middlewares: List[Callable],
    trace_config: DebugTrace,
    logger: Logger,
    payload: dict|None,
    timeout_val: int = 3,
    action: str = "get",
    batch_size: int = 5,
    num_workers: int = 8,
    qsize: int = 20,
    retryes: int = 1,
    verbose:bool=False,
    target_https:bool=True
):
    if logger is None:
        logger = Logger()
    
    queue: asyncio.Queue = asyncio.Queue(maxsize=qsize)
    loop = asyncio.get_running_loop()

    # async run safely in the event loop from another sync thread 
    def _queue_put(item):
        fut = asyncio.run_coroutine_threadsafe(queue.put(item), loop)
        fut.result()

    conn_limit = num_workers + 20 
    connector = TCPConnector(limit=conn_limit, force_close=True)

    timeout = ClientTimeout(total=timeout_val, connect=None, sock_connect=timeout_val, sock_read=timeout_val)
    async with ClientSession(
            connector=connector,
            middlewares=middlewares,
            trace_configs=[trace_config.trace], timeout=timeout) as session:
        async def worker(worker_id: int):
            logger.log(f"worker {worker_id} started", LogLevel.debug)
            processed = 0
            while True:
                batch = await queue.get()
                try:
                    if batch is None:
                        break
                    coros = list()
                    url:str
                    for url in batch:
                        url = url.strip()
                        if not url:
                            continue
                        if target_https:
                            trace_config.star_vars[f"worker-{worker_id} - {url}"].is_https = True
                        coros.append(fetch_and_process(session, trace_config.star_vars[f"worker-{worker_id} - {url}"], url, logger, action, timeout, payload, retryes, verbose))
                        processed += 1
                    await asyncio.gather(*coros, return_exceptions=True)
                    
                finally:
                    queue.task_done()
            logger.log(f"worker {worker_id} finished, processed={processed}", LogLevel.debug)

        # ensuring that all workers are eventually closed
        async with asyncio.TaskGroup() as tg:
            tg.create_task(asyncio.to_thread(_produce_batches_sync, path, manual_hosts, batch_size, _queue_put, num_workers))
            for i in range(num_workers):
                tg.create_task(worker(i))

    await queue.join()

def count_lines(filepath: str, logger: Logger) -> int:
    try:
        with open(filepath, "rb") as f:
            num_lines = 0
            # 1Mb
            while chunk := f.read(1024 * 1024):
                num_lines += chunk.count(b'\n')
            return num_lines
    except FileNotFoundError:
        logger.log(f"No such file or directory: '{filepath}'", LogLevel.fatal)
        return -1
    
def valid_headers_cookies_data(data):
    for k, v in data.items():
        if not isinstance(k, str) or not isinstance(v, str):
            return 0
    return 1

def check_cli_arg_middlewares(args, logger: Logger):
    middlewares = list()
    if args.file and args.host:
        raise RuntimeError("Only one of the keys can be specified at a time –F or -H")
    elif not args.file and not args.host:
        raise RuntimeError("One of the keys required –F or -H")
    

    if args.headers:
        try:
            data = json.loads(args.headers)
            if not valid_headers_cookies_data(data):
                raise RuntimeError("headers invalid")
            middlewares.append(headers_middleware(data))
        except json.JSONDecodeError as e:
            raise RuntimeError("headers invalid")
    if args.cookies:
        try:
            data = json.loads(args.cookies)
            if not valid_headers_cookies_data(data):
                raise RuntimeError("cookies invalid")
            middlewares.append(cookies_middleware(data))
        except json.JSONDecodeError as e:
            raise RuntimeError("cookies invalid")
    if args.bearer:
        try:
            middlewares.append(bearer_auth_middleware(args.bearer))
        except json.JSONDecodeError as e:
            raise RuntimeError("bearer invalid")
    elif args.cli_pass:
        if args.login:
            middlewares.append(pass_auth_middleware(args.login, None, logger))
        else:
            raise RuntimeError("cli_pass is specified, but no login is specified")
    elif args.file_pass:
        if args.login:
            middlewares.append(pass_auth_middleware(args.login, Path(args.file_pass), logger, args.force))
        else:
            raise RuntimeError("file_pass is specified, but no login is specified")

    if args.action:
        if args.action not in ["get", "post", "put", "patch", "delete", "options"]:
            raise RuntimeError("action invalid")
    else:
        args.action = "get"
    
    if args.payload:
        try:
            args.payload = json.loads(args.payload)
        except json.JSONDecodeError as e:
            raise RuntimeError("payload invalid")
        
    if args.timeout < 1:
        raise RuntimeError("timeout cannot be less than 1")
        
    return middlewares

def init_args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CLI for testing server availability over the HTTP protocol")
    parser.add_argument("--host", "-H", type=str, action='append', help="The host that the requests will be made to. Can specified multiple addresses separated by commas without spaces. Only one of the keys can be specified at a time –F or -H")
    parser.add_argument("--timeout", "-t", type=int, default=3, help="Timeout sec, default 3 sec")
    parser.add_argument("--count", "-C", type=int, default=1, help="The сount of requests that will be sent to each host to calculate the average value, default 1")
    parser.add_argument("--file", "-F", type=str, help="A file with a list of addresses divided into lines. Only one of the keys can be specified at a time –F or -H")
    parser.add_argument("--output", "-O", type=str, help="The path to the file where you want to save the output. If not specified, the output is sent to the console")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable detailed exception output")
    parser.add_argument("--not-quiet", "-q", action="store_true", help="Enable detailed log data, default disabled")
    parser.add_argument("--cli-pass", "-l", action="store_true", help="Enable hidden password entry via the console, need to specify --login")
    parser.add_argument("--file-pass", "-i", type=str, help="Accepts a path to file and enable password reading from a accepted file, need to specify --login")
    parser.add_argument("--login", "-n", type=str, help="Login for --file-pass or --cli-pass")
    parser.add_argument("--headers", "-d", type=str, help='Include headers json in the request. Headers must be json serializable and strictly requires the {"key": "value"} format, i.e. string: string')
    parser.add_argument("--cookies", "-k", type=str, help='Include cookies json in the request. Сookies must be json serializable and strictly requires the {"key": "value"} format, i.e. string: string')
    parser.add_argument("--bearer", "-b", type=str, help="Include bearer json in the headers request. If bearer is installed --file-pass and --cli-pass will be ignored")
    parser.add_argument("--payload", "-p", type=str, help="Json payload, must be json serializable")
    parser.add_argument("--action", "-a", type=str, help="Request metod, available: get, post, put, patch, delete, options")
    parser.add_argument("--log-level", "-g", type=str, help="Log level, available: debug, info, warn, err, fatal, success. Default - 'success'")
    parser.add_argument("--http", "-s", action="store_true", help="Enables http connection, if not specified in the hosts")
    parser.add_argument("--force", "-r", action="store_true", help="Disable security check for pass-file")

    return parser


def main() -> int:
    parser = init_args_parser()
    args = parser.parse_args()

    if args.output:
        logger = Logger(out=args.output, verbose=args.verbose, name=__name__, quiet=(not args.not_quiet))
    else:
        logger = Logger(verbose=args.verbose, name=__name__, quiet=(not args.not_quiet))

    logger.set_level(args.log_level)
    logger.init()

    try:
        middlewares = check_cli_arg_middlewares(args=args, logger=logger)
    except Exception as e:
        logger.log(f"Parameters are incorrect: '{str(e)}'", LogLevel.fatal)
        return 1

    debug_trace = DebugTrace(logger)
    debug_trace.init_trace()

    middlewares = []
    manual_hosts = []
    target_https = True
    if args.http:
        target_https = False
    
    total_urls = 0
    
    if args.host:
        for item in args.host:
            manual_hosts.extend(item.split(","))
        total_urls = len(manual_hosts)
    elif args.file:
        total_urls = count_lines(args.file, logger)
    
    calculated_workers = 0

    if total_urls > 0:
        calculated_workers = (total_urls // BATCH_SIZE + 1)
    elif total_urls < 1:
        raise RuntimeError("no host is specified")

    if calculated_workers > MAX_WORKERS_LIMIT:
        logger.log(f"Calculated workers {calculated_workers} exceeds limit. Capped to {MAX_WORKERS_LIMIT}", LogLevel.warn)
        calculated_workers = MAX_WORKERS_LIMIT
        
    logger.log(f"Total URLs: {total_urls}. Workers: {calculated_workers}. Batch size: {BATCH_SIZE}", LogLevel.info)
    
    asyncio.run(run_requester(
        path=args.file,
        manual_hosts=manual_hosts,
        middlewares=middlewares,
        trace_config=debug_trace,
        logger=logger,
        timeout_val=args.timeout,
        payload=args.payload,
        action=args.action,
        retryes=args.count,
        num_workers=calculated_workers,
        batch_size=BATCH_SIZE,
        qsize=int(calculated_workers//0.8), # dividing to get a little more qsize from calculated_workers
        verbose=args.verbose,
        target_https=target_https
    ))
    
    logger.close()

    return 0
    


if __name__ == "__main__":
    status = main()
    #so that the user doesn't think that nothing has happened.
    print(f"bye bye: {status}")
    
