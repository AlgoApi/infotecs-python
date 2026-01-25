import os
import pytest
import bench


class FakeLogger:
    def __init__(self):
        self.records = []

    def log(self, message: str, level=None):
        self.records.append((level, message))

    def last(self):
        return self.records[-1] if self.records else None


class DummyDigestAuth:
    def __init__(self, login, password):
        self.login = login
        self.password = password


def test_valid_headers_cookies_data_ok_and_bad():
    good = {"A": "1", "B": "xyz"}
    assert bench.valid_headers_cookies_data(good) == 1

    bad1 = {123: "1"}
    assert bench.valid_headers_cookies_data(bad1) == 0

    bad2 = {"a": 1}
    assert bench.valid_headers_cookies_data(bad2) == 0

    assert bench.valid_headers_cookies_data({}) == 1


def test_count_lines(tmp_path):
    p = tmp_path / "lines.txt"
    data = "one\ntwo\nthree\n"
    p.write_bytes(data.encode("utf-8"))
    logger = FakeLogger()
    assert bench.count_lines(str(p), logger) == 3

    missing = tmp_path / "nope.txt"
    res = bench.count_lines(str(missing), logger)
    assert res == -1
    assert "no such file" in logger.records[-1][1].lower() or "no such" in logger.records[-1][1].lower()


def test_produce_batches_from_list_and_file_collects_batches(tmp_path):
    items = [f"url{i}" for i in range(11)]
    collected = []

    def queue_put(item):
        collected.append(item)

    bench._produce_batches_sync(None, items, batch_size=4, queue_put=queue_put, num_workers=3)
    assert collected[:-3] == [["url0","url1","url2","url3"],
                              ["url4","url5","url6","url7"],
                              ["url8","url9","url10"]]
    assert collected[-3:] == [None, None, None]

    p = tmp_path / "u.txt"
    p.write_text("\n".join(items) + "\n", encoding="utf-8")
    collected2 = []
    def qput2(item):
        collected2.append(item)
    bench._produce_batches_sync(str(p), None, batch_size=5, queue_put=qput2, num_workers=2)
    assert collected2[:-2] == [
        ["url0","url1","url2","url3","url4"],
        ["url5","url6","url7","url8","url9"],
        ["url10"]
    ]
    assert collected2[-2:] == [None, None]


@pytest.mark.asyncio
async def test_headers_middleware_sets_defaults_and_keeps_existing():
    class Req:
        def __init__(self):
            self.headers = {"Existing": "keep"}

    async def handler(req):
        return "ok"

    mdw = bench.headers_middleware({"X-A": "1", "Existing": "should-not-override"})
    r = Req()
    res = await mdw(r, handler)
    assert res == "ok"
    assert r.headers["X-A"] == "1"
    assert r.headers["Existing"] == "keep"


@pytest.mark.asyncio
async def test_cookies_middleware_sets_cookie_header_and_preserves_other_headers():
    class Req:
        def __init__(self):
            self.headers = {}

    cookies = {"sessionid": "abc", "u": "x"}
    mdw = bench.cookies_middleware(cookies)

    async def handler(req):
        return req.headers.get("Cookie")

    r = Req()
    cookie_header = await mdw(r, handler)
    assert "sessionid=abc" in cookie_header
    assert "u=x" in cookie_header


@pytest.mark.asyncio
async def test_bearer_middleware_sets_authorization_header():
    class Req:
        def __init__(self):
            self.headers = {}

    token = "tok"
    mdw = bench.bearer_auth_middleware(token)

    async def handler(req):
        return req.headers["Authorization"]

    r = Req()
    auth = await mdw(r, handler)
    assert auth == f"Bearer {token}"


def test_pass_auth_middleware_unix_file(monkeypatch, tmp_path):
    p = tmp_path / "pw.txt"
    p.write_bytes(b"secret\n")
    os.chmod(p, 0o600)

    monkeypatch.setattr(bench.platform, "system", lambda: "Linux")
    monkeypatch.setattr(bench, "DigestAuthMiddleware", DummyDigestAuth)

    logger = FakeLogger()
    mdw = bench.pass_auth_middleware("user", p, logger)
    assert isinstance(mdw, DummyDigestAuth)
    assert mdw.login == "user"
    assert mdw.password == "secret"

def test_pass_auth_middleware_windows_icacls(monkeypatch, tmp_path):
    p = tmp_path / "w.txt"
    p.write_bytes(b"pwd\n")

    monkeypatch.setattr(bench.platform, "system", lambda: "Windows")
    def fake_check_output(cmd, text=True):
        if cmd[0] == "whoami":
            return "User"
        else:
            return f"{p} User:(F)\n{p} SYSTEM:(F)\n"

    monkeypatch.setattr(bench.subprocess, "check_output", fake_check_output)
    monkeypatch.setattr(bench, "DigestAuthMiddleware", DummyDigestAuth)

    logger = FakeLogger()
    mdw = bench.pass_auth_middleware("user", p, logger)
    assert isinstance(mdw, DummyDigestAuth)
    assert mdw.login == "user"
    assert mdw.password == "pwd"

@pytest.mark.asyncio
async def test_fetch_and_process_invalid_url_increments_errors_and_logs(monkeypatch):
    class FakeBadCM:
        def __init__(self, exc):
            self._exc = exc
        async def __aenter__(self):
            raise self._exc
        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeSession:
        def __init__(self):
            pass
        def get(self, url, **kwargs):
            # raise InvalidURL
            return FakeBadCM(bench.InvalidURL("bad url"))

    fake_session = FakeSession()
    logger = FakeLogger()
    stats = bench.RequestStats()
    await bench.fetch_and_process(fake_session, stats, "http://bad", logger, action="get", timeout=bench.ClientTimeout(total=1), payload=None, retryes=1, verbose=True)
    assert stats.errors == 1
    assert any("Invalid URL" in rec[1] for rec in logger.records)


def test_debug_trace_has_callbacks_attached():
    logger = FakeLogger()
    dt = bench.DebugTrace(logger)
    tc = dt.init_trace()
    assert len(tc.on_request_start) > 0
    assert len(tc.on_request_end) > 0
    assert len(tc.on_request_exception) > 0


@pytest.mark.asyncio
async def test_run_requester_with_urls_list(monkeypatch, tmp_path):
    items = ["http://a", "http://b", "http://c"]

    orig_produce = bench._produce_batches_sync
    def produce_override(path, items_arg, batch_size, queue_put, num_workers):
        return orig_produce(None, items, batch_size, queue_put, num_workers)

    monkeypatch.setattr(bench, "_produce_batches_sync", produce_override)

    async def fake_fetch(session, stats, url, logger, action, timeout, payload, retryes, verbose):
        await stats.add(200, 0.123)
        return None

    monkeypatch.setattr(bench, "fetch_and_process", fake_fetch)

    logger = FakeLogger()
    debug_trace = bench.DebugTrace(logger)
    debug_trace.init_trace()
    middlewares = []

    await bench.run_requester(
        path=None,
        manual_hosts=items,
        middlewares=middlewares,
        trace_config=debug_trace,
        logger=logger,
        payload=None,
        timeout_val=1,
        action="get",
        batch_size=2,
        num_workers=2,
        qsize=4,
        retryes=1,
        verbose=False,
        target_https=False
    )

    total = sum(v.total for v in debug_trace.star_vars.values())
    assert total == len(items)
