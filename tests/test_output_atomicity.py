"""Concurrent report publication must expose only complete artifacts."""

import threading

import praetor


def test_concurrent_reader_never_observes_partial_report(tmp_path):
    target = tmp_path / "praetor-report.json"
    first = '{"generation":"A","payload":"' + ("A" * 200_000) + '"}'
    second = '{"generation":"B","payload":"' + ("B" * 200_000) + '"}'
    target.write_text(first, encoding="utf-8")
    stop = threading.Event()
    partial = []

    def reader():
        while not stop.is_set():
            try:
                observed = target.read_text(encoding="utf-8")
            except PermissionError:
                # Windows may transiently refuse a new reader during publish;
                # the writer's bounded retry/loud-failure policy covers that.
                continue
            if observed not in (first, second):
                partial.append(observed[:80])
                stop.set()
                return

    thread = threading.Thread(target=reader)
    thread.start()
    try:
        for _ in range(20):
            for payload in (second, first):
                try:
                    praetor._atomic_write_text(str(target), payload)
                except RuntimeError as exc:
                    # A reader holding the destination open may produce the
                    # intentional loud failure; it must never produce bytes.
                    assert "destination is in use" in str(exc)
    finally:
        stop.set()
        thread.join(timeout=5)
    assert not partial, f"reader observed a partial report: {partial[0]!r}"


def test_blocked_windows_publish_fails_loudly_without_clobbering(tmp_path):
    target = tmp_path / "praetor-report.json"
    original = '{"generation":"old"}'
    target.write_text(original, encoding="utf-8")
    handle = target.open("r", encoding="utf-8")
    try:
        try:
            praetor._atomic_write_text(str(target), '{"generation":"new"}')
        except RuntimeError as exc:
            assert str(target) in str(exc)
            assert "destination is in use" in str(exc)
        else:
            # POSIX permits replacement while a reader is open; this control is
            # specifically asserted on Windows where the sharing refusal occurs.
            if __import__("os").name == "nt":
                raise AssertionError("blocked Windows publish unexpectedly succeeded")
    finally:
        handle.close()
    assert target.read_text(encoding="utf-8") == original
