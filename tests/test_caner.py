"""Fast, offline tests. No network, no root, no fixtures on disk."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from caner import crashscan, dnsquery, history, netscan, notify, procscan  # noqa: E402


class TestDNSWire(unittest.TestCase):
    def test_encode_name_roundtrip(self):
        self.assertEqual(dnsquery._encode_name("a.bc"), b"\x01a\x02bc\x00")

    def test_rejects_oversized_label(self):
        with self.assertRaises(dnsquery.DNSError):
            dnsquery._encode_name("x" * 64 + ".com")

    def test_skip_name_handles_compression_pointer(self):
        # 0xC0 0x0C is a pointer; it occupies exactly two bytes and has no tail.
        self.assertEqual(dnsquery._skip_name(b"\xc0\x0c", 0), 2)

    def test_skip_name_handles_labels(self):
        # 6 bytes total; the returned offset is one past the terminating null.
        self.assertEqual(dnsquery._skip_name(b"\x01a\x02bc\x00", 0), 6)


class TestCrashSignature(unittest.TestCase):
    def test_boilerplate_is_skipped(self):
        """Every C++ abort shares these frames; the signature must start below them."""
        frames = [
            "libc.so.6+0x9a17c", "raise@libc.so.6+0x3e5d0", "abort@libc.so.6+0x25685",
            "__cxa_call_terminate@libstdc++.so.6+0x9a459", "_Unwind_Resume@libgcc_s.so.1+0x22b8b",
            "liblauncher.so+0x136145", "liblauncher.so+0x29f201",
        ]
        self.assertEqual(crashscan.signature_frames(frames, want=2),
                         ["liblauncher.so+0x136145", "liblauncher.so+0x29f201"])

    def test_distinct_faults_do_not_collapse(self):
        boiler = ["raise@libc.so.6+0x1", "abort@libc.so.6+0x2"]
        a = crashscan.signature_frames(boiler + ["libfoo.so+0xaaa"])
        b = crashscan.signature_frames(boiler + ["libbar.so+0xbbb"])
        self.assertNotEqual(a, b)

    def test_all_boilerplate_still_yields_something(self):
        frames = ["raise@libc.so.6+0x1", "abort@libc.so.6+0x2"]
        self.assertTrue(crashscan.signature_frames(frames))

    def test_normalise_strips_addresses(self):
        self.assertEqual(crashscan._normalise("g_signal_emit (libgobject-2.0.so.0 + 0x33d94)"),
                         "g_signal_emit@libgobject-2.0.so.0+0x33d94")
        self.assertEqual(crashscan._normalise("n/a (liblauncher.so + 0x136145)"),
                         "liblauncher.so+0x136145")


class TestProcClassify(unittest.TestCase):
    def _p(self, comm, cmdline=""):
        return procscan.Proc(pid=1, comm=comm, rss_kb=1, ppid=0, age_s=0, scope="", cmdline=cmdline)

    def test_crash_agent_beats_generic_agent(self):
        """Ordering matters: an investigator must not vanish into the generic bucket."""
        key, _ = procscan.classify(self._p("claude", "claude -- systemd-coredump recorded ..."))
        self.assertEqual(key, "crash-agent")

    def test_plain_agent_session(self):
        self.assertEqual(procscan.classify(self._p("claude", "claude"))[0], "agent-session")

    def test_unknown_falls_through_to_own_bucket(self):
        self.assertEqual(procscan.classify(self._p("weirdthing"))[0], "other:weirdthing")


class TestNetscanVerdict(unittest.TestCase):
    """The case caner exists for: DNS answers, and the answer is a black hole."""

    def setUp(self):
        self._real_query = dnsquery.query
        self._real_sys = dnsquery.system_resolvers
        self._real_probe = netscan.tcp_probe
        self._real_v6 = netscan.have_ipv6_route
        netscan.have_ipv6_route = lambda: False

    def tearDown(self):
        dnsquery.query = self._real_query
        dnsquery.system_resolvers = self._real_sys
        netscan.tcp_probe = self._real_probe
        netscan.have_ipv6_route = self._real_v6

    def _wire(self, mapping, dead):
        # The reserved black-hole address must stay unreachable, or scan()'s probe
        # self-test correctly concludes the network is intercepting everything.
        dead = set(dead) | {netscan.BLACKHOLE_IP}
        dnsquery.system_resolvers = lambda: ["10.0.0.1"]
        dnsquery.query = lambda server, name, **kw: mapping[server]
        netscan.tcp_probe = lambda ip, port, timeout=5.0: (
            {"ip": ip, "ok": ip not in dead, "ms": 20.0,
             "error": "timeout — no SYN-ACK" if ip in dead else ""})

    def test_degraded_when_system_resolver_returns_dead_edge(self):
        self._wire({"10.0.0.1": ["1.2.3.4"], "9.9.9.9": ["5.6.7.8"],
                    "1.1.1.1": ["5.6.7.8"], "8.8.8.8": ["5.6.7.8"]}, dead={"1.2.3.4"})
        out = netscan.scan(endpoints=[{"host": "x.test", "port": 443}])
        self.assertEqual(out["endpoints"][0]["status"], "degraded")
        alert = [f for f in out["findings"] if f["level"] == "alert"]
        self.assertTrue(alert)
        self.assertIn("1.2.3.4", alert[0]["text"])
        self.assertIn("5.6.7.8", alert[0]["text"])

    def test_ok_when_system_resolver_works(self):
        self._wire({"10.0.0.1": ["5.6.7.8"], "9.9.9.9": ["5.6.7.8"],
                    "1.1.1.1": ["5.6.7.8"], "8.8.8.8": ["5.6.7.8"]}, dead=set())
        out = netscan.scan(endpoints=[{"host": "x.test", "port": 443}])
        self.assertEqual(out["endpoints"][0]["status"], "ok")
        self.assertFalse([f for f in out["findings"] if f["level"] == "alert"])

    def test_down_when_nothing_reachable(self):
        self._wire({"10.0.0.1": ["1.2.3.4"], "9.9.9.9": ["1.2.3.4"],
                    "1.1.1.1": ["1.2.3.4"], "8.8.8.8": ["1.2.3.4"]}, dead={"1.2.3.4"})
        out = netscan.scan(endpoints=[{"host": "x.test", "port": 443}])
        self.assertEqual(out["endpoints"][0]["status"], "down")


class TestNotifier(unittest.TestCase):
    """A monitor that cries wolf gets muted, so the quiet rules are the feature."""

    def _n(self, **kw):
        n = notify.Notifier(**kw)
        n.enabled = True                     # bypass the notify-send lookup
        self.sent = []
        n._send = lambda f: (self.sent.append(f), True)[1]
        return n

    def test_fingerprint_ignores_drifting_numbers(self):
        a = {"level": "alert", "text": "free 981.0 MB of 3309.4 MB"}
        b = {"level": "alert", "text": "free 984.2 MB of 3309.4 MB"}
        self.assertEqual(notify.fingerprint(a), notify.fingerprint(b))

    def test_fingerprint_distinguishes_different_findings(self):
        a = {"level": "alert", "text": "memory cliff"}
        b = {"level": "alert", "text": "endpoint degraded"}
        self.assertNotEqual(notify.fingerprint(a), notify.fingerprint(b))

    def test_requires_two_consecutive_scans(self):
        n = self._n(cooldown_s=0)
        f = [{"level": "alert", "text": "boom"}]
        self.assertEqual(n.process(f, now=100), [])       # first sighting: armed only
        self.assertEqual(len(n.process(f, now=101)), 1)   # confirmed: fires

    def test_transient_blip_never_fires(self):
        n = self._n(cooldown_s=0)
        n.process([{"level": "alert", "text": "blip"}], now=100)
        n.process([], now=101)                            # vanished before confirming
        self.assertEqual(n.process([{"level": "alert", "text": "blip"}], now=102), [])

    def test_cooldown_suppresses_repeat(self):
        n = self._n(cooldown_s=1800)
        f = [{"level": "alert", "text": "boom"}]
        n.process(f, now=100)
        self.assertEqual(len(n.process(f, now=101)), 1)
        self.assertEqual(n.process(f, now=200), [])       # inside cooldown
        self.assertEqual(len(n.process(f, now=2000)), 1)  # cooldown elapsed

    def test_min_level_filters_lower_findings(self):
        n = self._n(cooldown_s=0, min_level="alert")
        f = [{"level": "warn", "text": "meh"}, {"level": "info", "text": "fyi"}]
        n.process(f, now=100)
        self.assertEqual(n.process(f, now=101), [])

    def test_disabled_notifier_is_silent(self):
        n = self._n(cooldown_s=0)
        n.enabled = False
        f = [{"level": "alert", "text": "boom"}]
        n.process(f, now=100)
        self.assertEqual(n.process(f, now=101), [])


class TestProbeSelftest(unittest.TestCase):
    """A probe that cannot detect failure makes every 'ok' meaningless."""

    def setUp(self):
        self._real = netscan.tcp_probe

    def tearDown(self):
        netscan.tcp_probe = self._real

    def test_blackhole_unreachable_means_trustworthy(self):
        netscan.tcp_probe = lambda ip, port, timeout=5.0: {
            "ip": ip, "ok": False, "ms": 4000.0, "error": "timeout — no SYN-ACK"}
        out = netscan.probe_selftest()
        self.assertTrue(out["trustworthy"])
        self.assertFalse(out["connected"])

    def test_blackhole_reachable_means_interception(self):
        netscan.tcp_probe = lambda ip, port, timeout=5.0: {
            "ip": ip, "ok": True, "ms": 12.0, "error": ""}
        out = netscan.probe_selftest()
        self.assertFalse(out["trustworthy"])

    def test_scan_raises_alert_when_probes_cannot_be_trusted(self):
        real_sys, real_q, real_v6 = (dnsquery.system_resolvers, dnsquery.query,
                                     netscan.have_ipv6_route)
        try:
            dnsquery.system_resolvers = lambda: ["10.0.0.1"]
            dnsquery.query = lambda server, name, **kw: ["5.6.7.8"]
            netscan.have_ipv6_route = lambda: False
            netscan.tcp_probe = lambda ip, port, timeout=5.0: {
                "ip": ip, "ok": True, "ms": 5.0, "error": ""}      # everything "works"
            out = netscan.scan(endpoints=[{"host": "x.test", "port": 443}])
            alerts = [f for f in out["findings"] if f["level"] == "alert"]
            self.assertTrue(alerts)
            self.assertIn("unroutable", alerts[0]["text"])
            self.assertFalse(out["selftest"]["trustworthy"])
        finally:
            dnsquery.system_resolvers, dnsquery.query = real_sys, real_q
            netscan.have_ipv6_route = real_v6


class TestHistory(unittest.TestCase):
    def _fill(self, h, values, start=1000.0, step=30.0):
        for i, v in enumerate(values):
            h.sample({"available_mb": v, "reclaimable_mb": 0, "swap_used_mb": 0},
                     {"total_dumps": 0}, {"endpoints": []}, 26.0, now=start + i * step)

    def test_ring_is_bounded(self):
        h = history.History(retain=5)
        self._fill(h, list(range(20)))
        self.assertEqual(len(h.series()), 5)

    def test_trend_detects_sustained_decline(self):
        h = history.History(retain=100)
        self._fill(h, [1500 - i * 20 for i in range(40)])   # 20 min, steady fall
        self.assertLess(h.summary()["avail_trend_mb"], -500)

    def test_trend_ignores_a_single_spike(self):
        """First-vs-last would be fooled here; comparing fifths should not be."""
        h = history.History(retain=100)
        flat = [1000] * 40
        flat[20] = 100                                       # one dramatic dip
        self._fill(h, flat)
        self.assertEqual(h.summary()["avail_trend_mb"], 0.0)

    def test_finding_needs_a_long_enough_span(self):
        h = history.History(retain=100)
        self._fill(h, [1500 - i * 50 for i in range(5)], step=30)   # only 2 min
        self.assertEqual(h.findings(), [])

    def test_finding_fires_on_long_sustained_decline(self):
        h = history.History(retain=200)
        self._fill(h, [1500 - i * 10 for i in range(80)], step=30)  # 40 min
        found = h.findings()
        self.assertTrue(found)
        self.assertEqual(found[0]["level"], "warn")
        self.assertIn("fallen", found[0]["text"])

    def test_sample_returns_none_before_first_proc_scan(self):
        h = history.History(retain=10)
        self.assertIsNone(h.sample(None, None, None, 26.0))

    def test_persists_and_reloads(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "h.jsonl")
            h = history.History(retain=50, path=path)
            self._fill(h, [900, 880, 860])
            self.assertEqual(len(history.History(retain=50, path=path).series()), 3)

    def test_tolerates_a_torn_final_line(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "h.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"t": 1.0, "avail_mb": 500}) + "\n")
                fh.write('{"t": 2.0, "avail_mb":')          # killed mid-write
            self.assertEqual(len(history.History(retain=50, path=path).series()), 1)

    def test_disk_failure_never_raises(self):
        h = history.History(retain=10, path="/proc/definitely/not/writable.jsonl")
        self._fill(h, [900])
        self.assertEqual(len(h.series()), 1)                 # sample still recorded
        self.assertTrue(h.write_error)


if __name__ == "__main__":
    unittest.main(verbosity=2)
