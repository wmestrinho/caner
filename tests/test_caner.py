"""Fast, offline tests. No network, no root, no fixtures on disk."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from caner import crashscan, dnsquery, netscan, procscan  # noqa: E402


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
