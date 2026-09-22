"""Platform-seam tests. Every backend is checked on whatever OS runs the suite.

The point of these is that a port cannot be verified only on the machine it was
written on. Each backend module is importable and inspectable everywhere, so the
contract — the required functions exist, the pure parsing is right, declining is
graceful — is enforced on Seat 3 even though the code runs on Seats 1 and 2.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from caner import netscan, notify, platforms  # noqa: E402
from caner.platforms import darwin, generic, linux, windows  # noqa: E402

BACKENDS = {"generic": generic, "linux": linux, "darwin": darwin, "windows": windows}


class SeamTestCase(unittest.TestCase):
    """Patch the platform seam and restore it exactly.

    Assigning onto `platforms` creates a real attribute that shadows the
    module's `__getattr__` forwarding, so undoing it means deleting the
    attribute — reassigning would leave the shadow in place and quietly leak
    into every later test.
    """

    def patch_platform(self, name, value):
        had = name in platforms.__dict__
        previous = platforms.__dict__.get(name)
        setattr(platforms, name, value)

        def restore():
            if had:
                setattr(platforms, name, previous)
            else:
                delattr(platforms, name)

        self.addCleanup(restore)


class TestBackendContract(unittest.TestCase):
    def test_every_backend_satisfies_the_interface(self):
        """A missing function would only surface on the OS it belongs to."""
        for name, module in BACKENDS.items():
            for func in platforms._REQUIRED:
                with self.subTest(backend=name, function=func):
                    self.assertTrue(callable(getattr(module, func, None)),
                                    f"{name}.{func} missing or not callable")

    def test_os_backends_declare_capabilities(self):
        for name in ("linux", "darwin", "windows"):
            with self.subTest(backend=name):
                caps = BACKENDS[name].CAPABILITIES
                self.assertEqual(set(caps), {"procscan", "crashscan", "netscan"})

    def test_only_linux_claims_proc_and_crash_scanners(self):
        """Seats 1 and 2 must not silently report an empty scan as a clean one."""
        self.assertTrue(linux.CAPABILITIES["procscan"])
        self.assertTrue(linux.CAPABILITIES["crashscan"])
        for name in ("darwin", "windows"):
            with self.subTest(backend=name):
                self.assertFalse(BACKENDS[name].CAPABILITIES["procscan"])
                self.assertFalse(BACKENDS[name].CAPABILITIES["crashscan"])

    def test_signatures_accept_a_server_list(self):
        for name, module in BACKENDS.items():
            with self.subTest(backend=name):
                self.assertIsInstance(module.dns_fix_command(["1.2.3.4"]), str)
                self.assertIsInstance(module.dns_fix_command(), str)


class TestDispatch(unittest.TestCase):
    def test_name_matches_this_host(self):
        expected = {"linux": "linux", "darwin": "darwin", "win32": "windows"}
        self.assertEqual(platforms.NAME,
                         expected.get(sys.platform.rstrip("0123456789"), platforms.NAME))

    def test_missing_backend_attribute_falls_back_to_generic(self):
        """A half-ported backend must keep running, not crash the scan loop."""
        class Stub:
            CAPABILITIES = {"procscan": False, "crashscan": False, "netscan": True}

        original = platforms._backend
        platforms._backend = Stub()
        self.addCleanup(lambda: setattr(platforms, "_backend", original))
        self.assertIs(platforms._resolve("dns_fix_command"), generic.dns_fix_command)
        self.assertEqual(platforms._resolve("system_resolvers")(),
                         generic.system_resolvers())

    def test_unknown_attribute_raises_rather_than_returning_none(self):
        with self.assertRaises(AttributeError):
            platforms._resolve("no_such_platform_function")

    def test_private_attributes_are_not_forwarded(self):
        with self.assertRaises(AttributeError):
            platforms.__getattr__("_secret")

    def test_hostname_is_never_empty(self):
        self.assertTrue(platforms.hostname())

    def test_describe_reports_gaps_consistently(self):
        info = platforms.describe()
        for key in ("backend", "system", "python", "hostname", "capabilities", "unsupported"):
            self.assertIn(key, info)
        self.assertEqual(set(info["unsupported"]),
                         {k for k, v in info["capabilities"].items() if not v})

    def test_ipv6_route_check_returns_a_bool_without_a_subprocess(self):
        self.assertIsInstance(platforms.have_ipv6_route(), bool)


class TestGenericDeclinesCleanly(unittest.TestCase):
    """Declining must be silent and typed, never an exception or a fake value."""

    def test_no_notifications(self):
        self.assertFalse(generic.notify_available())
        self.assertFalse(generic.notify("t", "x", "alert"))

    def test_no_dns_remediation(self):
        self.assertEqual(generic.dns_fix_command(), "")

    def test_resolvers_are_a_list(self):
        self.assertIsInstance(generic.system_resolvers(), list)

    def test_rss_is_a_number(self):
        self.assertGreaterEqual(generic.self_rss_mb(), 0.0)


class TestDarwinParsing(unittest.TestCase):
    SCUTIL = """
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.0.1
  nameserver[1] : 9.9.9.9
  if_index : 12 (en0)

resolver #2
  nameserver[0] : 127.0.0.1
  flags    : Scoped, Request A records

resolver #3
  nameserver[0] : 192.168.0.1
"""

    def _with_scutil(self, text):
        original = darwin._run
        darwin._run = lambda cmd, timeout=5.0: text if cmd[0] == "scutil" else ""
        self.addCleanup(lambda: setattr(darwin, "_run", original))

    def test_parses_and_dedupes_preserving_order(self):
        self._with_scutil(self.SCUTIL)
        self.assertEqual(darwin.system_resolvers(), ["192.168.0.1", "9.9.9.9"])

    def test_drops_loopback_stub(self):
        self._with_scutil(self.SCUTIL)
        self.assertNotIn("127.0.0.1", darwin.system_resolvers())

    def test_falls_back_to_resolv_conf_when_scutil_says_nothing(self):
        self._with_scutil("DNS configuration\n")
        self.assertEqual(darwin.system_resolvers(), generic.system_resolvers())

    def test_notify_strips_quotes_that_would_break_applescript(self):
        sent = {}
        original = darwin.subprocess.run
        darwin.subprocess.run = lambda cmd, **kw: sent.update(script=cmd[-1])
        self.addCleanup(lambda: setattr(darwin.subprocess, "run", original))
        darwin.notify("caner", 'he said "boom" \\ then', "alert")
        self.assertNotIn('"boom"', sent["script"])
        self.assertIn("'boom'", sent["script"])
        self.assertEqual(sent["script"].count('"'), 4)   # only the two literals


class TestWindowsParsing(unittest.TestCase):
    def test_resolvers_empty_without_the_registry(self):
        """Imported on Linux for these tests; it must decline, not explode."""
        if windows.winreg is None:
            self.assertEqual(windows.system_resolvers(), [])

    def test_fix_command_covers_every_server_and_flags_elevation(self):
        cmd = windows.dns_fix_command(["9.9.9.9", "1.1.1.1", "8.8.8.8"])
        for addr in ("9.9.9.9", "1.1.1.1", "8.8.8.8"):
            self.assertIn(addr, cmd)
        self.assertIn("index=3", cmd)
        self.assertIn("Administrator", cmd)

    def test_notify_escapes_single_quotes_for_powershell(self):
        """An apostrophe in a finding would otherwise terminate the PS literal."""
        sent = {}

        class FakePopen:
            def __init__(self, cmd, **kwargs):
                sent["script"] = cmd[-1]

        original_popen = windows.subprocess.Popen
        original_shell = windows._powershell
        windows.subprocess.Popen = FakePopen
        windows._powershell = lambda: "powershell.exe"
        self.addCleanup(lambda: setattr(windows.subprocess, "Popen", original_popen))
        self.addCleanup(lambda: setattr(windows, "_powershell", original_shell))

        self.assertTrue(windows.notify("caner", "the host's resolver died", "alert"))
        script = sent["script"]
        self.assertIn("host''s", script)
        self.assertNotIn("host's ", script)
        # Odd numbers of quotes are what break the parse; doubling keeps it even.
        self.assertEqual(script.count("'") % 2, 0)

    def test_notify_declines_when_powershell_is_absent(self):
        original = windows._powershell
        windows._powershell = lambda: ""
        self.addCleanup(lambda: setattr(windows, "_powershell", original))
        self.assertFalse(windows.notify("caner", "x", "alert"))
        self.assertFalse(windows.notify_available())


class TestNetscanUsesTheSeam(SeamTestCase):
    """Exercises netscan.degraded_finding itself, not a copy of its wording."""

    def test_remediation_text_comes_from_the_platform(self):
        self.patch_platform("dns_fix_command", lambda servers=None: "FIXCMD --here")
        text = netscan.degraded_finding("sisu.xboxlive.com", ["1.2.3.4"], ["5.6.7.8"])["text"]
        self.assertIn("FIXCMD --here", text)
        self.assertIn("1.2.3.4", text)
        self.assertIn("5.6.7.8", text)

    def test_no_command_is_printed_when_the_platform_has_none(self):
        """Better a finding with no fix than a fix that cannot run on this OS."""
        self.patch_platform("dns_fix_command", lambda servers=None: "")
        text = netscan.degraded_finding("example.com", ["1.2.3.4"], ["5.6.7.8"])["text"]
        self.assertTrue(text.endswith("Pin DNS to a public resolver."), text)
        self.assertNotIn("nmcli", text)

    def test_platform_is_offered_the_public_resolvers_it_should_pin(self):
        seen = {}

        def capture(servers=None):
            seen["servers"] = servers
            return "x"

        self.patch_platform("dns_fix_command", capture)
        netscan.degraded_finding("example.com", [], ["5.6.7.8"])
        self.assertEqual(seen["servers"], netscan.DEFAULT_PUBLIC_RESOLVERS[:2])

    def test_empty_bad_list_still_reads_as_a_sentence(self):
        self.patch_platform("dns_fix_command", lambda servers=None: "")
        text = netscan.degraded_finding("example.com", [], ["5.6.7.8"])["text"]
        self.assertIn("no usable address", text)


class TestNotifierUsesTheSeam(SeamTestCase):
    def test_disabled_when_the_host_cannot_notify(self):
        self.patch_platform("notify_available", lambda: False)
        self.assertFalse(notify.Notifier(enabled=True).enabled)

    def test_enabled_when_the_host_can(self):
        self.patch_platform("notify_available", lambda: True)
        self.assertTrue(notify.Notifier(enabled=True).enabled)

    def test_config_off_still_wins_over_a_capable_host(self):
        self.patch_platform("notify_available", lambda: True)
        self.assertFalse(notify.Notifier(enabled=False).enabled)

    def test_backend_exception_is_recorded_not_raised(self):
        """One bad backend must not take down the scan loop."""
        def boom(*args, **kwargs):
            raise RuntimeError("backend died")

        self.patch_platform("notify_available", lambda: True)
        self.patch_platform("notify", boom)
        notifier = notify.Notifier(enabled=True)
        self.assertFalse(notifier._send({"level": "alert", "text": "x"}))
        self.assertIn("backend died", notifier.last_error)

    def test_level_maps_to_a_title_and_is_passed_through(self):
        seen = {}
        self.patch_platform("notify_available", lambda: True)
        self.patch_platform("notify", lambda t, x, lvl: seen.update(title=t, level=lvl) or True)
        notifier = notify.Notifier(enabled=True)
        self.assertTrue(notifier._send({"level": "alert", "text": "x"}))
        self.assertEqual(seen["level"], "alert")
        self.assertIn("action needed", seen["title"])


if __name__ == "__main__":
    unittest.main()


class TestCapabilityGating(SeamTestCase):
    """A scanner this host cannot run must be announced, not silently skipped."""

    def _scanner_with(self, backend):
        from caner import server
        original = platforms._backend
        platforms._backend = backend
        self.addCleanup(lambda: setattr(platforms, "_backend", original))
        cache = server.Cache()
        scanner = server.Scanner.__new__(server.Scanner)
        scanner.cache = cache
        return scanner, cache

    def test_linux_runs_everything(self):
        scanner, cache = self._scanner_with(linux)
        self.assertEqual(scanner._supported(), {"proc": True, "crash": True, "net": True})
        for name in ("proc", "crash", "net"):
            self.assertEqual(cache.get(name)["unsupported"], "")

    def test_unported_scanners_are_marked_with_the_right_backend(self):
        for backend, label in ((darwin, "darwin"), (windows, "windows")):
            with self.subTest(backend=label):
                scanner, cache = self._scanner_with(backend)
                self.assertEqual(scanner._supported(),
                                 {"proc": False, "crash": False, "net": True})
                self.assertIn(label, cache.get("proc")["unsupported"])
                self.assertIn("procscan", cache.get("proc")["unsupported"])
                self.assertEqual(cache.get("net")["unsupported"], "")

    def test_unsupported_is_distinct_from_an_empty_result(self):
        """The failure mode this guards: an empty panel read as a healthy zero."""
        scanner, cache = self._scanner_with(darwin)
        scanner._supported()
        entry = cache.get("proc")
        self.assertIsNone(entry["data"])
        self.assertEqual(entry["error"], "")
        self.assertTrue(entry["unsupported"])

    def test_backend_name_follows_the_backend_not_the_import_time_constant(self):
        self._scanner_with(windows)
        self.assertEqual(platforms.backend_name(), "windows")
        self.assertEqual(platforms.describe()["backend"], "windows")
