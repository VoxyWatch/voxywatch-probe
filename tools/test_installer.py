"""Hermetic installer contracts: no root, network, package or systemd mutations."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "install.sh"
MOCK = '''#!/usr/bin/env python3
import os,sys,pathlib,hashlib
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
root=pathlib.Path(os.environ["FIXTURE"])
with (root/"calls").open("a") as f: f.write(name+" "+" ".join(args)+"\\n")
if name=="id": print("0")
elif name=="uname": print(os.environ.get("TEST_ARCH","x86_64"))
elif name=="ldconfig": print("libpcap.so.0.8")
elif name=="sleep": pass
elif name=="curl":
    url=next(a for a in args if a.startswith("https://"))
    if url.endswith("/latest"): print("https://github.com/VoxyWatch/voxywatch-probe/releases/tag/v0.2.1-beta",end="")
    else:
        target=pathlib.Path(args[args.index("-o")+1])
        data=b"#!/bin/sh\\necho new-binary\\n"
        if url.endswith(".sha256"):
            digest=hashlib.sha256(data).hexdigest() if not os.environ.get("BAD_HASH") else "0"*64
            data=(digest+"  "+url.split("/")[-1][:-7]+"\\n").encode()
        target.write_bytes(data)
elif name=="systemctl":
    if args[0]=="is-active":
        if os.environ.get("FAIL_HEALTH") and (root/"restarted").exists() and not (root/"failed").exists():
            (root/"failed").touch(); sys.exit(3)
        sys.exit(0 if (root/"active").exists() else 3)
    if args[0]=="is-enabled": sys.exit(0 if (root/"enabled").exists() else 1)
    if args[0]=="enable": (root/"enabled").touch()
    if args[0]=="disable": (root/"enabled").unlink(missing_ok=True)
    if args[0]=="stop": (root/"active").unlink(missing_ok=True)
    if args[0]=="restart":
        (root/"restarted").touch()
        if os.environ.get("FAIL_RESTART") and not (root/"failed").exists():
            (root/"failed").touch(); sys.exit(1)
        (root/"active").touch()
else: sys.exit("unexpected mock")
'''


class Installer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin/probe"
        self.unit = self.root / "units/probe.service"
        self.config = self.root / "config/options"
        for path in (self.bin, self.unit, self.config):
            path.parent.mkdir()
        mock = self.root / "mock"
        mock.mkdir()
        for name in ("id", "uname", "curl", "systemctl", "ldconfig", "sleep"):
            p = mock / name
            p.write_text(MOCK)
            p.chmod(0o755)
        self.env = dict(os.environ, FIXTURE=str(self.root), PATH=f"{mock}:{os.environ['PATH']}")
        script = SOURCE.read_text().replace("BIN=/usr/local/bin/voxywatch-probe", f"BIN={self.bin}")
        script = script.replace("UNIT=/etc/systemd/system/voxywatch-probe.service", f"UNIT={self.unit}")
        script = script.replace("CONFIG=/etc/voxywatch-probe/options", f"CONFIG={self.config}")
        script = script.replace("LOCK=/run/voxywatch-probe-install/install.lock", f"LOCK={self.root}/private/install.lock")
        self.script = self.root / "install.sh"
        self.script.write_text(script)

    def run_install(self, *args, ok=True, **env):
        result = subprocess.run(["bash", str(self.script), *args], env=dict(self.env, **env), text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def test_destinations(self):
        for server in ("127.0.0.1:9060", "collector.example:9060", "[::1]:9060", "[2001:db8::1]:65535"):
            self.run_install("--server", server)
            self.assertIn(f"-hs {server}", self.unit.read_text())

    def test_invalid_input(self):
        for server in ("host:0", "host:65536", "host", "::1:9060", "[:::]:9060", "999.0.0.1:9060", "-bad:9060", "host:1\nRestart=no"):
            self.run_install("--server", server, ok=False)
        for site in ("4294967296", "-1", "99999999999", "010", "08", "00"):
            self.run_install("--server", "localhost:9060", "--site", site, ok=False)
        self.assertFalse(self.bin.exists())

    def test_missing_values(self):
        for flag in ("--server", "--site", "--iface", "--mode", "--transport", "--profile", "--media-policy", "--trusted-cidrs"):
            out = self.run_install(flag, ok=False)
            self.assertIn("missing value", out)
            self.assertNotIn("unbound variable", out)

    def test_preserve_and_restart(self):
        self.run_install("--server", "localhost:9060", "--site", "4294967295", "--iface", "eth9", "--transport", "tcp", "--profile", "span", "--media-policy", "heuristic", "--trusted-cidrs", "10.0.0.0/8")
        old = self.unit.read_bytes()
        inode = self.bin.stat().st_ino
        self.run_install()
        self.assertEqual(old, self.unit.read_bytes())
        self.assertNotEqual(inode, self.bin.stat().st_ino)
        self.assertIn("RuntimeDirectory=voxywatch-probe", self.unit.read_text())
        self.assertEqual((self.root / "calls").read_text().count("systemctl restart "), 2)
        calls = (self.root / "calls").read_text()
        self.assertNotIn("latest/download", calls)
        self.assertIn("/download/v0.2.1-beta/", calls)

    def test_hash_mismatch(self):
        self.run_install("--server", "localhost:9060", BAD_HASH="1", ok=False)
        self.assertFalse(self.bin.exists())

    def test_rollback(self):
        self.run_install("--server", "localhost:9060")
        self.bin.write_bytes(b"old-binary")
        previous = [p.read_bytes() for p in (self.bin, self.unit, self.config)]
        self.run_install("--site", "42", FAIL_RESTART="1", ok=False)
        self.assertEqual(previous, [p.read_bytes() for p in (self.bin, self.unit, self.config)])
        self.assertTrue((self.root / "active").exists())

    def test_custom_unit_is_preserved(self):
        self.unit.write_text("[Service]\nExecStart=/custom\n")
        self.run_install("--server", "localhost:9060", ok=False)
        self.assertIn("/custom", self.unit.read_text())
        self.assertFalse(self.bin.exists())

    def test_first_install_failure_restores_absence(self):
        self.run_install("--server", "localhost:9060", FAIL_RESTART="1", ok=False)
        for path in (self.bin, self.unit, self.config):
            self.assertFalse(path.exists())
        self.assertFalse((self.root / "active").exists())
        self.assertFalse((self.root / "enabled").exists())

    def test_health_failure_rolls_back(self):
        self.run_install("--server", "localhost:9060", FAIL_HEALTH="1", ok=False)
        self.assertFalse(self.bin.exists())

    def test_managed_unit_customization_is_preserved(self):
        self.run_install("--server", "localhost:9060")
        self.unit.write_text(self.unit.read_text() + "# local customization\n")
        old = self.unit.read_bytes()
        self.run_install(ok=False)
        self.assertEqual(old, self.unit.read_bytes())

    def test_arm64_and_zero_site(self):
        self.run_install("--server", "localhost:1", "--site", "0", TEST_ARCH="aarch64")
        self.assertIn("-capture-id 0", self.unit.read_text())
        self.assertIn("voxywatch-probe-linux-arm64", (self.root / "calls").read_text())

    def test_config_is_not_executable(self):
        self.config.write_text("server\t$(touch /should-not-exist)\n")
        self.run_install("--server", "localhost:9060", ok=False)
        self.assertFalse(self.bin.exists())

    def test_invalid_cidr(self):
        self.run_install("--server", "localhost:9060", "--trusted-cidrs", "10.0.0.0/99", ok=False)
        self.assertFalse(self.bin.exists())

    def test_lock_symlinks_cannot_truncate_files(self):
        victim = self.root / "victim"
        victim.write_text("must survive")
        private = self.root / "private"
        private.mkdir(mode=0o700)
        (private / "install.lock").symlink_to(victim)
        self.run_install("--server", "localhost:9060", ok=False)
        self.assertEqual(victim.read_text(), "must survive")
        (private / "install.lock").unlink()
        private.rmdir()
        private.symlink_to(self.root, target_is_directory=True)
        self.run_install("--server", "localhost:9060", ok=False)
        self.assertFalse((self.root / "install.lock").exists())

    def test_exact_legacy_unit_migrates_and_preserves_options(self):
        for trusted in ("", "-trusted-cidrs 10.0.0.0/8"):
            old = f'''[Unit]
Description=VoxyWatch Probe — captures SIP/RTP/RTCP toward VoxyWatch
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={self.bin} -hs collector.example:9060 -i eth9 -m siprtcp -t tcp -profile span -media-policy heuristic {trusted} -capture-id 42
DynamicUser=yes
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
'''
            self.unit.write_text(old)
            self.config.unlink(missing_ok=True)
            self.run_install()
            current = self.unit.read_text()
            self.assertIn("-hs collector.example:9060 -i eth9 -m siprtcp -t tcp -profile span -media-policy heuristic", current)
            self.assertIn("-capture-id 42", current)
            self.assertIn("RuntimeDirectory=voxywatch-probe", current)
            if trusted:
                self.assertIn(trusted, current)
            self.unit.write_text(old + "# custom\n")
            self.config.unlink()
            self.run_install(ok=False)
            self.assertEqual(self.unit.read_text(), old + "# custom\n")

    def test_fresh_config_parent_allows_pci_access(self):
        self.config.parent.rmdir()
        self.run_install("--server", "localhost:9060")
        self.assertEqual(self.config.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        suppression = self.config.parent / "pci_suppress.json"
        suppression.write_text('{"suppress_ssrcs":[1]}')
        suppression.chmod(0o644)
        if os.geteuid() == 0:
            # CI container runs as root: prove real access after dropping all groups
            # and UID, rather than trusting a mode-only assertion as root.
            self.root.chmod(0o755)
            result = subprocess.run([
                "python3", "-c",
                "import os,sys; os.setgroups([]); os.setgid(65534); os.setuid(65534); "
                "open(sys.argv[1]).read(); "
                "sys.exit(1 if os.access(sys.argv[2], os.R_OK) else 0)",
                str(suppression), str(self.config),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_private_config_parent_is_not_chmodded(self):
        self.config.parent.chmod(0o700)
        out = self.run_install("--server", "localhost:9060", ok=False)
        self.assertIn("DynamicUser", out)
        self.assertEqual(self.config.parent.stat().st_mode & 0o777, 0o700)
        self.assertFalse(self.bin.exists())


if __name__ == "__main__":
    unittest.main()
