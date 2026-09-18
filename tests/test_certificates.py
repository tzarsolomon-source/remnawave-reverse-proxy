"""Offline regression tests; no system installation, real DNS, or ACME requests.

Run: python3 -m unittest discover -s tests -v
PyYAML is required for the generated Compose checks.
"""
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class CertificatesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="certificates-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.live = self.root / "letsencrypt/live"
        self.live.mkdir(parents=True)
        self.renewal = self.root / "letsencrypt/renewal"
        self.renewal.mkdir()
        self.module = self.root / "certificates.sh"
        source = (ROOT / "src/modules/certificates.sh").read_text()
        source = source.replace("/etc/letsencrypt", str(self.root / "letsencrypt"))
        source = source.replace("$HOME/.secrets", str(self.root / "secrets"))
        source = source.replace("~/.secrets", str(self.root / "secrets"))
        self.module.write_text(source)
        self.prelude = f'''
source {shlex.quote(str(ROOT / 'src/lang/en.sh'))}
source {shlex.quote(str(self.module))}
DIR_REMNAWAVE={shlex.quote(str(self.root / 'hooks'))}/
TEST_ROOT={shlex.quote(str(self.root))}
extract_domain() {{ echo "$1" | awk -F. '{{if (NF>2) print $(NF-1)"."$NF; else print $0}}'; }}
reading() {{ IFS= read -r "$2"; }}
question() {{ printf '%s' "$1"; }}
sleep() {{ :; }}
crontab() {{ return 1; }}
add_cron_rule() {{ printf '%s\\n' "$1" >> "$TEST_ROOT/cron"; }}
remnawave_reverse() {{ :; }}
check_api() {{ return 0; }}
certbot() {{
    if [ "$1" = plugins ]; then
        echo 'dns-bunny dns-gcore dns-cloudflare'
        return 0
    fi
    printf '%s\\0' "$@" >> "$TEST_ROOT/certbot-args"
    printf '\\n' >> "$TEST_ROOT/certbot-calls"
    [ "${{FAIL_CERTBOT:-0}}" = 0 ] || return 42
    local name="" domain="" first_domain=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --cert-name) name="$2"; shift ;;
            -d) domain="$2"; [ -n "$first_domain" ] || first_domain="$domain"; shift ;;
        esac
        shift
    done
    name="${{name:-$first_domain}}"
    mkdir -p "$TEST_ROOT/letsencrypt/live/$name"
    cp "$TEST_ROOT/fixture/fullchain.pem" "$TEST_ROOT/fixture/privkey.pem" "$TEST_ROOT/letsencrypt/live/$name/"
    echo 'authenticator = dns-bunny' > "$TEST_ROOT/letsencrypt/renewal/$name.conf"
}}
'''

    def bash(self, code, input="", expected=0):
        result = subprocess.run(["bash", "-c", self.prelude + "\n" + code],
                                input=input, text=True, capture_output=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result.stdout.strip()

    def fixture(self, *domains):
        folder = self.root / "fixture"
        folder.mkdir(exist_ok=True)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "90", "-subj", "/CN=" + domains[0],
            "-addext", "subjectAltName=" + ",".join("DNS:" + x for x in domains),
            "-keyout", str(folder / "privkey.pem"), "-out", str(folder / "fullchain.pem"),
        ], check=True, capture_output=True)
        return folder

    def existing(self, name, *domains):
        shutil.copytree(self.fixture(*domains), self.live / name)

    def args(self):
        return (self.root / "certbot-args").read_bytes().decode().strip("\0").split("\0")

    def domains(self):
        args = self.args()
        return [args[i + 1] for i, x in enumerate(args) if x == "-d"]

    def test_bunny_single_and_credentials_permissions(self):
        self.fixture("node.example.com")
        self.bash('BUNNY_API_KEY=test-key; get_certificates node.example.com 5 admin@example.com single')
        self.assertEqual(self.domains(), ["node.example.com"])
        self.assertIn("dns-bunny", self.args())
        self.assertIn("--dns-bunny-propagation-seconds", self.args())
        self.assertIn("--email", self.args())
        credentials = self.root / "secrets/certbot/bunny.ini"
        self.assertEqual(credentials.stat().st_mode & 0o777, 0o600)
        self.assertEqual(credentials.read_text(), "dns_bunny_api_key = test-key\n")

    def test_bunny_wildcard_and_no_email(self):
        self.fixture("example.com", "*.example.com")
        self.bash('BUNNY_API_KEY=test-key; get_certificates node.example.com 5 "" wildcard', input="example.com\n")
        self.assertEqual(self.domains(), ["example.com", "*.example.com"])
        self.assertIn("--register-unsafely-without-email", self.args())
        self.assertEqual(self.bash('resolve_certificate_domain node.example.com'), "example.com")

    def test_wildcard_public_suffix_and_subzone(self):
        self.fixture("example.co.uk", "*.example.co.uk")
        self.bash('BUNNY_API_KEY=test-key; get_certificates node.example.co.uk 5 "" wildcard', input="\n")
        self.assertEqual(self.domains(), ["example.co.uk", "*.example.co.uk"])
        self.assertEqual(self.bash('resolve_certificate_domain node.example.co.uk'), "example.co.uk")

    def test_explicit_wildcard_keeps_full_base(self):
        self.fixture("vpn.example.com", "*.vpn.example.com")
        self.bash('BUNNY_API_KEY=test-key; get_certificates "*.vpn.example.com" 5 "" wildcard', input="\n")
        self.assertEqual(self.domains(), ["vpn.example.com", "*.vpn.example.com"])

    def test_failed_acme_is_not_hidden_by_existing_certificate(self):
        self.existing("node.example.com", "node.example.com")
        self.bash('BUNNY_API_KEY=test-key; FAIL_CERTBOT=1; get_certificates node.example.com 5 "" single', expected=1)

    def test_cloudflare_and_gcore_preserved(self):
        for method in (1, 3):
            with self.subTest(method=method):
                self.fixture("example.com", "*.example.com")
                (self.root / "certbot-args").unlink(missing_ok=True)
                self.bash(f'CLOUDFLARE_API_KEY=TEST; GCORE_API_KEY=test; get_certificates node.example.com {method} ""')
                self.assertEqual(self.domains(), ["example.com", "*.example.com"])
                self.assertIn("--dns-cloudflare" if method == 1 else "dns-gcore", self.args())

    def test_resolver_suffix_exact_precedence_and_missing_key(self):
        self.existing("example.com", "example.com", "*.example.com")
        self.existing("node.example.com-0001", "node.example.com")
        self.existing("node.example.com.evil.test", "node.example.com")
        self.assertEqual(self.bash('resolve_certificate_domain node.example.com'), "node.example.com-0001")
        (self.live / "node.example.com-0001/privkey.pem").unlink()
        self.assertEqual(self.bash('resolve_certificate_domain node.example.com'), "example.com")
        self.bash('resolve_certificate_domain deep.node.example.com', expected=1)
        self.bash('resolve_certificate_domain other.test', expected=1)

    def test_install_menu_deduplicates_wildcard_and_writes_mounts(self):
        self.fixture("example.com", "*.example.com")
        self.bash('''
            declare -A domains=([node.example.com]=1 [panel.example.com]=1)
            handle_certificates domains "" "" "$TEST_ROOT"
        ''', input="5\n\n2\ntest-key\nexample.com\n")
        self.assertEqual((self.root / "certbot-calls").read_text().count("\n"), 1)
        compose = (self.root / "docker-compose.yml").read_text()
        self.assertEqual(sum("fullchain.pem:" in line for line in compose.splitlines()), 1)
        self.assertIn("/live/example.com/fullchain.pem:", compose)
        self.assertTrue((self.renewal / "example.com.conf").read_text().endswith('certbot-hooks.sh deploy\n'))

    def test_generation_menu_single(self):
        self.fixture("node.example.com")
        self.bash('generate_new_certificates', input="node.example.com\n5\n1\n\ntest-key\n")
        self.assertEqual(self.domains(), ["node.example.com"])

    def test_mixed_existing_lineages_and_no_caddy_nginx_mounts(self):
        self.existing("node.example.com-0001", "node.example.com")
        self.existing("other.test", "other.test", "*.other.test")
        self.bash('''
            declare -A domains=([node.example.com]=1 [panel.other.test]=1)
            handle_certificates domains "" "" "$TEST_ROOT"
        ''')
        compose = (self.root / "docker-compose.yml").read_text()
        self.assertIn("/live/node.example.com-0001/fullchain.pem:", compose)
        self.assertIn("/live/other.test/fullchain.pem:", compose)
        (self.root / "docker-compose.yml").unlink()
        self.bash('''
            declare -A domains=([node.example.com]=1)
            handle_certificates domains "" "" "$TEST_ROOT" false
        ''')
        self.assertFalse((self.root / "docker-compose.yml").exists())

    def test_renewal_hooks_and_generated_script(self):
        for authenticator in ("dns-bunny", "standalone"):
            conf = self.renewal / (authenticator + ".conf")
            conf.write_text(f"authenticator = {authenticator}\ndeploy_hook = obsolete\n")
            self.bash(f'configure_certbot_renewal_hooks {shlex.quote(str(conf))}')
            text = conf.read_text()
            self.assertNotIn("obsolete", text)
            self.assertEqual(text.count("deploy_hook ="), 1)
            self.assertEqual("pre_hook =" in text, authenticator == "standalone")
            self.assertEqual("post_hook =" in text, authenticator == "standalone")
        hook = self.root / "hooks/certbot-hooks.sh"
        subprocess.run(["bash", "-n", str(hook)], check=True)
        self.assertIn("remnanode", hook.read_text())
        self.assertIn("caddy-remnawave", hook.read_text())

    def test_renewal_hook_restarts_node_and_restores_running_proxies(self):
        self.bash('install_certbot_hook_script')
        hook = self.root / "hooks/certbot-hooks.sh"
        docker = self.root / "docker"
        docker.write_text(f'''#!/bin/bash
printf '%s\\n' "$*" >> {shlex.quote(str(self.root / 'docker-log'))}
if [ "$1" = ps ]; then
    echo remnawave-nginx
    echo caddy-remnawave
    [[ "$*" != *remnanode* ]] || echo remnanode
fi
exit 0
''')
        docker.chmod(0o700)
        ufw = self.root / "ufw"
        ufw.write_text('''#!/bin/bash
if [ "$1" = status ]; then
    echo 'Status: active'
    echo '80/tcp ALLOW Anywhere'
else
    exit 99
fi
''')
        ufw.chmod(0o700)
        hook.write_text(hook.read_text().replace('/usr/bin/docker', str(docker))
                        .replace('/run/remnawave-certbot', str(self.root / 'state'))
                        .replace('ufw', str(ufw)))
        self.bash(f'"{hook}" pre && "{hook}" pre && "{hook}" post && "{hook}" deploy')
        log = (self.root / 'docker-log').read_text().splitlines()
        self.assertEqual(log.count('stop remnawave-nginx caddy-remnawave'), 1)
        self.assertIn('start remnawave-nginx caddy-remnawave', log)
        self.assertIn('restart remnawave-nginx caddy-remnawave remnanode', log)
        self.assertFalse((self.root / 'state/containers').exists())

    def test_plugin_install_failure_aborts_issuance(self):
        self.bash('''
            certbot() { return 1; }
            python3() { return 1; }
            BUNNY_API_KEY=test-key
            get_certificates node.example.com 5 "" single
        ''', expected=1)
        self.assertFalse((self.root / 'certbot-args').exists())

    def test_all_node_compose_templates(self):
        for server in ("nginx", "caddy"):
            for install in ("install_node.sh", "install_panel_node.sh"):
                with self.subTest(server=server, install=install):
                    source = (ROOT / "src" / server / install).read_text()
                    blocks = re.findall(r'^\s*cat (?:>|>>) [^\n]*docker-compose\.yml <<EOL\n(.*?)^EOL$', source, re.M | re.S)
                    self.assertTrue(blocks)
                    body = "\n".join(blocks)
                    rendered = self.bash('''
                        NODE_CERT_DOMAIN=example.com-0001
                        CERTIFICATE=test-secret
                        SELFSTEAL_DOMAIN=node.example.com
                        PANEL_DOMAIN=panel.example.com
                        SUB_DOMAIN=sub.example.com
                        CADDY_IMAGE=caddy:test
                        cat <<EOL
                    '''.rstrip() + "\n" + body + "\nEOL\n")
                    config = yaml.safe_load(rendered)
                    mounts = config["services"]["remnanode"]["volumes"]
                    self.assertIn('/etc/letsencrypt/live/example.com-0001/fullchain.pem:/ssl/fullchain.pem:ro', mounts)
                    self.assertIn('/etc/letsencrypt/live/example.com-0001/privkey.pem:/ssl/privkey.pem:ro', mounts)
                    self.assertIn('/dev/shm:/dev/shm:rw', mounts)
                    self.assertIn('/var/log/remnanode:/var/log/remnanode', mounts)
                    if server == 'caddy':
                        self.assertIn('tls /ssl/fullchain.pem /ssl/privkey.pem', source)


if __name__ == "__main__":
    unittest.main()
