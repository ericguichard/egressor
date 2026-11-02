#!/usr/bin/env python3
"""
Golden-file tests for render.py.

How this works:
  1. Monkey-patch render.py's file-path globals to point at tests/fixtures/
     (profiles.yaml, .secrets.yaml, home_wg/, hy2.crt). This is how we
     run the full render pipeline without touching production state and
     without adding a --manifest-path flag to render.py itself.
  2. Call render.load_manifest() + render.compose() for each user/device,
     emit_json the result, and compare byte-for-byte against the matching
     tests/goldens/<user>-<device>.json.
  3. A mismatch prints a unified diff and fails with exit 1.
  4. Pass `--update` (or UPDATE_GOLDENS=1) to overwrite goldens with the
     fresh output — use this deliberately after intentional changes, then
     eyeball the git diff of tests/goldens/.

Why not pytest: stdlib-only keeps this test suite runnable on any fresh
checkout of the repo without `pip install`. The tradeoffs are lost
fixtures/parametrize ergonomics and no colored output, both minor for a
single-file harness.

Run directly:
    ./tests/test_render.py           # assert against goldens
    ./tests/test_render.py --update  # regenerate goldens

Exit codes: 0 = all pass, 1 = one or more mismatches, 2 = harness error.
"""
import json
import difflib
import importlib.util
import os
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).parent.resolve()
FIXTURES = TESTS_DIR / 'fixtures'
GOLDENS = TESTS_DIR / 'goldens'
RENDER_PY = TESTS_DIR.parent / 'render.py'


def _load_render_module():
    """
    Import render.py as a module and overwrite its file-path globals so
    it reads from the fixture dir instead of production. Must happen
    BEFORE any render.* function is called.
    """
    spec = importlib.util.spec_from_file_location('render', RENDER_PY)
    render = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(render)

    # These constants drive every file read in render.py. Overriding them
    # after import is enough — no module-level I/O happens at import time.
    render.ROOT = FIXTURES
    render.MANIFEST = FIXTURES / 'profiles.yaml'
    render.SECRETS = FIXTURES / '.secrets.yaml'
    render.HOME_WG_DIR = FIXTURES / 'home_wg'
    render.EXIT_WG_DIR = FIXTURES / 'exit_wg'
    render.HY2_CERT = FIXTURES / 'hy2.crt'
    render.HY2_NEXT_CERT = FIXTURES / 'hy2-next.crt'
    # AWG paths: the client template lives in the real templates/ dir
    # (read-only), but the awg-server stub path is rebased under FIXTURES so
    # the stub-emission test path doesn't write into the real awg-server/
    # location. Tests assert against the stub's *content*, not its filesystem
    # location, so a fixtures-relative path works for the comparison without
    # mutating the live repo layout.
    render.AWG_SERVER_DIR = FIXTURES / 'awg-server'
    render.AWG_SERVER_CONFIG = FIXTURES / 'awg-server' / 'config' / 'awg0.conf'
    # AWG_CLIENT_TEMPLATE stays at the real location (read-only template,
    # part of the renderer's static assets — not fixture-dependent).
    # Pin PROFILE_HOST to the sanitized placeholder so goldens are HERMETIC and
    # portable: PROFILE_HOST resolves from the repo-level .env (the deployment
    # host sets it to the real private hostname), and anything that embeds it in
    # a rendered file (the installers do; until 2026-10-04 a config-fetch route
    # rule did too) would otherwise carry the real name — without this pin,
    # regenerating goldens on the deploy host would bake the real hostname into
    # the public repo (a leak) and break the suite for clean checkouts.
    render.PROFILE_HOST = 'profile.example.com'

    return render


def _render_all(render):
    """
    Render every output the renderer produces from the fixture manifest.
    Returns a dict {'<filename>': '<file-contents>'} — the key is the full
    filename including extension so .json (sing-box configs) and .conf
    (AWG client + awg-server stub) co-exist in one map. _compare() looks
    each one up under the same name in tests/goldens/.
    Uses -y-equivalent: auto_yes=True prevents prompting, but we also
    patch save_secrets to a no-op so the test run never mutates the
    fixture .secrets.yaml.
    """
    render.save_secrets = lambda data: None  # defensive: fixtures are read-only

    manifest = render.load_manifest(auto_yes=True)
    out = {}
    for uname, user in manifest['users'].items():
        user.setdefault('_name', uname)
        for dev in user['devices']:
            cfg = render.compose(user, dev, manifest['defaults'])
            out[f'{uname}-{dev["name"]}.json'] = render.emit_json(cfg)

            # Per-protocol single-outbound profiles for mobile devices —
            # mirrors compute_client_plan's emission so the goldens cover
            # both the unified config and the alternate-client fallback
            # files. Skipped for single-protocol users (would duplicate
            # the unified file byte-for-byte).
            if dev['type'] == 'mobile':
                solo_tags = render.protocol_outbound_tags(user.get('protocols', []))
                if len(solo_tags) >= 2:
                    for proto in solo_tags:
                        solo_user = dict(user)
                        # Same sentinel the production emitter uses; keeps
                        # the Trusted-domains gate firing on solo files
                        # rendered from multi-protocol users.
                        solo_user['_original_protocols'] = list(user['protocols'])
                        solo_user['protocols'] = [proto]
                        solo_cfg = render.compose(solo_user, dev, manifest['defaults'])
                        out[f'{uname}-{dev["name"]}-{proto}.json'] = render.emit_json(solo_cfg)

    # AWG outputs: per-device awg-<dev>.conf + awg-server config. AWG
    # identities are per-device (post-2026-04-27); each device has its own
    # keypair, /32 address, and [Peer] block. Only emitted when at least
    # one user has 'awg' in protocols, so non-AWG fixture runs produce
    # nothing here and existing goldens stay clean.
    awg_state = manifest.get('_awg')
    if awg_state:
        for uname, user in manifest['users'].items():
            if 'awg' not in user.get('protocols', []):
                continue
            for dev in user['devices']:
                text = render._render_awg_client_conf(
                    uname,
                    dev['name'],
                    dev,
                    awg_state['block'],
                    awg_state['addresses'][uname][dev['name']],
                )
                out[f'{uname}-{dev["name"]}-awg.conf'] = text
        out['awg-server.conf'] = render._render_awg_server_config(manifest, awg_state)

    return out


def _compare(rendered, update):
    """
    Diff rendered output vs goldens. Return (passes, fails) counts.
    When `update=True`, overwrite goldens instead of failing.

    Keys in `rendered` are full filenames (e.g. test_alice-pixel.json,
    test_dave-awg.conf). Goldens live at tests/goldens/<filename>. The
    extension differentiates sing-box JSON outputs from AWG wg-quick .conf
    outputs without forcing two parallel comparison loops.
    """
    passes = fails = 0
    GOLDENS.mkdir(exist_ok=True)

    # Orphan goldens (a file present in tests/goldens/ that no rendered
    # output matches) signal renamed/removed devices or a fixture user that
    # dropped a protocol. Reported but don't fail the run — the reporter
    # spots them so the operator can clean them up explicitly.
    existing_goldens = {p.name for p in GOLDENS.glob('*') if p.is_file()}
    rendered_keys = set(rendered.keys())
    orphans = existing_goldens - rendered_keys

    for key in sorted(rendered.keys()):
        golden = GOLDENS / key
        new = rendered[key]
        if update:
            golden.write_text(new)
            print(f'  ✎ wrote {golden.name}')
            passes += 1
            continue
        if not golden.exists():
            print(f'  ✗ {key}: NO GOLDEN (run with --update to create)')
            fails += 1
            continue
        old = golden.read_text()
        if old == new:
            print(f'  ✓ {key}')
            passes += 1
        else:
            print(f'  ✗ {key}: rendered output differs from golden')
            diff = difflib.unified_diff(
                old.splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile=f'goldens/{key}',
                tofile=f'rendered/{key}',
                n=3,
            )
            sys.stdout.writelines(diff)
            fails += 1

    for orphan in sorted(orphans):
        print(f'  ⚠ orphan golden: {orphan} (no matching output in fixtures)')

    return passes, fails


def _test_x25519_derivation(render):
    """
    Unit test: render._x25519_public_from_private must produce the canonical
    WG public key for a known private key. Uses the WireGuard upstream test
    vector (RFC-7748 / wg's `tools/embedded-test/test-key`) so a regression
    in the cryptography lib or a parameter mishap in render.py shows up
    immediately rather than at handshake-fail time on a real client.

    Vector source: cryptography library's own test suite + RFC-7748 test
    vectors. Private key 0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    (base64 d3B20Kcxi...) -> public 0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a.
    """
    import base64
    priv_b = bytes.fromhex(
        '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
    )
    expected_pub_b = bytes.fromhex(
        '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
    )
    priv_b64 = base64.b64encode(priv_b).decode()
    got_pub = render._x25519_public_from_private(priv_b64)
    expected_pub = base64.b64encode(expected_pub_b).decode()
    if got_pub == expected_pub:
        print('  ✓ x25519-derivation: matches RFC-7748 test vector')
        return 1, 0
    print(f'  ✗ x25519-derivation: expected {expected_pub!r}, got {got_pub!r}')
    return 0, 1


def _test_awg_negative(render):
    """
    Negative test: an AWG-enabled device with no `awg_private_key` under
    .secrets.yaml.users.<n>.devices.<dev> must cause _validate_awg_block
    to exit with a message that names both the field and the offending
    user/device. Uses the validation function directly with a synthetic
    minimal manifest + sfile, so it doesn't need its own fixture tree on
    disk and doesn't pollute the goldens.

    Returns (passed, failed) — printed as a single line by main().
    """
    awg_block = {
        'subnet': '10.66.66.0/24', 'port': 51820,
        'endpoint_host': 'vpn.example.com',
        'server_private_key': 'X', 'server_public_key': 'Y',
        'Jc': 8, 'Jmin': 40, 'Jmax': 80, 'S1': 75, 'S2': 110,
        'H1': 1, 'H2': 2, 'H3': 3, 'H4': 4,
    }
    # Device exists in profiles.yaml but its slot in .secrets.yaml is empty —
    # _autogen_missing would normally fill this in; the validator is the last
    # line of defence if autogen was bypassed (e.g. an operator hand-edit).
    sfile = {'users': {'someone': {'devices': {'phone': {}}}}}
    manifest = {
        'users': {
            'someone': {
                'protocols': ['awg'],
                'devices': [{'type': 'mobile', 'name': 'phone'}],
            }
        }
    }
    try:
        render._validate_awg_block(awg_block, sfile, manifest)
    except SystemExit as e:
        msg = str(e)
        if 'awg_private_key' in msg and 'someone/phone' in msg:
            print('  ✓ awg-negative: missing per-device awg_private_key fails loud')
            return 1, 0
        print(f'  ✗ awg-negative: SystemExit message did not mention '
              f'awg_private_key + the offending uname/dev: {msg!r}')
        return 0, 1
    print('  ✗ awg-negative: validation did NOT exit when awg_private_key '
          'was missing — regression of the per-device hard check')
    return 0, 1


def _test_home_endpoint_bootstrap_dns(render):
    """
    The home WG peer hostname MUST resolve via bootstrap_dns, and that rule
    must come before the A/AAAA→fakeip rule.

    Why this is a hard requirement and not a preference: sing-box treats WG
    peer-domain resolution as a post-start dependency, so a hostname it cannot
    resolve aborts the WHOLE service (`FATAL start service: post-start
    endpoint/wireguard[...]: resolve endpoint domain for peer[0]`), and the
    supervisor then crash-loops it. Resolving it through cloudflare_doh (the
    pre-2026-07-20 shape) fails on any network that blackholes DoH, and is not
    guaranteed to have a usable proxy that early in startup. If it ever falls
    back to fakeip, the handshake UDP loops into the TUN instead of leaving.

    Returns (passed, failed) — printed as a single line by main().
    """
    host = 'home.example.test'
    # countries=[] keeps this independent of which country packs are loaded;
    # has_home=True is what gates the home-endpoint DNS handling under test.
    dns = render.frag_dns([], has_home=True, home_endpoint=host)['dns']
    rules = dns['rules']

    def idx(pred):
        return next((i for i, r in enumerate(rules) if pred(r)), None)

    boot = idx(lambda r: r.get('server') == 'bootstrap_dns' and host in (r.get('domain') or []))
    fake = idx(lambda r: r.get('server') == 'fakeip-server')
    doh = idx(lambda r: r.get('server') == 'cloudflare_doh' and host in (r.get('domain') or []))

    if boot is None:
        print(f'  ✗ home-bootstrap-dns: {host} is not routed to bootstrap_dns — '
              f'a restart on a DoH-blocked network will FATAL the service')
        return 0, 1
    if doh is not None:
        print(f'  ✗ home-bootstrap-dns: {host} still has a cloudflare_doh rule '
              f'(regression to the shape that crash-looped a client)')
        return 0, 1
    if fake is not None and boot > fake:
        print(f'  ✗ home-bootstrap-dns: bootstrap rule (idx {boot}) comes AFTER '
              f'the fakeip rule (idx {fake}) — WG handshake would loop into the TUN')
        return 0, 1

    print('  ✓ home-bootstrap-dns: home WG peer resolves via bootstrap_dns, ahead of fakeip')
    return 1, 0


def _test_device_filename_scheme(render):
    """
    Unit test: device_filename must key on USER + device TYPE, never the
    device's model name. The whole reason for the egressor-<user>-<type>
    scheme is that a hardware swap under the same user+type (e.g. the
    pixel9 -> motorola migration) then yields an IDENTICAL served filename,
    so a device's saved subscription URL never orphans — the outage a
    model-based name (singbox-<model>.json) caused when the model changed.
    Guard that property here so a future refactor can't silently regress it.

    Returns (passed, failed) — printed as a single line by main().
    """
    p = f = 0
    cases = [
        (('bob', {'type': 'mobile', 'name': 'iphone'}), 'egressor-bob-mobile.json'),
        (('dave', {'type': 'windows', 'name': 'pc'}), 'egressor-dave-windows.json'),
        (('alice', {'type': 'mac', 'name': 'macbook'}), 'egressor-alice-mac.json'),
        (('dave', {'type': 'linux', 'name': 'workstation'}), 'egressor-dave-linux.json'),
    ]
    for (uname, dev), want in cases:
        got = render.device_filename(uname, dev)
        if got == want:
            p += 1
            print(f'  ✓ device_filename: {uname}/{dev["type"]} -> {want}')
        else:
            f += 1
            print(f'  ✗ device_filename: {uname}/{dev["type"]} expected {want!r}, got {got!r}')
    # AWG names: long primary + the short import alias that must stay within
    # the WireGuard/AmneziaWG 15-char tunnel-name cap (the apps derive the
    # tunnel name from the filename and reject longer ones as "invalid name").
    awg_cases = [
        (('bob', {'type': 'mobile', 'name': 'iphone'}),
         'egressor-bob-mobile-awg.conf', 'bob-mobile.conf'),
        (('charlie', {'type': 'windows', 'name': 'pc'}),   # stem = exactly 15
         'egressor-charlie-windows-awg.conf', 'charlie-windows.conf'),
        (('charlie', {'type': 'linux', 'name': 'desktop'}),
         'egressor-charlie-linux-awg.conf', 'charlie-linux.conf'),
    ]
    for (uname, dev), want_long, want_short in awg_cases:
        got_long = render.awg_filename(uname, dev)
        got_short = render.awg_short_filename(uname, dev)
        stem_ok = len(want_short[:-len('.conf')]) <= render.AWG_TUNNEL_NAME_MAX
        if got_long == want_long and got_short == want_short and stem_ok:
            p += 1
            print(f'  ✓ awg filenames: {uname}/{dev["type"]} -> {want_long} + {want_short}')
        else:
            f += 1
            print(f'  ✗ awg filenames: {uname}/{dev["type"]} got {got_long!r} / {got_short!r}')
    # Over-cap stem must fail loud, not serve an unimportable file.
    try:
        render.awg_short_filename('christopher', {'type': 'windows', 'name': 'pc'})
        f += 1
        print('  ✗ awg short name: 19-char stem did NOT exit')
    except SystemExit as e:
        if 'tunnel name' in str(e):
            p += 1
            print('  ✓ awg short name: over-cap stem fails loud')
        else:
            f += 1
            print(f'  ✗ awg short name: unexpected SystemExit message {e!r}')
    # Model-swap stability: same user+type, different model -> same filename.
    a = render.device_filename('alice', {'type': 'mobile', 'name': 'pixel'})
    b = render.device_filename('alice', {'type': 'mobile', 'name': 'newphone'})
    if a == b:
        p += 1
        print('  ✓ device_filename: model swap keeps served filename stable (no orphan)')
    else:
        f += 1
        print(f'  ✗ device_filename: model swap changed the name ({a!r} != {b!r})')
    return p, f


def _test_endpoint_detour_not_selector(rendered):
    """
    Every wireguard endpoint's `detour` must name a CONCRETE outbound, never a
    selector. sing-box 1.14 refuses to resolve a selector tag as an endpoint
    detour and fails the endpoint at RUNTIME ("outbound detour not found"), so
    the tunnel silently carries nothing. 1.13.x accepts it, and `sing-box
    check` passes on both — which is exactly how the '🚇 Home Carrier' selector
    detour shipped and left home egress dead on every 1.14 client until
    2026-07-20.

    Goldens alone do NOT cover this: they happily encoded the broken value for
    months. This asserts the invariant directly.
    """
    bad = []
    checked = 0
    for name, cfg in rendered.items():
        # _render_all stores emit_json() text; AWG .conf entries are not JSON.
        if isinstance(cfg, str):
            if not name.endswith('.json'):
                continue
            cfg = json.loads(cfg)
        checked += 1
        selector_tags = {
            o.get('tag') for o in cfg.get('outbounds', [])
            if o.get('type') in ('selector', 'urltest')
        }
        for ep in cfg.get('endpoints', []):
            detour = ep.get('detour')
            if detour and detour in selector_tags:
                bad.append(f'{name}: endpoint {ep.get("tag")!r} '
                           f'detours to selector {detour!r}')
    if bad:
        for b in bad:
            print(f'  ✗ endpoint-detour: {b}')
        return 0, 1
    if not checked:
        print('  ✗ endpoint-detour: no JSON configs inspected (vacuous)')
        return 0, 1
    print(f'  ✓ endpoint-detour: no endpoint detours to a selector/urltest ({checked} configs)')
    return 1, 0


def _test_core_min_gate(render, rendered):
    """
    1.14-only fields must reach exactly the devices whose core floor is 1.14+.
    sing-box 1.13 fails to decode a config carrying `http_clients` or
    `route.default_http_client` ("unknown field"), so one of them leaking into
    a 1.13 device's file takes that client down at its next config fetch.
    Fixture floors: mobile defaults to 1.14, desktops to 1.13, and the linux
    workstation raises itself with `core_min: '1.14'`. Per-protocol solo files
    are for alternate clients with an unknown core, so they stay on 1.13.
    """
    p = f = 0

    def check(cond, label):
        nonlocal p, f
        if cond:
            p += 1
        else:
            f += 1
            print(f'  ✗ core_min gate: {label}')

    check(render.core_at_least({'type': 'mobile'}, '1.14'), 'mobile defaults to 1.14')
    check(not render.core_at_least({'type': 'windows'}, '1.14'), 'windows defaults to 1.13')
    check(not render.core_at_least({'type': 'mobile', 'core_min': '1.13'}, '1.14'),
          'core_min lowers a mobile device')
    check(render.core_at_least({'type': 'mac', 'core_min': '1.15'}, '1.14'),
          'core_min raises a desktop device')
    check(not render.core_at_least({'type': 'mac', 'core_min': '1.9'}, '1.14'),
          'minor versions compare numerically (1.9 < 1.14)')

    floor_113 = ('-laptop.json', '-macbook.json', '-pc.json',
                 '-reality.json', '-ws-cf.json', '-shadowtls.json', '-hy2.json')
    seen = {True: 0, False: 0}
    for name, cfg in rendered.items():
        if not name.endswith('.json'):
            continue
        if isinstance(cfg, str):
            cfg = json.loads(cfg)
        want = not name.endswith(floor_113)
        clients = [c.get('tag') for c in cfg.get('http_clients', [])]
        default = cfg['route'].get('default_http_client')
        got = bool(clients) or default is not None
        seen[want] += 1
        check(got == want, f'{name}: 1.14 HTTP client fields '
                           f'{"missing" if want else "present on a 1.13 device"}')
        if want and got:
            check(default in clients, f'{name}: default_http_client {default!r} not declared')
            check(cfg['http_clients'][0].get('detour') == cfg['route']['final'],
                  f'{name}: rule-set fetch must follow route.final')
    check(seen[True] and seen[False], 'fixtures cover both a 1.13 and a 1.14 device')
    if not f:
        print(f'  ✓ core_min gate: 1.14 fields only on 1.14+ devices ({p} checks)')
    return p, f


def _test_per_core_check(render):
    """
    check_client_plan must send every sing-box JSON to the first release of
    its OWN floor and to the current release, and report what an image
    rejects. The images are faked (fixtures carry placeholder keys no real
    `sing-box check` accepts): the fake 1.13 rejects any config carrying a
    1.14-only field, which is what the real 1.13 does.
    """
    p = f = 0

    def check(cond, label):
        nonlocal p, f
        if cond:
            p += 1
        else:
            f += 1
            print(f'  ✗ per-core check: {label}')

    manifest = render.load_manifest(auto_yes=True)
    # AWG files carry no floor, and the fixture's deliberately over-long AWG
    # alias (see _test_device_filename_scheme) aborts a full plan: plan
    # without AWG.
    manifest['_awg'] = None
    for user in manifest['users'].values():
        user['protocols'] = [x for x in user['protocols'] if x != 'awg']
    plan = render.compute_client_plan(manifest)
    floors = manifest['_core_floors']
    by_name = {path.name: floor for path, floor in floors.items()}
    check(by_name.get('egressor-test_alice-mobile.json') == '1.14', 'mobile file floor is 1.14')
    check(by_name.get('egressor-test_alice-mobile-hy2.json') == '1.13', 'solo file floor is 1.13')
    check(by_name.get('egressor-test_alice-windows.json') == '1.13', 'windows file floor is 1.13')
    check(by_name.get('egressor-test_dave-linux.json') == '1.14', 'core_min raises the linux file floor')
    check(not any(n.endswith('.conf') or n == 'README.md' for n in by_name),
          'only sing-box JSON files carry a floor')

    calls = {}

    def fake_batch(image, texts):
        calls[image] = set(texts)
        if image.endswith(':v1.13.0'):
            return {k: 'unknown field' for k, v in texts.items() if '"http_clients"' in v}, None
        return {}, None

    real_batch, real_emits = render._check_batch, render.emits
    render._check_batch = fake_batch
    try:
        failures, unavailable = render.check_client_plan(manifest, plan)
        check(not failures and not unavailable, f'gated render passes ({failures[:1]})')
        repo, cur = render.CORE_CHECK_REPO, render.CORE_CHECK_CURRENT
        check(set(calls) == {f'{repo}:v1.13.0', f'{repo}:v1.14.0', cur}, f'images used: {sorted(calls)}')
        check(calls.get(cur) == set(floors), 'every file is checked on the current release')
        check(calls.get(f'{repo}:v1.13.0') == {q for q, fl in floors.items() if fl == '1.13'},
              '1.13-floor files, and only those, go to the 1.13 image')
        check(calls.get(f'{repo}:v1.14.0') == {q for q, fl in floors.items() if fl == '1.14'},
              '1.14-floor files, and only those, go to the 1.14 image')

        calls.clear()
        unchanged = [(q, text, 'unchanged', u) for q, text, _, u in plan]
        render.check_client_plan(manifest, unchanged, only_changed=True)
        check(not calls, 'only_changed skips unchanged files')

        # A 1.14 field emitted without its gate: every 1.13-floor file fails.
        render.emits = lambda user, device, version: True
        ungated = render.compute_client_plan(manifest)
        failures, _ = render.check_client_plan(manifest, ungated)
        want = {q for q, fl in manifest['_core_floors'].items() if fl == '1.13'}
        check({q for q, _, _ in failures} == want and want, 'an ungated 1.14 field fails on every 1.13-floor file')

        render._check_batch = lambda image, texts: ({}, 'docker not found')
        failures, unavailable = render.check_client_plan(manifest, plan)
        check(not failures and len(unavailable) == 3, 'an image that cannot run is reported, not a failure')
    finally:
        render._check_batch, render.emits = real_batch, real_emits
    if not f:
        print(f'  ✓ per-core check: floor + current image per file ({p} checks)')
    return p, f


def _test_hy2_key_pins(render, rendered):
    """
    hy2 clients pin the server cert by public-key hash, current key first and
    the next rotation's key second, so a rotation needs no flag day. Asserts
    the hash is the one `openssl` computes (the value sing-box compares), that
    every rendered hy2 outbound carries both pins and no inlined PEM, and the
    two degraded forms: no next cert yet (one pin), and a core older than 1.13
    (PEM fallback, the field does not exist there).
    """
    import subprocess
    p = f = 0

    def check(cond, label):
        nonlocal p, f
        if cond:
            p += 1
        else:
            f += 1
            print(f'  ✗ hy2 key pins: {label}')

    def openssl_pin(path):
        pub = subprocess.run(['openssl', 'x509', '-in', str(path), '-pubkey', '-noout'],
                             capture_output=True, check=True).stdout
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'der'],
                             input=pub, capture_output=True, check=True).stdout
        dgst = subprocess.run(['openssl', 'dgst', '-sha256', '-binary'],
                              input=der, capture_output=True, check=True).stdout
        return subprocess.run(['openssl', 'enc', '-base64'],
                              input=dgst, capture_output=True, check=True).stdout.decode().strip()

    cur, nxt = render.HY2_CERT, render.HY2_NEXT_CERT
    try:
        check(render.cert_public_key_sha256(cur) == openssl_pin(cur), 'hash differs from openssl (current)')
        check(render.cert_public_key_sha256(nxt) == openssl_pin(nxt), 'hash differs from openssl (next)')
    except FileNotFoundError:
        print('  (openssl not installed: hash cross-check skipped)')
    want = [render.cert_public_key_sha256(cur), render.cert_public_key_sha256(nxt)]
    check(want[0] != want[1], 'fixture certs must carry two different keys')
    check(render.hy2_pins() == want, 'hy2_pins = [current, next]')

    seen = 0
    for name, cfg in rendered.items():
        if not name.endswith('.json'):
            continue
        if isinstance(cfg, str):
            cfg = json.loads(cfg)
        for o in cfg.get('outbounds', []):
            if o.get('type') != 'hysteria2':
                continue
            seen += 1
            check(o['tls'].get('certificate_public_key_sha256') == want, f'{name}: pins {o["tls"].get("certificate_public_key_sha256")}')
            check('certificate' not in o['tls'], f'{name}: PEM still inlined')
    check(seen > 0, 'no hy2 outbound in the fixtures')

    render.HY2_NEXT_CERT = FIXTURES / 'no-such-next.crt'
    try:
        check(render.hy2_pins() == want[:1], 'without a next cert: the current pin only')
    finally:
        render.HY2_NEXT_CERT = nxt
    defaults = {'hy2': {'sni': 'cloud.example.com', 'obfs_salamander_password': 'x', 'server_port': 443},
                'reality': {'server': '198.51.100.10'}}
    old = render.frag_outbound_hy2(defaults, 'pw', pin_key=False)['tls']
    check('certificate_public_key_sha256' not in old and old.get('certificate', [''])[0].startswith('-----BEGIN'),
          'pin_key=False falls back to the inlined PEM')
    if not f:
        print(f'  ✓ hy2 key pins: current + next public-key hash, no PEM ({p} checks)')
    return p, f


def _test_reality_alternating(render):
    """
    Unit test for the alternating Reality keypair rotation:
      - reality_client_server() dials `server` on endpoint a, `server_b` on b,
        and refuses b when server_b is missing (never silently dials A);
      - _reality_retiring_live() honours expires_at;
      - _reality_server_parts() puts the active inbound on the endpoint's
        listen IP and emits the retiring inbound (previous key, other
        endpoint, same users/short_ids) only while its window is open, as a
        fragment that keeps the template valid JSON.
    TEST-NET addresses only; no env file is read (host_env is passed in and
    _read_env is stubbed).
    """
    import datetime
    ok = fail = 0

    def check(cond, label):
        nonlocal ok, fail
        if cond:
            ok += 1
        else:
            fail += 1
            print(f'  ✗ reality-alternating: {label}')

    base = {'server': '192.0.2.10', 'server_b': '198.51.100.20',
            'handshake_sni': 'cover.example.com', 'private_key': 'ACTIVE'}
    check(render.reality_client_server(dict(base)) == '192.0.2.10', 'endpoint a dials server')
    check(render.reality_client_server(dict(base, endpoint='b')) == '198.51.100.20', 'endpoint b dials server_b')
    try:
        render.reality_client_server({'server': '192.0.2.10', 'endpoint': 'b'})
        check(False, 'endpoint b without server_b must exit')
    except SystemExit:
        check(True, '')

    now = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
    check(not render._reality_retiring_live(None, now), 'no retiring key is not live')
    check(render._reality_retiring_live({'expires_at': '2030-01-02T00:00:00Z'}, now), 'future expiry is live')
    check(not render._reality_retiring_live({'expires_at': '2029-12-31T00:00:00Z'}, now), 'past expiry is not live')

    view = {'reality_users': [{'name': 'u-d', 'uuid': '00000000-0000-4000-8000-000000000000',
                               'flow': 'xtls-rprx-vision'}],
            'reality_short_ids': ['0123456789abcdef']}
    host_env = {'INCOMING_IP_1': '10.0.0.10'}
    real_read_env = render._read_env
    render._read_env = lambda keys: {'INCOMING_IP_2': '10.0.0.11'}
    try:
        listen, frag = render._reality_server_parts(view, {'reality': dict(base)}, host_env)
        check(listen == '10.0.0.10' and frag == '', 'endpoint a, no retiring: listen A, no extra inbound')

        far = '2999-01-01T00:00:00Z'
        d = dict(base, endpoint='b', retiring={'private_key': 'PREVIOUS', 'expires_at': far})
        listen, frag = render._reality_server_parts(view, {'reality': d}, host_env)
        check(listen == '10.0.0.11', 'endpoint b: active inbound listens on B')
        body = '\n'.join(l for l in frag.splitlines() if not l.strip().startswith('//'))
        arr = json.loads('[' + body.rstrip().rstrip(',') + ']')
        ib = arr[0]
        check(ib['tag'] == 'reality-retiring-in' and ib['listen'] == '10.0.0.10',
              'retiring inbound sits on the other endpoint')
        check(ib['tls']['reality']['private_key'] == 'PREVIOUS', 'retiring inbound carries the previous key')
        check(ib['users'] == view['reality_users']
              and ib['tls']['reality']['short_id'] == view['reality_short_ids'],
              'retiring inbound shares users + short_ids')

        d['retiring']['expires_at'] = '2000-01-01T00:00:00Z'
        listen, frag = render._reality_server_parts(view, {'reality': d}, host_env)
        check(listen == '10.0.0.11' and frag == '', 'expired window: no retiring inbound')
    finally:
        render._read_env = real_read_env

    if fail == 0:
        print(f'  ✓ reality-alternating: endpoint selection, expiry and retiring inbound ({ok} checks)')
        return 1, 0
    return 0, 1


def _test_server_user_accounting(render):
    """Per-user accounting on the server: every credential name gets an
    auth_user rule to its owner's `user:<name>` outbound, `direct` stays the
    first (default) outbound, the longest user name wins a shared prefix and
    a name with no known owner is its own owner."""
    ok = fail = 0

    def check(cond, label):
        nonlocal ok, fail
        if cond:
            ok += 1
        else:
            fail += 1
            print(f'  ✗ server-user-accounting: {label}')

    view = {
        'hy2_users': [{'name': 'ann'}, {'name': 'ann-marie'}],
        'reality_users': [{'name': 'ann-pc'}, {'name': 'ann-marie-pc'}, {'name': 'gone-phone'}],
        'ws_cf_users': [{'name': 'ann'}],
    }
    outbounds, rules = render._server_user_accounting(view, ['ann', 'ann-marie'])
    route = {r['auth_user'][0]: r['outbound'] for r in rules}
    check(outbounds[0] == {'tag': 'direct', 'type': 'direct'}, 'direct stays the default outbound')
    check([o['tag'] for o in outbounds[1:]] == ['user:ann', 'user:ann-marie', 'user:gone-phone'],
          'one direct outbound per owner')
    check(all(o['type'] == 'direct' for o in outbounds), 'accounting outbounds are plain direct')
    check(len(rules) == 5, 'one rule per credential name, no duplicate')
    check(route['ann-pc'] == 'user:ann', 'device credential goes to its user')
    check(route['ann-marie-pc'] == 'user:ann-marie', 'longest user name wins a shared prefix')
    check(route['gone-phone'] == 'user:gone-phone', 'unknown owner is its own owner')

    if fail == 0:
        print(f'  ✓ server-user-accounting: outbounds and auth_user rules ({ok} checks)')
        return 1, 0
    return 0, 1


def main():
    update = '--update' in sys.argv or os.environ.get('UPDATE_GOLDENS') == '1'
    try:
        render = _load_render_module()
    except Exception as e:
        print(f'harness error: failed to import render.py: {e}', file=sys.stderr)
        sys.exit(2)

    try:
        rendered = _render_all(render)
    except Exception as e:
        print(f'harness error: render failed: {e}', file=sys.stderr)
        raise

    passes, fails = _compare(rendered, update=update)

    # Unit + negative tests run even in --update mode (they're not goldens,
    # they exercise renderer-internal checks). Skipping under --update
    # would silently lose the regression coverage.
    x_pass, x_fail = _test_x25519_derivation(render)
    neg_pass, neg_fail = _test_awg_negative(render)
    hb_pass, hb_fail = _test_home_endpoint_bootstrap_dns(render)
    df_pass, df_fail = _test_device_filename_scheme(render)
    det_pass, det_fail = _test_endpoint_detour_not_selector(rendered)
    ra_pass, ra_fail = _test_reality_alternating(render)
    ua_pass, ua_fail = _test_server_user_accounting(render)
    cm_pass, cm_fail = _test_core_min_gate(render, rendered)
    pc_pass, pc_fail = _test_per_core_check(render)
    hp_pass, hp_fail = _test_hy2_key_pins(render, rendered)
    extra_pass = x_pass + neg_pass + hb_pass + df_pass + det_pass + ra_pass + ua_pass + cm_pass + pc_pass + hp_pass
    extra_fail = x_fail + neg_fail + hb_fail + df_fail + det_fail + ra_fail + ua_fail + cm_fail + pc_fail + hp_fail
    passes += extra_pass
    fails += extra_fail

    total = passes + fails
    print()
    if update:
        print(f'regenerated {passes - extra_pass} golden(s); '
              f'{extra_pass}/{extra_pass + extra_fail} unit+negative test(s) passed')
        sys.exit(0 if extra_fail == 0 else 1)
    print(f'{passes}/{total} passed, {fails} failed')
    sys.exit(0 if fails == 0 else 1)


if __name__ == '__main__':
    main()
