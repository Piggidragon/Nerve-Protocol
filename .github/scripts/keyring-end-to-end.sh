#!/usr/bin/env bash
# The installed node on a real Linux, on this machine's kernel (issue #135):
# its keys in the system keyring, and folder mode as `nerve-run`. Run as root
# on a machine that may be changed and broken (a CI runner, a test VM); CI
# runs it on Ubuntu 22.04 (kernel 5.15) and 24.04 (6.x), where the keyring
# used to be refused below Linux 7.1.
#
#   NERVE_NODE_REAL=<the nerve-node to install>
#   REAL_ACCOUNT_TEST=<the real_account test program>
#   .github/scripts/keyring-end-to-end.sh
#
# 1. crates/nerve-node/tests/real_account.rs, its first test: install, the
#    account nerve-run, folder grants as ACLs, uninstall.
# 2. The keyring path as an owner takes it: install the node (with the
#    owner's sudo), run `setup` in a terminal and answer yes to the keyring,
#    which installs GNOME Keyring, a session for `nerve` and a login keyring
#    (crates/nerve-node/src/keyring_setup.rs); check that the keys moved out of
#    their files; the second test of real_account.rs pairs a center, restarts
#    the node and runs a folder mode command as nerve-run, which cannot reach
#    the node's bus or keyring folder; `uninstall --purge` takes it all away.
#
# What this machine lacks compared to a desktop, and the node does not make
# up: nothing the node needs. A desktop's keyring is started by the user's
# graphical login and unlocked with its password; the node asks for neither.
# Its own step (apt, `loginctl enable-linger nerve`, the plain login keyring)
# gives `nerve` a systemd user session with a D-Bus that starts GNOME
# Keyring, exactly as on a server without a desktop. So nothing is set up
# here by hand but the owner.
set -euo pipefail

NODE=${NERVE_NODE_REAL:?the nerve-node to install}
TESTS=${REAL_ACCOUNT_TEST:?the real_account test program}
OWNER=${NERVE_REAL_OWNER:-nrvown}
PASS=ci-owner-pass
BIN=/usr/local/bin/nerve-node
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT=$(mktemp -d)
# The program where the owner can run it: a checkout is often below a home
# that only its user may enter.
INSTALL_FROM=$(mktemp -d)
chmod 755 "$INSTALL_FROM"
install -m 755 "$NODE" "$INSTALL_FROM/nerve-node"
NODE=$INSTALL_FROM/nerve-node
# A folder every account can enter, and none the owner's.
cd /

step() { printf '\n==== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
as_owner() { runuser -u "$OWNER" -- "$BIN" "$@"; }
# Root through the owner's sudo, as a person installs and uninstalls.
owners_sudo() { printf '%s\n' "$PASS" | runuser -u "$OWNER" -- sudo -S -p '' "$@"; }
summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY" || true; }

diagnostics() {
  echo "---- diagnostics"
  systemctl status nerve-node --no-pager -l 2>&1 | tail -20 || true
  journalctl -u nerve-node --no-pager -n 60 2>&1 || true
  loginctl list-users 2>&1 || true
  nuid=$(id -u nerve 2>/dev/null || true)
  [ -z "$nuid" ] || journalctl -u "user@$nuid" --no-pager -n 40 2>&1 || true
  # What the session of nerve was given: its manager's environment, the
  # system-wide one every login reads, and this script's own session.
  [ -z "$nuid" ] || runuser -u nerve -- env -i "XDG_RUNTIME_DIR=/run/user/$nuid" systemctl --user show-environment 2>&1 | grep -E 'XDG|DBUS' || true
  grep -E 'XDG|DBUS' /etc/environment 2>&1 || true
  env | grep -E '^(XDG|DBUS)' || true
  ls -la /etc/nerve /etc/nerve/keys /var/lib/nerve /var/lib/nerve/state 2>&1 || true
  [ -z "$nuid" ] || ls -la "/run/user/$nuid" 2>&1 || true
}
cleanup() {
  code=$?
  [ "$code" = 0 ] || diagnostics
  # What a failed run leaves: the node, the accounts, the owner.
  if [ -e "$BIN" ]; then "$BIN" uninstall --purge >/dev/null 2>&1 || true; fi
  userdel -r "$OWNER" >/dev/null 2>&1 || true
  rm -rf "$OUT" "$INSTALL_FROM"
  exit "$code"
}
trap cleanup EXIT

step "This kernel"
KERNEL=$(uname -r)
LSM=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "(no /sys/kernel/security/lsm)")
case ",$LSM," in *,landlock,*) LANDLOCK=yes ;; *) LANDLOCK=no ;; esac
echo "kernel:   $KERNEL"
echo "LSMs:     $LSM"
echo "Landlock: $LANDLOCK"
grep -E '^(PRETTY_NAME)=' /etc/os-release || true
summary "- kernel \`$KERNEL\`, Landlock: $LANDLOCK (\`$LSM\`)"

step "The owner"
# Not a system account: it has a home and a password, and is in sudo, as the
# person who installs the node is.
id "$OWNER" >/dev/null 2>&1 && userdel -r "$OWNER" >/dev/null 2>&1 || true
useradd --create-home --shell /bin/bash "$OWNER"
chmod 750 "/home/$OWNER"
usermod -aG sudo "$OWNER"
printf '%s:%s\n' "$OWNER" "$PASS" | chpasswd

step "1. real_account.rs: install, nerve-run, folder grants, uninstall"
NERVE_NODE_REAL=$NODE NERVE_REAL_OWNER=$OWNER \
  "$TESTS" --ignored --exact --nocapture folder_mode_runs_as_nerve_run_on_this_machine
# The test changes the owner's password.
printf '%s:%s\n' "$OWNER" "$PASS" | chpasswd
[ ! -e "$BIN" ] || fail "the test left the node installed"

step "2. Install the node as the owner"
owners_sudo "$NODE" install
as_owner status | tee "$OUT/status-files"
grep -q 'daemon: running' "$OUT/status-files"
as_owner config get machine.secret_storage | tee "$OUT/storage"
grep -q 'file' "$OUT/storage"
# The keys start in their files; setup moves them.
[ -f /var/lib/nerve/state/config.key ] || fail "no config.key before setup"
NERVE_UID=$(id -u nerve)
[ ! -e "/run/user/$NERVE_UID/bus" ] || fail "nerve has a session bus already"

step "3. setup at a terminal, yes to the keyring"
# The questions: the node's name (Enter), where the keys go (keyring), the
# offer to install a keyring (y), a pairing link (Enter).
python3 "$HERE/pty-answers.py" \
  'Name of this node=' \
  'Where the node keeps its keys=keyring' \
  'Install it now=y' \
  'Pairing link=' \
  -- runuser -u "$OWNER" -- "$BIN" setup | tee "$OUT/setup"
grep -q 'the system keyring answers for nerve' "$OUT/setup" || fail "setup did not install a keyring that answers"
grep -q "the node's keys are in the system keyring now" "$OUT/setup" || fail "setup did not move the keys"

step "4. The keys are in the keyring"
as_owner --json config get machine.secret_storage | tee "$OUT/storage"
grep -q '"keyring"' "$OUT/storage"
grep -q '"usable": *true' "$OUT/storage" || fail "the node says the keyring is not usable"
[ ! -e /var/lib/nerve/state/config.key ] || fail "config.key is still a file"
[ -z "$(find /etc/nerve/keys -name '*.key' 2>/dev/null)" ] || fail "a node key is still a file"
[ -S "/run/user/$NERVE_UID/bus" ] || fail "nerve has no session bus"
# GNOME Keyring holds them, as nerve's own secret service.
ls -la /var/lib/nerve/.local/share/keyrings/

step "5. The node starts again with the keys from the keyring"
systemctl restart nerve-node
for _ in $(seq 1 60); do
  as_owner status 2>/dev/null | grep -q 'daemon: running' && break
  sleep 1
done
as_owner status | tee "$OUT/status-keyring"
grep -q 'daemon: running' "$OUT/status-keyring" || fail "the node does not come up with its keys in the keyring"
if grep -q 'folder mode runs no command' "$OUT/status-keyring"; then fail "folder mode is refused with the keys in the keyring"; fi
# What status says in JSON: the node found its keyring and no folder mode
# command is held back (the refusal this job exists to keep away).
as_owner --json status | tee "$OUT/status-json"
python3 - "$OUT/status-json" <<'PY' || fail "status does not say the node runs with its keys in the keyring"
import json, sys
text = open(sys.argv[1]).read()
status = json.loads(text[text.index("{"):])
status = status.get("data", status)
assert status["keyring_failed"] is False, status
assert "folder_commands_off" not in status or status["folder_commands_off"] is None, status
PY

step "6. real_account.rs: a center, a restart, a folder mode command as nerve-run"
NERVE_REAL_KEYRING=1 NERVE_REAL_OWNER=$OWNER \
  "$TESTS" --ignored --exact --nocapture the_installed_node_with_its_keys_in_the_keyring_runs_folder_commands_as_nerve_run

step "7. uninstall --purge"
owners_sudo "$BIN" uninstall --purge | tee "$OUT/uninstall"
if id nerve >/dev/null 2>&1; then fail "the account nerve is still there"; fi
if id nerve-run >/dev/null 2>&1; then fail "the account nerve-run is still there"; fi
[ ! -e "$BIN" ] || fail "the program is still installed"
[ ! -e /etc/systemd/system/nerve-node.service ] || fail "the unit is still there"
[ ! -e /var/lib/nerve ] || fail "the node's home is still there"
[ ! -e "/run/user/$NERVE_UID" ] || fail "nerve's session is still there"

step "Done"
summary "- the keyring path end to end: passed"
