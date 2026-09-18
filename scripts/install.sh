#!/bin/sh
set -eu
# Download this script, inspect it, then run with the HTTPS service origin.
# Installs only the client. It does not enroll, start services, or change shell files.
origin=${1:?Usage: sh install.sh https://your-agentnet-service}
case "$origin" in
  https://*) ;;
  *) echo 'An HTTPS origin is required.' >&2; exit 1 ;;
esac
origin=${origin%/}
# Find an interpreter that is actually new enough. `node` on PATH is often an older LTS,
# and a client installed with #!/usr/bin/env node would then silently run on the wrong one.
pinned=''
for candidate in "${AGENTNET_NODE:-}" "$(command -v node 2>/dev/null || true)" "$(command -v node22 2>/dev/null || true)" "$HOME/.local/bin/node" /opt/homebrew/bin/node /usr/local/bin/node; do
  [ -n "$candidate" ] || continue
  [ -x "$candidate" ] || continue
  if "$candidate" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' 2>/dev/null; then
    pinned=$("$candidate" -e 'console.log(process.execPath)')
    break
  fi
done
if [ -z "$pinned" ]; then
  echo 'Node.js 22 or newer is required, and none was found.' >&2
  echo 'Install one, then re-run this script (set AGENTNET_NODE=/path/to/node to choose it explicitly):' >&2
  echo '  macOS:  brew install node@22' >&2
  echo '  Linux:  curl -fsSL https://nodejs.org/dist/v22.20.0/node-v22.20.0-linux-x64.tar.xz | tar -xJ -C "$HOME/.local" --strip-components=1' >&2
  echo '  nvm:    nvm install 22' >&2
  exit 1
fi
node() { "$pinned" "$@"; }
printf 'Using Node %s at %s\n' "$("$pinned" -e 'console.log(process.versions.node)')" "$pinned"
dest="$HOME/.local/bin/agentnet"
if [ -e "$dest" ] || [ -L "$dest" ]; then
  echo "Refusing to overwrite $dest. Move your previous client aside first." >&2
  exit 1
fi
umask 077
tmp=$(mktemp -d)
trap 'rm -f "$tmp/agentnet.mjs" "$tmp/agentnet.sha256"; rmdir "$tmp"' EXIT HUP INT TERM
curl --fail --silent --show-error --proto '=https' --max-time 60 "$origin/agentnet.mjs" -o "$tmp/agentnet.mjs"
curl --fail --silent --show-error --proto '=https' --max-time 60 "$origin/agentnet.sha256" -o "$tmp/agentnet.sha256"
node --input-type=module - "$tmp" <<'NODE'
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const directory = process.argv[2];
const expected = readFileSync(`${directory}/agentnet.sha256`, 'utf8');
if (!/^[a-f0-9]{64}  agentnet\.mjs\n$/.test(expected)) throw new Error('Invalid checksum file');
const actual = createHash('sha256').update(readFileSync(`${directory}/agentnet.mjs`)).digest('hex');
if (actual !== expected.slice(0, 64)) throw new Error('Client checksum mismatch');
NODE
mkdir -p "$HOME/.local/bin"
# Exclusive creation prevents overwriting an existing executable or following its symlink.
# The checksum is verified against the downloaded bytes above; only afterwards is the
# shebang rewritten to the interpreter validated here, so `env node` cannot later resolve
# to an older Node. `agentnet update` preserves this pinned line.
node --input-type=module - "$tmp/agentnet.mjs" "$dest" "$pinned" <<'NODE'
import { readFileSync, writeFileSync, chmodSync, constants } from 'node:fs';
const [, , source, destination, interpreter] = process.argv;
const bundle = readFileSync(source, 'utf8');
const body = bundle.startsWith('#!') ? bundle.slice(bundle.indexOf('\n') + 1) : bundle;
writeFileSync(destination, `#!${interpreter}\n${body}`, { mode: 0o700, flag: 'wx' });
chmodSync(destination, 0o700);
NODE
printf 'Installed %s (pinned to %s)\nRun it by its full path, or add ~/.local/bin to PATH.\nNext: %s doctor\n' "$dest" "$pinned" "$dest"
