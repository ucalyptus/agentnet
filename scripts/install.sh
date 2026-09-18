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
node -e 'if (Number(process.versions.node.split(".")[0]) < 22) process.exit(1)' || {
  echo 'Node.js 22 or newer is required.' >&2; exit 1;
}
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
node --input-type=module - "$tmp/agentnet.mjs" "$dest" <<'NODE'
import { copyFileSync, chmodSync, constants } from 'node:fs';
copyFileSync(process.argv[2], process.argv[3], constants.COPYFILE_EXCL);
chmodSync(process.argv[3], 0o700);
NODE
printf 'Installed %s\nRun it by its full path, or add ~/.local/bin to PATH.\n' "$dest"
