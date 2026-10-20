"""Pin the built image into the Runtipi recipe. Run after every image build:

    python3 tools/package.py ghcr.io/oscarhenrycollins/wizard-cloudflare:<tag>@sha256:<digest>

Plain text replacement; every other compose line stays byte-identical. The recipe must never enable the
loopback development bypass."""
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
compose = root / 'runtipi' / 'docker-compose.yml'
text = compose.read_text(encoding='utf-8')
if len(sys.argv) != 2 or not re.fullmatch(r'[\w.:/-]+:[\w.-]+@sha256:[0-9a-f]{64}', sys.argv[1]):
    raise SystemExit('usage: package.py <image:tag@sha256:digest>')
text, n = re.subn(r'(?m)^(    image: )\S+$', lambda m: m.group(1) + sys.argv[1], text)
if n != 1:
    raise SystemExit('image line not found exactly once')
if 'CF_DEVELOPMENT_MODE' in text:
    raise SystemExit('portable recipe must not enable the loopback development bypass')
compose.write_text(text, encoding='utf-8')
print('pinned', sys.argv[1])
