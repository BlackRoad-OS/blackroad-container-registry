# BlackRoad Container Registry

> Production-grade, OCI-compatible container image registry with SQLite persistence, CVE scanning, garbage collection, and a rich CLI.

[![CI](https://github.com/BlackRoad-OS/blackroad-container-registry/actions/workflows/ci.yml/badge.svg)](https://github.com/BlackRoad-OS/blackroad-container-registry/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
![License](https://img.shields.io/github/license/BlackRoad-OS/blackroad-container-registry)

---

## Features

| Feature | Details |
|---------|---------|
| 🗄️ **SQLite persistence** | Zero-dependency storage at `~/.blackroad/container-registry.db` |
| 📦 **OCI manifests** | Schema v2 manifests with layer tracking |
| 🏷️ **Tag management** | Push, retag, and list tags per image |
| 🔍 **Full-text search** | Query by name, tag, or label |
| 🛡️ **CVE scanning** | Simulated vulnerability scan with severity ratings |
| 🗑️ **Garbage collection** | Auto-remove untagged images older than 30 days |
| 📊 **Registry stats** | Total images, sizes, pull counts |
| 🌈 **Rich CLI output** | Beautiful tables via `rich` (falls back gracefully) |

---

## Installation

```bash
git clone https://github.com/BlackRoad-OS/blackroad-container-registry.git
cd blackroad-container-registry
pip install rich          # optional — enables pretty tables
pip install pytest rich   # for running tests
```

---

## Quick Start

```python
from container_registry import ContainerRegistry

reg = ContainerRegistry()

# Push an image
img = reg.push_image(
    name="blackroad/api",
    tag="v2.1.0",
    size_bytes=45_000_000,
    layers=[
        {"digest": "sha256:abc…", "size_bytes": 20_000_000},
        {"digest": "sha256:def…", "size_bytes": 25_000_000},
    ],
    architecture="amd64",
    os="linux",
    labels={"maintainer": "team@blackroad.io"},
)
print(img.digest)   # sha256:...

# Pull
pulled = reg.pull_image("blackroad/api", "v2.1.0")

# Scan for CVEs
vulns = reg.scan_vulnerabilities(img.id)

# Stats
print(reg.get_stats())
```

---

## CLI Reference

```
registry push   <name> <tag> <size_bytes> [--arch ARCH] [--os OS] [--label KEY=VAL ...]
registry pull   <name> <tag>
registry list   [--filter GLOB]
registry delete <image_id>
registry manifest <name> <tag>
registry tag    <source_id> <new_tag>
registry gc
registry scan   <image_id>
registry stats
registry search <query>
registry tags   <name>
```

### Examples

```bash
# Push
python container_registry.py push blackroad/api v2.1.0 45000000 --arch amd64 --label env=prod

# List all images
python container_registry.py list

# Filter by glob
python container_registry.py list --filter "blackroad/*"

# Pull
python container_registry.py pull blackroad/api v2.1.0

# Scan vulnerabilities
python container_registry.py scan <image-id>

# Garbage collect
python container_registry.py gc

# Stats
python container_registry.py stats

# Search
python container_registry.py search api

# Retag
python container_registry.py tag <source-id> stable
```

---

## Architecture

```
ContainerRegistry
│
├── push_image()       ─── generates sha256 manifest digest, stores layers + labels
├── pull_image()       ─── increments pull_count, records pull_events row
├── list_images()      ─── supports fnmatch glob on image name
├── delete_image()     ─── cascades to pull_events + vulnerabilities
├── get_manifest()     ─── returns OCI schema v2 Manifest dataclass
├── tag_image()        ─── creates new Image row copying source layers
├── garbage_collect()  ─── removes pulled_count=0 images older than 30 days
├── scan_vulnerabilities() ─ deterministic CVE simulation seeded by digest
├── get_stats()        ─── aggregate metrics via SQL
├── search()           ─── full-text match on name/tag/labels_json
└── list_tags()        ─── all tags for a given image name
```

### Database Schema

```sql
images (id, name, tag, digest, size_bytes, architecture, os,
        pushed_at, pulled_count, labels_json, layers_json, manifest_json)

pull_events (id, image_id, pulled_at)

vulnerabilities (id, image_id, cve_id, severity, package,
                 description, fixed_version)
```

---

## Data Models

```python
@dataclass
class ImageLayer:
    digest: str          # "sha256:..."
    size_bytes: int
    media_type: str      # OCI media type

@dataclass
class Image:
    id: str              # uuid4
    name: str            # e.g. "blackroad/api"
    tag: str             # e.g. "v2.1.0"
    digest: str          # sha256 of manifest JSON
    size_bytes: int
    layers: list[ImageLayer]
    architecture: str    # amd64 | arm64 | arm/v7
    os: str              # linux | windows
    pushed_at: str       # ISO-8601
    pulled_count: int
    labels: dict
    vulnerabilities: list[dict]

@dataclass
class Manifest:
    schema_version: int  # 2
    media_type: str      # application/vnd.oci.image.manifest.v1+json
    config_digest: str
    layers: list[ImageLayer]
    created_at: str
```

---

## Running Tests

```bash
pytest tests/ -v --cov=container_registry
```

Expected: **15+ tests** across push, pull, list, delete, manifest, tag, gc, scan, stats, search, list_tags, and utility functions.

---

## Contributing

Pull requests welcome. Please ensure all tests pass and `ruff check` produces no errors before submitting.

---

## License

See [LICENSE](LICENSE) for details. All code is proprietary to BlackRoad OS, Inc.
