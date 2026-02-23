#!/usr/bin/env python3
"""
BlackRoad Container Registry
Production-grade OCI-compatible container image registry with SQLite persistence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
import fnmatch

# ── Optional rich for pretty output ─────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

console = Console() if _RICH else None

DB_PATH = Path.home() / ".blackroad" / "container-registry.db"

# ── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class ImageLayer:
    digest: str          # sha256:...
    size_bytes: int
    media_type: str = "application/vnd.oci.image.layer.v1.tar+gzip"


@dataclass
class Image:
    id: str
    name: str
    tag: str
    digest: str          # sha256 of manifest JSON
    size_bytes: int
    layers: list[ImageLayer]
    architecture: str = "amd64"
    os: str = "linux"
    pushed_at: str = ""
    pulled_count: int = 0
    labels: dict = field(default_factory=dict)
    vulnerabilities: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.pushed_at:
            self.pushed_at = datetime.now(timezone.utc).isoformat()


@dataclass
class Manifest:
    schema_version: int
    media_type: str
    config_digest: str
    layers: list[ImageLayer]
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "schemaVersion": self.schema_version,
            "mediaType": self.media_type,
            "config": {"digest": self.config_digest, "mediaType": "application/vnd.oci.image.config.v1+json"},
            "layers": [
                {"digest": lyr.digest, "size": lyr.size_bytes, "mediaType": lyr.media_type}
                for lyr in self.layers
            ],
            "created": self.created_at,
        }


# ── Registry ─────────────────────────────────────────────────────────────────

class ContainerRegistry:
    """SQLite-backed OCI-compatible container registry."""

    MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    # ── Schema ────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS images (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                tag         TEXT NOT NULL,
                digest      TEXT NOT NULL UNIQUE,
                size_bytes  INTEGER NOT NULL,
                architecture TEXT NOT NULL DEFAULT 'amd64',
                os          TEXT NOT NULL DEFAULT 'linux',
                pushed_at   TEXT NOT NULL,
                pulled_count INTEGER NOT NULL DEFAULT 0,
                labels_json TEXT NOT NULL DEFAULT '{}',
                layers_json TEXT NOT NULL DEFAULT '[]',
                manifest_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_images_name_tag ON images(name, tag);
            CREATE INDEX IF NOT EXISTS idx_images_pushed_at ON images(pushed_at);

            CREATE TABLE IF NOT EXISTS pull_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                image_id    TEXT NOT NULL,
                pulled_at   TEXT NOT NULL,
                FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                image_id    TEXT NOT NULL,
                cve_id      TEXT NOT NULL,
                severity    TEXT NOT NULL,
                package     TEXT NOT NULL,
                description TEXT NOT NULL,
                fixed_version TEXT,
                FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
            );
        """)
        self._conn.commit()

    # ── Helpers ───────────────────────────────────────────────────────────

    def _sha256(self, data: str) -> str:
        return "sha256:" + hashlib.sha256(data.encode()).hexdigest()

    def _row_to_image(self, row: sqlite3.Row) -> Image:
        layers_raw = json.loads(row["layers_json"])
        layers = [ImageLayer(**lyr) for lyr in layers_raw]
        return Image(
            id=row["id"],
            name=row["name"],
            tag=row["tag"],
            digest=row["digest"],
            size_bytes=row["size_bytes"],
            layers=layers,
            architecture=row["architecture"],
            os=row["os"],
            pushed_at=row["pushed_at"],
            pulled_count=row["pulled_count"],
            labels=json.loads(row["labels_json"]),
        )

    # ── Core Operations ───────────────────────────────────────────────────

    def push_image(
        self,
        name: str,
        tag: str,
        size_bytes: int,
        layers: list[dict],
        architecture: str = "amd64",
        os: str = "linux",
        labels: dict = None,
    ) -> Image:
        """Push an image to the registry."""
        labels = labels or {}
        image_layers = [
            ImageLayer(
                digest=lyr.get("digest", self._sha256(str(lyr))),
                size_bytes=lyr.get("size_bytes", 0),
                media_type=lyr.get("media_type", "application/vnd.oci.image.layer.v1.tar+gzip"),
            )
            for lyr in layers
        ]

        manifest = Manifest(
            schema_version=2,
            media_type=self.MEDIA_TYPE,
            config_digest=self._sha256(f"{name}:{tag}:{architecture}"),
            layers=image_layers,
        )
        manifest_json = json.dumps(manifest.to_dict(), sort_keys=True)
        digest = self._sha256(manifest_json)

        image_id = str(uuid.uuid4())
        pushed_at = datetime.now(timezone.utc).isoformat()

        cur = self._conn.cursor()
        # Remove existing image with same name:tag if present
        cur.execute("DELETE FROM images WHERE name=? AND tag=?", (name, tag))

        cur.execute(
            """INSERT INTO images
               (id, name, tag, digest, size_bytes, architecture, os, pushed_at,
                pulled_count, labels_json, layers_json, manifest_json)
               VALUES (?,?,?,?,?,?,?,?,0,?,?,?)""",
            (
                image_id, name, tag, digest, size_bytes,
                architecture, os, pushed_at,
                json.dumps(labels),
                json.dumps([asdict(lyr) for lyr in image_layers]),
                manifest_json,
            ),
        )
        self._conn.commit()

        return Image(
            id=image_id, name=name, tag=tag, digest=digest,
            size_bytes=size_bytes, layers=image_layers,
            architecture=architecture, os=os,
            pushed_at=pushed_at, labels=labels,
        )

    def pull_image(self, name: str, tag: str) -> Image:
        """Pull an image and record the pull event."""
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM images WHERE name=? AND tag=?", (name, tag))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Image {name}:{tag} not found")

        cur.execute(
            "UPDATE images SET pulled_count = pulled_count + 1 WHERE id=?",
            (row["id"],),
        )
        cur.execute(
            "INSERT INTO pull_events (image_id, pulled_at) VALUES (?,?)",
            (row["id"], datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

        image = self._row_to_image(row)
        image.pulled_count += 1
        return image

    def list_images(self, name_filter: str = None) -> list[Image]:
        """List images, optionally filtered by glob pattern on name."""
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM images ORDER BY pushed_at DESC")
        rows = cur.fetchall()
        images = [self._row_to_image(r) for r in rows]
        if name_filter:
            images = [img for img in images if fnmatch.fnmatch(img.name, name_filter)]
        return images

    def delete_image(self, image_id: str) -> bool:
        """Delete an image by ID."""
        cur = self._conn.cursor()
        cur.execute("SELECT id FROM images WHERE id=?", (image_id,))
        if not cur.fetchone():
            return False
        cur.execute("DELETE FROM images WHERE id=?", (image_id,))
        self._conn.commit()
        return True

    def get_manifest(self, name: str, tag: str) -> Manifest:
        """Retrieve the OCI manifest for an image."""
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM images WHERE name=? AND tag=?", (name, tag))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Image {name}:{tag} not found")

        manifest_dict = json.loads(row["manifest_json"])
        layers_raw = json.loads(row["layers_json"])
        layers = [ImageLayer(**lyr) for lyr in layers_raw]
        return Manifest(
            schema_version=manifest_dict.get("schemaVersion", 2),
            media_type=manifest_dict.get("mediaType", self.MEDIA_TYPE),
            config_digest=manifest_dict.get("config", {}).get("digest", ""),
            layers=layers,
            created_at=manifest_dict.get("created", ""),
        )

    def tag_image(self, source_id: str, new_tag: str) -> Image:
        """Create a new image entry with the same layers under a new tag."""
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM images WHERE id=?", (source_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Image {source_id} not found")

        source = self._row_to_image(row)
        return self.push_image(
            name=source.name,
            tag=new_tag,
            size_bytes=source.size_bytes,
            layers=[asdict(lyr) for lyr in source.layers],
            architecture=source.architecture,
            os=source.os,
            labels={**source.labels, "tag.source": source.tag},
        )

    def garbage_collect(self) -> dict:
        """Remove untagged/old images older than 30 days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        cur = self._conn.cursor()
        cur.execute(
            "SELECT id, size_bytes FROM images WHERE pulled_count=0 AND pushed_at < ?",
            (cutoff,),
        )
        rows = cur.fetchall()
        if not rows:
            return {"removed_count": 0, "freed_bytes": 0}

        freed = sum(r["size_bytes"] for r in rows)
        ids = [r["id"] for r in rows]
        cur.executemany("DELETE FROM images WHERE id=?", [(i,) for i in ids])
        self._conn.commit()
        return {"removed_count": len(ids), "freed_bytes": freed}

    def scan_vulnerabilities(self, image_id: str) -> list[dict]:
        """Simulated CVE vulnerability scan for an image."""
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM images WHERE id=?", (image_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Image {image_id} not found")

        # Deterministic simulation seeded by digest
        digest_int = int(row["digest"].replace("sha256:", "")[:8], 16)
        cve_pool = [
            {"cve_id": "CVE-2023-44487", "severity": "HIGH",   "package": "nghttp2",      "description": "HTTP/2 Rapid Reset attack", "fixed_version": "1.57.0"},
            {"cve_id": "CVE-2023-4863",  "severity": "CRITICAL","package": "libwebp",      "description": "Heap buffer overflow in WebP", "fixed_version": "1.3.2"},
            {"cve_id": "CVE-2024-3094",  "severity": "CRITICAL","package": "xz-utils",     "description": "Supply chain backdoor in liblzma", "fixed_version": "5.6.2"},
            {"cve_id": "CVE-2023-5363",  "severity": "HIGH",   "package": "openssl",       "description": "AES-SIV cipher decryption issue", "fixed_version": "3.0.12"},
            {"cve_id": "CVE-2023-6246",  "severity": "HIGH",   "package": "glibc",         "description": "Heap buffer overflow in __vsyslog_internal", "fixed_version": "2.39"},
            {"cve_id": "CVE-2024-0553",  "severity": "MEDIUM", "package": "gnutls",        "description": "Timing side-channel in RSA-PSK", "fixed_version": "3.8.3"},
            {"cve_id": "CVE-2024-1086",  "severity": "HIGH",   "package": "linux-kernel",  "description": "Use-after-free in netfilter nf_tables", "fixed_version": "6.6.15"},
            {"cve_id": "CVE-2023-47038", "severity": "MEDIUM", "package": "perl",          "description": "Heap buffer overflow in regcomp", "fixed_version": "5.38.2"},
            {"cve_id": "CVE-2024-2961",  "severity": "HIGH",   "package": "glibc",         "description": "Out-of-bounds write in iconv", "fixed_version": "2.39"},
            {"cve_id": "CVE-2023-52425", "severity": "MEDIUM", "package": "libexpat",      "description": "Denial of service in XML parsing", "fixed_version": "2.6.0"},
        ]

        count = (digest_int % 4)  # 0-3 vulns per image
        selected = []
        for i in range(count):
            idx = (digest_int + i * 3) % len(cve_pool)
            vuln = dict(cve_pool[idx])
            vuln["image_id"] = image_id
            selected.append(vuln)

        # Persist to DB
        cur.execute("DELETE FROM vulnerabilities WHERE image_id=?", (image_id,))
        for v in selected:
            cur.execute(
                """INSERT INTO vulnerabilities
                   (image_id, cve_id, severity, package, description, fixed_version)
                   VALUES (?,?,?,?,?,?)""",
                (image_id, v["cve_id"], v["severity"], v["package"],
                 v["description"], v.get("fixed_version")),
            )
        self._conn.commit()
        return selected

    def get_stats(self) -> dict:
        """Return registry-wide statistics."""
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt, SUM(size_bytes) as total_size FROM images")
        row = cur.fetchone()
        total_images = row["cnt"] or 0
        total_size = row["total_size"] or 0

        cur.execute(
            "SELECT name, tag, pulled_count FROM images ORDER BY pulled_count DESC LIMIT 1"
        )
        top = cur.fetchone()
        most_pulled = f"{top['name']}:{top['tag']} ({top['pulled_count']} pulls)" if top else "N/A"

        cur.execute("SELECT COUNT(*) as cnt FROM pull_events")
        total_pulls = cur.fetchone()["cnt"]

        return {
            "total_images": total_images,
            "total_size_bytes": total_size,
            "total_size_human": _human_size(total_size),
            "most_pulled": most_pulled,
            "total_pulls": total_pulls,
            "db_path": str(self.db_path),
        }

    def search(self, query: str) -> list[Image]:
        """Full-text search across name, tag, and labels."""
        query_lower = query.lower()
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM images")
        results = []
        for row in cur.fetchall():
            if (
                query_lower in row["name"].lower()
                or query_lower in row["tag"].lower()
                or query_lower in row["labels_json"].lower()
            ):
                results.append(self._row_to_image(row))
        return results

    def list_tags(self, name: str) -> list[str]:
        """List all tags for a given image name."""
        cur = self._conn.cursor()
        cur.execute("SELECT tag FROM images WHERE name=? ORDER BY pushed_at DESC", (name,))
        return [row["tag"] for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()


# ── Utilities ────────────────────────────────────────────────────────────────

def _human_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def _print_images(images: list[Image]) -> None:
    if not images:
        print("No images found.")
        return
    if _RICH:
        table = Table(title="Container Images", box=box.ROUNDED, show_lines=True)
        table.add_column("ID", style="dim", width=12)
        table.add_column("Name", style="cyan")
        table.add_column("Tag", style="green")
        table.add_column("Digest", style="dim", width=20)
        table.add_column("Size", justify="right")
        table.add_column("Arch")
        table.add_column("OS")
        table.add_column("Pulls", justify="right", style="yellow")
        table.add_column("Pushed At")
        for img in images:
            table.add_row(
                img.id[:12],
                img.name,
                img.tag,
                img.digest[:20] + "…",
                _human_size(img.size_bytes),
                img.architecture,
                img.os,
                str(img.pulled_count),
                img.pushed_at[:19],
            )
        console.print(table)
    else:
        header = f"{'ID':12}  {'NAME':30}  {'TAG':15}  {'SIZE':10}  {'ARCH':6}  {'PULLS':5}  PUSHED"
        print(header)
        print("-" * len(header))
        for img in images:
            print(
                f"{img.id[:12]:12}  {img.name:30}  {img.tag:15}  "
                f"{_human_size(img.size_bytes):10}  {img.architecture:6}  "
                f"{img.pulled_count:5}  {img.pushed_at[:19]}"
            )


def _print_manifest(manifest: Manifest) -> None:
    data = manifest.to_dict()
    print(json.dumps(data, indent=2))


def _print_vulns(vulns: list[dict]) -> None:
    if not vulns:
        print("No vulnerabilities found.")
        return
    if _RICH:
        table = Table(title="Vulnerability Scan Results", box=box.ROUNDED)
        table.add_column("CVE ID", style="bold red")
        table.add_column("Severity")
        table.add_column("Package", style="cyan")
        table.add_column("Description")
        table.add_column("Fixed In", style="green")
        for v in vulns:
            sev = v["severity"]
            color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
            table.add_row(
                v["cve_id"],
                f"[{color}]{sev}[/{color}]",
                v["package"],
                v["description"],
                v.get("fixed_version") or "N/A",
            )
        console.print(table)
    else:
        for v in vulns:
            print(f"[{v['severity']:8}] {v['cve_id']:20} {v['package']:15} {v['description']}")


def _print_stats(stats: dict) -> None:
    if _RICH:
        table = Table(title="Registry Statistics", box=box.SIMPLE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold")
        for k, v in stats.items():
            if k != "total_size_bytes":
                table.add_row(k.replace("_", " ").title(), str(v))
        console.print(table)
    else:
        for k, v in stats.items():
            if k != "total_size_bytes":
                print(f"{k:25} {v}")


# ── CLI ───────────────────────────────────────────────────────────────────────

USAGE = """
BlackRoad Container Registry CLI

Usage:
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
"""


def _parse_labels(args: list[str]) -> dict:
    labels = {}
    for arg in args:
        if "=" in arg:
            k, v = arg.split("=", 1)
            labels[k] = v
    return labels


def main(argv: list[str] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        print(USAGE)
        return 0

    cmd = argv[0]
    args = argv[1:]
    reg = ContainerRegistry()

    try:
        if cmd == "push":
            if len(args) < 3:
                print("Usage: push <name> <tag> <size_bytes> [--arch ARCH] [--os OS]")
                return 1
            name, tag, size_bytes = args[0], args[1], int(args[2])
            arch = "amd64"
            image_os = "linux"
            label_args = []
            i = 3
            while i < len(args):
                if args[i] == "--arch" and i + 1 < len(args):
                    arch = args[i + 1]; i += 2
                elif args[i] == "--os" and i + 1 < len(args):
                    image_os = args[i + 1]; i += 2
                elif args[i] == "--label" and i + 1 < len(args):
                    label_args.append(args[i + 1]); i += 2
                else:
                    i += 1
            layers = [{"digest": f"sha256:{'a' * 64}", "size_bytes": size_bytes, "media_type": "application/vnd.oci.image.layer.v1.tar+gzip"}]
            img = reg.push_image(name, tag, size_bytes, layers, arch, image_os, _parse_labels(label_args))
            print(f"Pushed {img.name}:{img.tag}  digest={img.digest[:32]}…  id={img.id}")

        elif cmd == "pull":
            if len(args) < 2:
                print("Usage: pull <name> <tag>")
                return 1
            img = reg.pull_image(args[0], args[1])
            print(f"Pulled {img.name}:{img.tag}  pulls={img.pulled_count}  size={_human_size(img.size_bytes)}")

        elif cmd == "list":
            name_filter = None
            if "--filter" in args:
                idx = args.index("--filter")
                name_filter = args[idx + 1] if idx + 1 < len(args) else None
            _print_images(reg.list_images(name_filter))

        elif cmd == "delete":
            if not args:
                print("Usage: delete <image_id>")
                return 1
            ok = reg.delete_image(args[0])
            print("Deleted." if ok else "Image not found.")

        elif cmd == "manifest":
            if len(args) < 2:
                print("Usage: manifest <name> <tag>")
                return 1
            _print_manifest(reg.get_manifest(args[0], args[1]))

        elif cmd == "tag":
            if len(args) < 2:
                print("Usage: tag <source_id> <new_tag>")
                return 1
            img = reg.tag_image(args[0], args[1])
            print(f"Tagged as {img.name}:{img.tag}  id={img.id}")

        elif cmd == "gc":
            result = reg.garbage_collect()
            print(f"GC complete: removed={result['removed_count']} freed={_human_size(result['freed_bytes'])}")

        elif cmd == "scan":
            if not args:
                print("Usage: scan <image_id>")
                return 1
            vulns = reg.scan_vulnerabilities(args[0])
            _print_vulns(vulns)

        elif cmd == "stats":
            _print_stats(reg.get_stats())

        elif cmd == "search":
            if not args:
                print("Usage: search <query>")
                return 1
            _print_images(reg.search(" ".join(args)))

        elif cmd == "tags":
            if not args:
                print("Usage: tags <name>")
                return 1
            tags = reg.list_tags(args[0])
            print("\n".join(tags) if tags else "No tags found.")

        else:
            print(USAGE)
            return 1

    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        reg.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
