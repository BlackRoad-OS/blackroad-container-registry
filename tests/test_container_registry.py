"""
Tests for the BlackRoad Container Registry.
"""

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

# Resolve project root so imports work from any directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from container_registry import (
    ContainerRegistry,
    Image,
    ImageLayer,
    Manifest,
    _human_size,
    main,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_registry(tmp_path):
    """Return a fresh ContainerRegistry backed by a temp SQLite file."""
    db = tmp_path / "test-registry.db"
    reg = ContainerRegistry(db_path=db)
    yield reg
    reg.close()


def _sample_layers(n: int = 2) -> list[dict]:
    return [
        {
            "digest": f"sha256:{'a' * 63}{i}",
            "size_bytes": 10 * 1024 * 1024,
            "media_type": "application/vnd.oci.image.layer.v1.tar+gzip",
        }
        for i in range(n)
    ]


# ── Unit Tests ────────────────────────────────────────────────────────────────

class TestPushImage:
    def test_push_returns_image(self, tmp_registry):
        img = tmp_registry.push_image("nginx", "1.25", 50_000_000, _sample_layers())
        assert isinstance(img, Image)
        assert img.name == "nginx"
        assert img.tag == "1.25"
        assert img.digest.startswith("sha256:")
        assert img.size_bytes == 50_000_000
        assert img.pulled_count == 0

    def test_push_stores_layers(self, tmp_registry):
        layers = _sample_layers(3)
        img = tmp_registry.push_image("alpine", "3.18", 5_000_000, layers)
        assert len(img.layers) == 3
        for lyr in img.layers:
            assert isinstance(lyr, ImageLayer)

    def test_push_with_labels(self, tmp_registry):
        labels = {"maintainer": "team@example.com", "version": "1.0"}
        img = tmp_registry.push_image("myapp", "latest", 20_000_000, _sample_layers(), labels=labels)
        assert img.labels == labels

    def test_push_overwrite_same_tag(self, tmp_registry):
        tmp_registry.push_image("redis", "7", 30_000_000, _sample_layers())
        img2 = tmp_registry.push_image("redis", "7", 31_000_000, _sample_layers())
        images = tmp_registry.list_images()
        redis_images = [i for i in images if i.name == "redis" and i.tag == "7"]
        assert len(redis_images) == 1
        assert redis_images[0].size_bytes == 31_000_000

    def test_push_architecture_and_os(self, tmp_registry):
        img = tmp_registry.push_image(
            "myapp", "arm", 10_000_000, _sample_layers(),
            architecture="arm64", os="linux"
        )
        assert img.architecture == "arm64"
        assert img.os == "linux"


class TestPullImage:
    def test_pull_increments_count(self, tmp_registry):
        tmp_registry.push_image("postgres", "15", 80_000_000, _sample_layers())
        img = tmp_registry.pull_image("postgres", "15")
        assert img.pulled_count == 1
        img2 = tmp_registry.pull_image("postgres", "15")
        assert img2.pulled_count == 2

    def test_pull_nonexistent_raises(self, tmp_registry):
        with pytest.raises(ValueError, match="not found"):
            tmp_registry.pull_image("ghost", "latest")

    def test_pull_returns_image(self, tmp_registry):
        tmp_registry.push_image("ubuntu", "22.04", 30_000_000, _sample_layers())
        img = tmp_registry.pull_image("ubuntu", "22.04")
        assert img.name == "ubuntu"
        assert img.tag == "22.04"


class TestListImages:
    def test_list_all(self, tmp_registry):
        tmp_registry.push_image("img1", "v1", 1_000_000, _sample_layers())
        tmp_registry.push_image("img2", "v2", 2_000_000, _sample_layers())
        images = tmp_registry.list_images()
        assert len(images) == 2

    def test_list_with_glob_filter(self, tmp_registry):
        tmp_registry.push_image("blackroad/api", "latest", 1_000_000, _sample_layers())
        tmp_registry.push_image("blackroad/web", "latest", 2_000_000, _sample_layers())
        tmp_registry.push_image("third-party/db", "latest", 3_000_000, _sample_layers())
        filtered = tmp_registry.list_images(name_filter="blackroad/*")
        assert len(filtered) == 2

    def test_list_empty(self, tmp_registry):
        assert tmp_registry.list_images() == []


class TestDeleteImage:
    def test_delete_existing(self, tmp_registry):
        img = tmp_registry.push_image("todelete", "v1", 1_000_000, _sample_layers())
        assert tmp_registry.delete_image(img.id) is True
        assert tmp_registry.list_images() == []

    def test_delete_nonexistent(self, tmp_registry):
        assert tmp_registry.delete_image(str(uuid.uuid4())) is False


class TestManifest:
    def test_get_manifest(self, tmp_registry):
        tmp_registry.push_image("myimg", "v1", 5_000_000, _sample_layers(2))
        manifest = tmp_registry.get_manifest("myimg", "v1")
        assert isinstance(manifest, Manifest)
        assert manifest.schema_version == 2
        assert len(manifest.layers) == 2

    def test_manifest_nonexistent_raises(self, tmp_registry):
        with pytest.raises(ValueError):
            tmp_registry.get_manifest("ghost", "latest")

    def test_manifest_to_dict(self, tmp_registry):
        tmp_registry.push_image("testimg", "v1", 5_000_000, _sample_layers(1))
        m = tmp_registry.get_manifest("testimg", "v1")
        d = m.to_dict()
        assert "schemaVersion" in d
        assert "layers" in d
        assert "config" in d


class TestTagImage:
    def test_tag_creates_new_image(self, tmp_registry):
        src = tmp_registry.push_image("app", "v1.0", 10_000_000, _sample_layers())
        tagged = tmp_registry.tag_image(src.id, "latest")
        assert tagged.name == "app"
        assert tagged.tag == "latest"
        assert tagged.id != src.id

    def test_tag_preserves_layers(self, tmp_registry):
        src = tmp_registry.push_image("app", "v2", 10_000_000, _sample_layers(3))
        tagged = tmp_registry.tag_image(src.id, "stable")
        assert len(tagged.layers) == 3

    def test_tag_nonexistent_raises(self, tmp_registry):
        with pytest.raises(ValueError):
            tmp_registry.tag_image(str(uuid.uuid4()), "new-tag")


class TestGarbageCollect:
    def test_gc_no_old_images(self, tmp_registry):
        tmp_registry.push_image("fresh", "v1", 1_000_000, _sample_layers())
        result = tmp_registry.garbage_collect()
        assert result["removed_count"] == 0
        assert result["freed_bytes"] == 0

    def test_gc_removes_old_unpulled(self, tmp_registry):
        img = tmp_registry.push_image("old", "v1", 5_000_000, _sample_layers())
        # Backdating pushed_at to 31 days ago via direct SQL
        import sqlite3
        from datetime import timezone, timedelta, datetime
        old_date = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        conn = sqlite3.connect(str(tmp_registry.db_path))
        conn.execute("UPDATE images SET pushed_at=? WHERE id=?", (old_date, img.id))
        conn.commit(); conn.close()
        result = tmp_registry.garbage_collect()
        assert result["removed_count"] == 1
        assert result["freed_bytes"] == 5_000_000


class TestScanVulnerabilities:
    def test_scan_returns_list(self, tmp_registry):
        img = tmp_registry.push_image("scanme", "v1", 1_000_000, _sample_layers())
        vulns = tmp_registry.scan_vulnerabilities(img.id)
        assert isinstance(vulns, list)

    def test_scan_vuln_structure(self, tmp_registry):
        img = tmp_registry.push_image("vulntest", "v1", 1_000_000, _sample_layers())
        vulns = tmp_registry.scan_vulnerabilities(img.id)
        for v in vulns:
            assert "cve_id" in v
            assert "severity" in v
            assert v["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert "package" in v
            assert "description" in v

    def test_scan_nonexistent_raises(self, tmp_registry):
        with pytest.raises(ValueError):
            tmp_registry.scan_vulnerabilities(str(uuid.uuid4()))


class TestStats:
    def test_stats_empty(self, tmp_registry):
        stats = tmp_registry.get_stats()
        assert stats["total_images"] == 0
        assert stats["total_size_bytes"] == 0

    def test_stats_with_images(self, tmp_registry):
        tmp_registry.push_image("a", "v1", 1_000_000, _sample_layers())
        tmp_registry.push_image("b", "v1", 2_000_000, _sample_layers())
        stats = tmp_registry.get_stats()
        assert stats["total_images"] == 2
        assert stats["total_size_bytes"] == 3_000_000


class TestSearch:
    def test_search_by_name(self, tmp_registry):
        tmp_registry.push_image("blackroad/api-gateway", "v2", 10_000_000, _sample_layers())
        tmp_registry.push_image("postgres", "15", 80_000_000, _sample_layers())
        results = tmp_registry.search("api-gateway")
        assert len(results) == 1
        assert results[0].name == "blackroad/api-gateway"

    def test_search_by_tag(self, tmp_registry):
        tmp_registry.push_image("img", "stable", 5_000_000, _sample_layers())
        tmp_registry.push_image("img", "canary", 5_000_000, _sample_layers())
        results = tmp_registry.search("stable")
        assert len(results) == 1

    def test_search_no_results(self, tmp_registry):
        tmp_registry.push_image("myimage", "v1", 1_000_000, _sample_layers())
        assert tmp_registry.search("nothing-matches-xyz") == []


class TestListTags:
    def test_list_tags(self, tmp_registry):
        tmp_registry.push_image("app", "v1", 1_000_000, _sample_layers())
        tmp_registry.push_image("app", "v2", 1_000_000, _sample_layers())
        tmp_registry.push_image("app", "latest", 1_000_000, _sample_layers())
        tags = tmp_registry.list_tags("app")
        assert set(tags) == {"v1", "v2", "latest"}

    def test_list_tags_no_match(self, tmp_registry):
        assert tmp_registry.list_tags("nonexistent") == []


class TestHumanSize:
    def test_bytes(self):
        assert _human_size(500) == "500.0 B"

    def test_kilobytes(self):
        assert "KB" in _human_size(1500)

    def test_megabytes(self):
        assert "MB" in _human_size(5_000_000)

    def test_gigabytes(self):
        assert "GB" in _human_size(3_000_000_000)
