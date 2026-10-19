#!/usr/bin/env python3
"""Pack a built release directory into a deterministic archive for publication: release-out/svavyom-<version>.tar.gz (sorted entries, zero timestamps and
owners) and release-out/svavyom-<version>.tar.gz.sha256. Signs nothing. Usage: package_release.py [release-out]"""
import gzip
import hashlib
import io
import sys
import tarfile
from pathlib import Path

sys.dont_write_bytecode = True


def main(argv):
    out = Path(argv[1] if len(argv) > 1 else "release-out")
    version = Path("VERSION").read_text().strip()
    src = out / ("svavyom-" + version)
    if not src.is_dir():
        print("ERROR %s does not exist: run make docker-release first" % src)
        return 2
    arc = out / ("svavyom-%s.tar.gz" % version)
    if arc.exists():
        print("ERROR %s exists; move it away on purpose" % arc)
        return 2
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for p in sorted(src.rglob("*")):
                rel = Path(src.name) / p.relative_to(src)
                ti = tar.gettarinfo(str(p), arcname=rel.as_posix())
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                ti.mtime = 0
                if p.is_file():
                    with p.open("rb") as f:
                        tar.addfile(ti, f)
                else:
                    tar.addfile(ti)
    arc.write_bytes(buf.getvalue())
    digest = hashlib.sha256(buf.getvalue()).hexdigest()
    (out / (arc.name + ".sha256")).write_text("%s  %s\n" % (digest, arc.name))
    print("OK %s (%d bytes) sha256 %s" % (arc, arc.stat().st_size, digest))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
