"""Build full and upgrade Plesk archives; runtime data and secrets are never included."""
from pathlib import Path
import zipfile
import re

source = Path(__file__).resolve().parent
out = source.parent / 'dist'
out.mkdir(exist_ok=True)
public = source / 'httpdocs'
private = source / 'hackscan-private'
version = re.search(r"const HS_VERSION = '([^']+)'", (private / 'core.php').read_text()).group(1)
full = [source / 'UPLOAD-VEJLEDNING.md', source / 'OPDATERING.md', public, private]
full += sorted(public.rglob('*')) + sorted(private.rglob('*'))
upgrade = [source / 'OPDATERING.md', private, public, public / 'hackscan',
           private / 'app.php', private / 'core.php', public / 'hackscan/app.js', public / 'hackscan/style.css']
for name, paths in [('HackScan-Plesk.zip', full), (f'HackScan-Opdatering-{version}.zip', upgrade)]:
    target = out / name
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            rel = path.relative_to(source)
            if any(part in {'data', 'setup-key.txt', '__pycache__'} for part in rel.parts):
                continue
            info = zipfile.ZipInfo(rel.as_posix() + ('/' if path.is_dir() else ''))
            info.create_system = 3
            secret_area = rel.parts[0] == 'hackscan-private'
            mode = (0o40700 if secret_area else 0o40755) if path.is_dir() else (0o100600 if secret_area else 0o100644)
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, b'' if path.is_dir() else path.read_bytes())
    with zipfile.ZipFile(target) as archive:
        assert archive.testzip() is None
        names = archive.namelist()
        assert not any('setup-key' in n or '/data/' in n or '..' in Path(n).parts or n.startswith('/') for n in names)
        assert 'httpdocs/index.html' not in names
        assert 'hackscan-private/core.php' in names
        assert 'httpdocs/hackscan/app.js' in names
        assert archive.read('hackscan-private/core.php') == (private / 'core.php').read_bytes()
        assert archive.read('httpdocs/hackscan/app.js') == (public / 'hackscan/app.js').read_bytes()
    print(f'Verified: {target.name} ({target.stat().st_size} bytes)')
