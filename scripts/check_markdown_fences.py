from pathlib import Path

failed = []
for path in Path('.').rglob('*.md'):
    if any(part.startswith('.') for part in path.parts):
        continue
    text = path.read_text(encoding='utf-8', errors='ignore')
    if text.count('```') % 2:
        failed.append(str(path))
if failed:
    raise SystemExit('Unbalanced markdown fences: ' + ', '.join(failed))
print('markdown fences ok')
