"""Declare design-only status explicitly; reject incomplete Go integration."""
from pathlib import Path
import os
import subprocess

tracked = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
modules = [p for p in tracked if p.endswith('/go.mod')]
if modules:
    raise SystemExit('Nested Go modules require explicit CI integration: ' + ', '.join(modules))
has_module = Path('go.mod').is_file()
has_source = any(p.endswith('.go') for p in tracked)
if has_source and not has_module:
    raise SystemExit('Go source exists without root go.mod; Go checks cannot run')
state = 'true' if has_module else 'false'
message = ('Go module detected: format, vet and tests are required.' if has_module else
           'DESIGN ONLY: no Go module/source; Go format/vet/tests have NOT run. They activate when root go.mod is added.')
print(message)
if os.getenv('GITHUB_OUTPUT'):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
        out.write(f'enabled={state}\n')
if os.getenv('GITHUB_STEP_SUMMARY'):
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as out:
        out.write(message + '\n')
