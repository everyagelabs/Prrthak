"""Release-publisher checks; runtime policy signing has a separate authority."""
from pathlib import Path


def outside_source_key(value,*,must_exist=True):
    key=Path(value).expanduser().resolve(strict=must_exist)
    root=Path(__file__).resolve().parents[1]
    if key.is_relative_to(root):
        raise ValueError('Release signing keys must be outside the source/project directory; use an independently controlled private signing location')
    if any(key.is_relative_to(Path.home()/name) for name in ('Documents','Desktop')):
        raise ValueError('Release keys must be outside Desktop/Documents locations that may synchronize to cloud storage')
    if any(part.casefold() in ('mobile documents','cloudstorage','onedrive','dropbox','google drive') for part in key.parts):
        raise ValueError('A cloud-synchronized folder is not an approved release-key location')
    return key
