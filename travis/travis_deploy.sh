#!/bin/bash
set -e -x

echo "Deploying since this is a tag commit"

# Upload to PYPI
python -m twine upload dist/* -u aantonitis -p $PYPASS --skip-existing
