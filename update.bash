#!/usr/bin/env bash
python3 -m pip install --upgrade build
python3 -m pip install --upgrade twine
python3 -m build
python3 -m twine upload --repository testpypi dist/*0.0.3*