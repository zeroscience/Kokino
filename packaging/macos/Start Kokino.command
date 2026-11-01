#!/bin/bash
# Starts Kokino Forensic Toolkit and opens it in the browser.
# Double-click this file; close the Terminal window to stop Kokino.
cd "$(dirname "$0")" || exit 1
exec ./kokino serve
