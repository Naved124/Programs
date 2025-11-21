Image Steganography Toolkit

Lightweight browser-based image steganography analysis and extraction tool.
Provides automatic file-signature scanning, LSB extraction, channel visualizations, histograms, and basic metadata — all in the browser with no server component.

Live files (local paths in this environment)

Main app script: /mnt/data/app.js

HTML: /mnt/data/index.html

CSS: /mnt/data/style.css

Example screenshot (used during debugging): /mnt/data/2e4acbbd-21a8-44e0-82d4-641ea322b127.png

When you publish this repository to GitHub, replace the local paths above with appropriate relative links (e.g. ./app.js, ./index.html) so the files are viewable in repo.

Features

Client-side analysis (no server/upload required)

Detects embedded file signatures (EXE, ELF, ZIP, RAR, 7z, PDF)

Attempts to detect appended data after image termination markers (JPEG/PNG/GIF)

Entropy-based validation and simple risk scoring

LSB extraction methods:

standard (1-bit RGB)

2bit (2-bit LSB)

red-only

sequential

LSB visualization (bit-plane preview)

Channel visualizations: Red / Green / Blue / LSB

Simple statistical analysis: means, ranges and histograms

Export analysis report (JSON) and extracted files/text

Session saving (localStorage)

Quickstart

Clone the repo (or download files)

Open index.html in a browser (recommended: Chrome / Firefox modern versions).

If your browser blocks local file access for FileReader on direct file open, run a simple static server:
