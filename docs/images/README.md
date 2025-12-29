# Documentation Assets

This directory contains shared images and assets for the Server-Baukasten documentation.

## Usage

Reference images using relative paths from your documentation file:
- From `docs/en/README.md`: `![Alt text](../images/filename.png)`
- From `docs/de/README.md`: `![Alt text](../images/filename.png)`
- From module docs: `![Alt text](../../images/filename.png)`

## Naming Convention

Use descriptive, lowercase names with hyphens:
- `architecture-overview.png`
- `nftables-config-example.png`
- `crowdsec-dashboard.png`

## Image Formats

Prefer:
- **PNG** for screenshots and diagrams
- **SVG** for vector graphics and logos
- **JPG** for photos (if needed)

## Contributing Images

When adding new images:
1. Use descriptive filenames
2. Optimize file size before committing
3. Add alt text in both languages when referencing in docs
4. Update this README if adding new categories
