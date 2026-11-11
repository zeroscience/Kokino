# Website

The Kokino Forensic Toolkit website, served at
https://zeroscience.github.io/kokino-ftk/

Plain static files (no build step). To publish a change, copy this folder's
files into the `kokino-ftk/` folder of the
[zeroscience.github.io](https://github.com/zeroscience/zeroscience.github.io)
repository and push; GitHub Pages serves it within a minute or two.

The download buttons ask GitHub for the latest release, so a new release
needs no change here; update the feature list and FAQ when what Kokino
reads changes.

The stylesheet and script are referenced with `?v=<version>` so browsers
fetch them again after a change: raise it in index.html with every update.
