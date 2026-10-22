"""Allow ``python -m ztrust``."""

import sys

from ztrust.cli import main

if __name__ == "__main__":
    sys.exit(main())
