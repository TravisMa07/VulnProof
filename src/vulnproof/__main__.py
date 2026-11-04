"""Support python -m vulnproof as well as the installed command."""

from .cli import main

raise SystemExit(main())
