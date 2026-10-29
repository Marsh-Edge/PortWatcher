"""Shared configuration defaults for PortWatcher."""

DEFAULT_TIMEOUT = 0.5
DEFAULT_WORKERS = 200
DEFAULT_RETRIES = 0
DEFAULT_BANNER_TIMEOUT = 0.75

# Maximum number of bytes read from a service banner.
MAX_BANNER_BYTES = 4096

# How many pending futures to keep in flight per worker.
PENDING_PER_WORKER = 2
