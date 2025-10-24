"""
Runtime-tunable constants with profiles for different use cases.

Two built-in profiles:
- realtime: Balanced defaults for live capture on network interfaces
- offline:  Optimized for PCAP -> CSV conversion (no wall-clock driven GC)

Use set_profile("offline"|"realtime") at startup to switch.
"""

# Profile definitions
PROFILES = {
	# Good performance across normal traffic and attack scenarios (live capture)
	"realtime": {
		"EXPIRED_UPDATE": 60,   # seconds - Balance between memory usage and flow completeness
		"CLUMP_TIMEOUT": 0.8,   # seconds - Good bulk detection without excessive CPU usage
		"ACTIVE_TIMEOUT": 3.0,  # seconds - Reasonable active/idle classification threshold
		"BULK_BOUND": 5,        # packets - Moderate bulk transfer detection sensitivity
		"PACKETS_PER_GC": 300,  # packets - Regular cleanup without performance impact
		"GC_INTERVAL": 0.3,     # seconds - Balanced background cleanup frequency
		"CHECK_INTERVAL": 0.1,  # seconds - Responsive monitoring without excessive overhead
	},
	# Optimized for offline PCAP processing
	"offline": {
		"EXPIRED_UPDATE": 60,    # keep flows intact but cap idle splits
		"CLUMP_TIMEOUT": 1.0,    # standard for bulk/subflow and IAT features
		"ACTIVE_TIMEOUT": 1.0,   # standard for active/idle segmentation
		"BULK_BOUND": 5,         # common threshold
		"PACKETS_PER_GC": 2000,  # fewer GC passes; rely on per-packet GC + final flush
		"GC_INTERVAL": 3600,     # effectively disable periodic wall-clock GC
		"CHECK_INTERVAL": 0.25,  # coarse loop; irrelevant for offline but harmless
	},
}

_active_profile = "realtime"

def _apply(profile: dict):
	global EXPIRED_UPDATE, CLUMP_TIMEOUT, ACTIVE_TIMEOUT, BULK_BOUND
	global PACKETS_PER_GC, GC_INTERVAL, CHECK_INTERVAL
	EXPIRED_UPDATE = profile["EXPIRED_UPDATE"]
	CLUMP_TIMEOUT = profile["CLUMP_TIMEOUT"]
	ACTIVE_TIMEOUT = profile["ACTIVE_TIMEOUT"]
	BULK_BOUND = profile["BULK_BOUND"]
	PACKETS_PER_GC = profile["PACKETS_PER_GC"]
	GC_INTERVAL = profile["GC_INTERVAL"]
	CHECK_INTERVAL = profile["CHECK_INTERVAL"]


def set_profile(name: str) -> None:
	"""Select active constants profile at runtime.

	Must be called before starting capture/processing for consistent behavior.
	"""
	global _active_profile
	if name not in PROFILES:
		raise ValueError(f"Unknown constants profile: {name}")
	_active_profile = name
	_apply(PROFILES[name])


def get_profile() -> str:
	"""Return the current active profile name."""
	return _active_profile


# Initialize with the default (realtime) profile
_apply(PROFILES[_active_profile])