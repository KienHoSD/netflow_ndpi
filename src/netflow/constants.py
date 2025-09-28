# Balanced Constants - Good performance across normal traffic and attack scenarios
EXPIRED_UPDATE = 60   # seconds - Balance between memory usage and flow completeness
CLUMP_TIMEOUT = 0.8   # seconds - Good bulk detection without excessive CPU usage
ACTIVE_TIMEOUT = 3.0  # seconds - Reasonable active/idle classification threshold
BULK_BOUND = 5        # packets - Moderate bulk transfer detection sensitivity
PACKETS_PER_GC = 300  # packets - Regular cleanup without performance impact
GC_INTERVAL = 0.3     # seconds - Balanced background cleanup frequency
CHECK_INTERVAL = 0.1  # seconds - Responsive monitoring without excessive overhead
