# Running netflow_ndpi on PyPy (Linux)

PyPy can speed up long-running Python code thanks to its JIT. For this project, PyPy may help in CPU-bound parts (feature aggregation, cffi calls to nDPI). Expect best gains for live sniffing sessions that run for minutes/hours; short offline conversions may see little benefit due to JIT warm-up.

Note: SciPy is required by some feature modules. Installing SciPy on PyPy is possible but may require system BLAS/LAPACK dev packages. If SciPy isn’t available on your platform, see the troubleshooting section below or consider using CPython for now.

## 1) Prerequisites

- nDPI compiled (library and python bindings location present):
  - Follow the README “Installation” section to build nDPI
  - Ensure the `../nDPI/python` path exists relative to this repo (pyproject points to it)
- Linux build tools (for SciPy when needed):

```bash
sudo apt update
sudo apt install -y build-essential gfortran pkg-config libopenblas-dev liblapack-dev
```

- PyPy 3 (with venv support):

```bash
sudo apt install -y pypy3 pypy3-venv
# verify
pypy3 -V
```

## 2) Create a PyPy virtual environment with uv

From the repo root:

```bash
# Tell uv to use PyPy
export UV_PYTHON=$(command -v pypy3)
# Create/refresh the venv and install deps from pyproject + uv.lock
uv sync
```

## 3) Install Numpy on PyPy (if not already installed by uv/pip)

```bash
# Inside the PyPy venv
. .venv/bin/activate
pip install numpy
```

If SciPy fails to build, see Troubleshooting.

## 4) Run commands under sudo with the PyPy venv

sudo does not inherit your shell PATH by default. Use one of:

```bash
# Full path to the venv entrypoint
sudo .venv/bin/netflow -f example.pcap -c flows.csv

# Or preserve PATH
sudo env PATH=$PATH netflow -i eth0 -u http://localhost:8080/predict
```

## 5) Performance tips

- Use BPF filters to reduce traffic load (e.g., `--filter 'tcp or udp'`).
- Prefer long-running capture when benchmarking to let the JIT warm up.
- Avoid excessive logging (`-v`) in production captures.
- Tune constants in `src/netflow/constants.py` for your workload (GC intervals, timeouts).

## 6) Troubleshooting

- SciPy build fails on PyPy:
  - Ensure you installed: `gfortran libopenblas-dev liblapack-dev`
  - Try the latest pip: `pip install -U pip setuptools wheel`
  - Some distros may not have compatible SciPy wheels for PyPy; building from source might be slow. If blocked, consider:
    - Using CPython for now: `uv python pin system` then `uv sync`
    - Or ask us to make SciPy optional in the code (fallback to NumPy-only paths for mode/stats)

- nDPI import errors:
  - Rebuild nDPI and ensure the Python bindings path matches `pyproject.toml` ([tool.uv.sources] ndpi = { path = "../nDPI/python" })
  - Make sure `LD_LIBRARY_PATH` (or system linker config) can find libndpi if you installed it system-wide.

- sudo cannot find netflow:
  - Use `sudo env PATH=$PATH netflow` or `sudo .venv/bin/netflow`.

## 7) Switch back to CPython

```bash
# Use system python
unset UV_PYTHON
uv sync
```

---
If you’d like, we can make a small change to the feature modules to gracefully skip SciPy at runtime and use NumPy fallbacks for basic stats. This keeps PyPy usable even when SciPy isn’t available.
