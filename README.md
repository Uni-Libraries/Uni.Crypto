# uni.crypto

Small, cross-platform C library implementing CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) with a table-driven core. Built with CMake; tested with Catch2 via CPM.cmake.

## Quickstart

Build, test, and install with CMake.

```bash
# Configure (Release)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release

# Run tests
ctest --test-dir build --build-config Release

# Optionally install (adjust prefix as needed)
cmake --install build --config Release --prefix ./_install
```

Notes:
- On Windows with the default Visual Studio generator, keep the `--config Release` arguments.
- Tests require C++ (Catch2) and internet access on first configure to fetch Catch2 via CPM, unless cached.
