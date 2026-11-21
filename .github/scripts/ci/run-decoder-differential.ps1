$ErrorActionPreference = "Stop"
cmake -S . -B build-decoder-oracle -G Ninja -DCMAKE_BUILD_TYPE=Release -DTESSERA_BUILD_TESTS=ON -DTESSERA_BUILD_EXAMPLES=OFF -DTESSERA_ENABLE_DECODER_ORACLE=ON
if ($LASTEXITCODE -ne 0) { throw "Decoder differential configure failed ($LASTEXITCODE)." }
cmake --build build-decoder-oracle --target tessera_decoder_probe --parallel
if ($LASTEXITCODE -ne 0) { throw "Decoder probe build failed ($LASTEXITCODE)." }
ctest --test-dir build-decoder-oracle -R tessera_decoder_differential --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "Decoder differential test failed ($LASTEXITCODE)." }
