from cryptography.hazmat.bindings._openssl import ffi, lib

print(lib.Cryptography_osrandom_engine_id)
print(ffi.SignFunc)
print(lib.SignFunc)