# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import os

HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, "src/osrandom_engine.h")) as f:
    INCLUDES = f.read()

TYPES = """
static const char *const Cryptography_osrandom_engine_name;
static const char *const Cryptography_osrandom_engine_id;
"""

FUNCTIONS = """
int Cryptography_add_osrandom_engine(void);
int ConfigureSslContext(int (*sign_func)(unsigned char *sig, size_t *sig_len,
                         const unsigned char *tbs, size_t tbs_len), const char *cert,
                    SSL_CTX *ctx);
"""

with open(os.path.join(HERE, "src/osrandom_engine.c")) as f:
    CUSTOMIZATIONS = f.read()
