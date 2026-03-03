#include "test_suite.h"
#include "../include/pqc_config.h"

#ifdef ENABLE_PQC_TESTS

#include "../include/dilithium.h"
#include <string.h>

namespace PQC {
namespace Test {

// Dilithium Malleability Testi
bool TestSuite::test_dilithium_malleability() {
    uint8_t d_pk[2048];
    uint8_t d_sk[4096];
    uint8_t sig[2420]; 
    size_t siglen;
    const uint8_t msg[] = "Test Message";
    
    DSA::Dilithium2::keypair(d_pk, d_sk);
    DSA::Dilithium2::sign(sig, &siglen, msg, sizeof(msg), d_sk);
    
    // İmzayı boz
    sig[20] ^= 0x01;
    
    int res = DSA::Dilithium2::verify(sig, siglen, msg, sizeof(msg), d_pk);
    return (res != 0); 
}

} // namespace Test
} // namespace PQC

#endif
