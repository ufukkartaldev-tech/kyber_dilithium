# GümüşPQC: Optimized Post-Quantum Cryptography Library for ESP32

## Overview
GümüşPQC is a high-performance, memory-efficient Post-Quantum Cryptography (PQC) library specifically engineered for the ESP32 microcontroller architecture. The system leverages the NIST-standardized Kyber Key Encapsulation Mechanism (KEM) and Dilithium Digital Signature Algorithm (DSA) to provide robust, quantum-resistant security for resource-constrained embedded systems.

## Key Features
- **Kyber (512/768)**: Quantum-resistant key exchange protocol ensuring forward secrecy against future cryptographic threats.
- **Dilithium2**: High-assurance digital signature scheme providing identity verification and data integrity.
- **PQC-Mesh Network**: Advanced multi-hop routing and automated relaying (B-Node) layer over the ESP-NOW protocol.
- **KeyVault (Secure Storage)**: Persistent NVS storage for PQC keys, protected via hardware-accelerated AES-256-GCM and device-unique Secret Salts.
- **Hybrid Encryption**: Dual-layer security utilizing hardware AES-256-GCM and ChaCha20 for defense-in-depth data protection.
- **Asynchronous Framework**: Non-blocking architecture offloading network traffic to Core 0 while reserving Core 1 for intensive cryptographic arithmetic.

## Security & Resilience Infrastructure
The library incorporates multiple defensive layers to mitigate advanced cyber threats and hardware-level attacks:

1.  **Trust-Chain (Peer Whitelisting)**: A persistent MAC-based whitelist ensures that only authenticated network participants can initiate or relay data. Unauthorized packets are discarded at the link layer.
2.  **Encrypted BlackBox**: Critical system telemetry and security indicators are encrypted via AES-256-GCM and logged to LittleFS (Flash). This preserves forensic auditability while maintaining confidentiality against physical extraction.
3.  **Silent Mode (Production Hardening)**: In production environments, UART (Serial) output is completely suppressed to prevent side-channel information leakage and local system disclosure.
4.  **Persistent Anti-Replay Layer**: Monotonic message identifiers are tracked via NVS, ensuring that replayed transmissions are detected and rejected even across system power cycles.
5.  **Session Timeout Mechanism**: A 500ms temporal guard is enforced for fragment reassembly. This prevents "Deadlock DoS" attacks where malformed or incomplete streams could exhaust internal buffers.
6.  **Entropy Lock**: The True Random Number Generator (TRNG) quality is monitored via real-time Shannon Entropy analysis. Operations are suspended if entropy falls below the 75% threshold to prevent weak key generation.

## Memory Optimization Strategies
To ensure reliable execution within the 520 KB RAM constraints of the ESP32, several specialized techniques have been implemented:

- **Universal Memory Recycling**: A shared static workspace (Union) allows for 100% memory reuse between Kyber and Dilithium operations, significantly reducing the static RAM footprint.
- **Bit-Level Packing**: Cryptographic coefficients are packed at 12-bit (Kyber) and 24-bit (Dilithium) levels, achieving a 25% reduction in polynomial storage requirements.
- **Flash Offloading (DROM)**: NTT zeta tables and Keccak constants are relocated to Flash memory via `PQC_FLASH_STORAGE` macros to maximize available heap space.

## Side-Channel & Physical Protections
- **Constant-Time (CT) Implementation**: All sensitive comparisons and arithmetic operations are executed in constant time to eliminate timing-based data exfiltration.
- **Anti-Fault-Injection**: Redundant validation logic and double-check mechanisms protect against hardware glitching and voltage manipulation attacks.
- **Secure Memory Sanitization**: Sensitive buffers and ephemeral keys are physically zeroed out (`memset 0`) immediately following their utilization.

## Technical Specifications
| Parameter | Value |
|-----------|-------|
| Target MCU | ESP32 (S3/C3/Standard) |
| Static RAM Footprint | ~16 KB |
| Stack Allocation | < 4 KB |
| Networking Protocol | ESP-NOW (Reliable Async) |
| Security Compliance | NIST Level 2-3 |

## Project Structure
- `src/include/`: Header definitions and configuration parameters.
- `src/source/`: Core algorithm implementations and communication stacks.
- `src/tests/`: Stability, performance, and security validation units.
- `kyber_dilithium.ino`: Integration entry point and application demo.

## License
This project is an open-source reference implementation intended for high-security embedded applications.
