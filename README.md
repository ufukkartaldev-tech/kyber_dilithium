# GümüşPQC: Optimized Post-Quantum Cryptography Library for ESP32

## Overview
GümüşPQC is a high-performance, memory-efficient Post-Quantum Cryptography (PQC) library specifically engineered for the ESP32 microcontroller architecture. The system leverages the NIST-standardized Kyber Key Encapsulation Mechanism (KEM) and Dilithium Digital Signature Algorithm (DSA) to provide advanced security for resource-constrained embedded systems.

## Key Features
- **Kyber (512/768)**: Secure key exchange resistant to quantum computer attacks.
- **Dilithium2**: Digital signature verification resilient against physical and theoretical exploits.
- **PQC-Mesh Network**: Multi-hop routing and automated relaying (B-Node) layer for distributed communication over ESP-NOW.
- **KeyVault (Secure Storage)**: Persistent, encrypted storage for PQC keys in ESP32 NVS using hardware-accelerated AES-256-GCM and device-specific keys.
- **Hybrid Encryption**: Double-layer data security using hardware-accelerated AES-256-GCM and ChaCha20.
- **Asynchronous Framework**: Dedicated network core (Core 0) to prevent CPU stalls during heavy PQC arithmetic.

## Reliability and Diagnostics
- **BlackBox (Flash Logging)**: Critical system failures, memory leaks, and integrity errors are persistently logged to Flash (LittleFS) for post-mortem analysis.
- **Stress Test Mode**: Continuous, high-intensity validation of Kyber/Dilithium operations with 1-byte granularity memory leak detection.
- **Entropy Guard**: Hardware TRNG (True Random Number Generator) quality is validated using real-time Shannon Entropy calculation (0-100% score).

## Memory Optimization Strategies
To ensure stable operation within the 520 KB RAM limit of the ESP32, several advanced memory management techniques have been implemented:

1. **SharedWorkspace (Universal Memory Recycling)**: A unified static buffer (union) is utilized for both Kyber and Dilithium operations, achieving 100% memory reuse between algorithms. This reduces static RAM footprint by approximately 20 KB.
2. **Bit-Packing (Bit-Level Compression)**: 
    - Kyber coefficients are packed at a 12-bit level, saving 25% of storage space per polynomial.
    - Dilithium coefficients are packed at a 24-bit level, resulting in a 25% efficiency gain in matrix storage.
3. **Flash Offloading (DROM Placement)**: NTT (Number Theoretic Transform) zeta tables and Keccak constants are stored in Flash (RODATA) rather than RAM via the `PQC_FLASH_STORAGE` macro, preserving precious heap space.
4. **Lean Stack Design**: Large local arrays have been migrated to static storage to eliminate the risk of Stack Overflow during complex cryptographic operations.

## Performance and Asynchronous Architecture
- **PQC-Mesh Routing**: Nodes automatically detect and forward packets if the final destination MAC differs from the local MAC, enabling multi-hop network topologies.
- **Dual-Core Offloading**: ESP-NOW network traffic is handled by the Pro-Core (Core 0), while cryptographic computations are executed on the App-Core (Core 1), maximizing parallel processing capability.
- **DMA Compatibility**: Network transmission buffers are 4-byte (32-bit) aligned to optimize hardware-level Direct Memory Access (DMA) speed.
- **Non-Blocking Communication**: Data transmission is managed through FreeRTOS Queues, preventing CPU bottlenecks and ensuring system responsiveness.

## Security Analysis
- **Side-Channel Protections**: Constant-time (CT) algorithms and comparisons prevent timing-based data leaks during sensitive operations.
- **Anti-Fault-Injection**: Redundant verification and "double-check" logic protect against hardware glitching and voltage manipulation attacks.
- **Secure Wipe**: Sensitive data is physically erased from memory (memset 0) immediately after operation completion to ensure no cryptographic remnants remain.
- **Hardware Acceleration**: AES and SHA operations are offloaded to the ESP32 hardware accelerator, maximizing energy efficiency and side-channel resistance.

## Technical Specifications
| Parameter | Value |
|-----------|-------|
| Target MCU | ESP32 (S3/C3/Plain) |
| RAM Footprint | ~16 KB (Static) |
| Stack Usage | < 4 KB |
| Networking | ESP-NOW (Reliable Async) |
| Security Mode | NIST Level 2-3 |

## Project Structure
- `src/include/`: Header files and parameter configurations.
- `src/source/`: Implementation of algorithms and communication layers.
- `src/tests/`: Stability and performance testing units.
- `kyber_dilithium.ino`: Main application and integration example.

## License and Usage
This project is an open-source reference implementation designed for high-security embedded system applications.
