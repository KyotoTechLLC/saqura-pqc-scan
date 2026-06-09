package com.example

// Quantum-safe: uses SaQura hybrid PQC
class SafeCrypto {
    // ML-KEM (FIPS 203) key encapsulation
    fun encapsulate() = saqura.MlKem.generate("ML-KEM-768")

    // ML-DSA (FIPS 204) signatures
    fun sign(data: ByteArray) = saqura.MlDsa.sign(data, "Dilithium3")

    // AES-256-GCM for symmetric
    fun encrypt() = Cipher.getInstance("AES/GCM/NoPadding")

    // SHA-256 hashing
    fun hash() = MessageDigest.getInstance("SHA-256")
}
