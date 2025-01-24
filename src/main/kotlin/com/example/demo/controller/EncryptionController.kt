package com.example.demo.controller

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.web.bind.annotation.*
import java.io.BufferedReader
import java.io.InputStreamReader

@RestController
@RequestMapping("/encryption")
class EncryptionController {

    private fun saveKeyToKeyring(keyName: String, secret: String): Boolean {
        val process = ProcessBuilder("keyctl", "add", "user", keyName, secret, "@u")
            .redirectErrorStream(true)
            .start()
        process.waitFor()
        return process.exitValue() == 0
    }

    private fun getKeyFromKeyring(keyName: String): String? {
        return try {
            // Crea y ejecuta el proceso para leer la clave
            val process = ProcessBuilder("keyctl", "read", keyName)
                .redirectErrorStream(true)
                .start()

            // Lee la salida del proceso
            val output = process.inputStream.bufferedReader().use { it.readText().trim() }

            // Espera la finalización del proceso y verifica el resultado
            if (process.waitFor() == 0) {
                output // Retorna la clave si el proceso fue exitoso
            } else {
                val error = process.errorStream.bufferedReader().use { it.readText().trim() }
                println("Error reading key '$keyName' from keyring: $error")
                null // Retorna null si hubo un error
            }
        } catch (e: Exception) {
            println("Exception while reading key '$keyName': ${e.message}")
            null // Retorna null en caso de excepción
        }
    }


    private fun signJWT(secret: ByteArray): String {
        val claimsSet = JWTClaimsSet.Builder()
            .subject("user123")
            .issuer("my-app")
            .claim("role", "admin")
            .build()

        val signedJWT = SignedJWT(
            JWSHeader(JWSAlgorithm.HS256),
            claimsSet
        )

        signedJWT.sign(MACSigner(secret))
        return signedJWT.serialize()
    }

    @PostMapping("/save-key")
    fun saveKey(@RequestParam keyName: String, @RequestParam secret: String): String {
        return if (saveKeyToKeyring(keyName, secret)) {
            "Key '$keyName' saved successfully in keyring."
        } else {
            "Failed to save key '$keyName' in keyring."
        }
    }

    @GetMapping("/get-jwt")
    fun getSignedJWT(@RequestParam keyName: String): String {
        val secret = getKeyFromKeyring(keyName)?.toByteArray(Charsets.UTF_8)
            ?: throw IllegalStateException("Key '$keyName' not found in keyring.")

        return signJWT(secret)
    }
}
