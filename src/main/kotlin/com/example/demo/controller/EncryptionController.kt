package com.example.demo.controller

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.*
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import org.springframework.web.bind.annotation.*
import java.io.File
import java.nio.file.Files
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@RestController
@RequestMapping("/encryption")
class EncryptionController {

    private val signerKey: RSAKey by lazy { generateRSAKey() }
    private val encrypterKey: RSAKey by lazy { generateRSAKey() }

    @PostMapping("/sign")
    fun signFile(@RequestParam filePath: String): String {
        val file = File(filePath)
        if (!file.exists()) return "El archivo no existe: $filePath"

        val payload = Files.readString(file.toPath())
        val signedContent = signContent(payload)
        val outputFilePath = "$filePath.signed"
        File(outputFilePath).writeText(signedContent)

        return "Archivo firmado exitosamente: $outputFilePath"
    }

    @PostMapping("/encrypt")
    fun encryptFile(@RequestParam filePath: String): String {
        val file = File(filePath)
        if (!file.exists()) return "El archivo no existe: $filePath"

        val payload = Files.readString(file.toPath())
        val encryptedContent = encryptContent(payload)
        val outputFilePath = "$filePath.encrypted"
        File(outputFilePath).writeText(encryptedContent)

        return "Archivo encriptado exitosamente: $outputFilePath"
    }

    @PostMapping("/decrypt")
    fun decryptFile(@RequestParam filePath: String): String {
        val success = processDecryption(filePath)
        return if (success) "Archivo desencriptado exitosamente: $filePath.decrypted"
        else "Error al desencriptar el archivo."
    }

    @PostMapping("/sign-encrypt")
    fun signAndEncryptFile(@RequestParam filePath: String): String {
        val file = File(filePath)
        if (!file.exists()) return "El archivo no existe: $filePath"

        val payload = Files.readString(file.toPath())
        val signedContent = signContent(payload)
        val encryptedContent = encryptContent(signedContent)
        val outputFilePath = "$filePath.signed-encrypted"
        File(outputFilePath).writeText(encryptedContent)

        return "Archivo firmado y encriptado exitosamente: $outputFilePath"
    }

    private fun signContent(payload: String): String {
        val jwsObject = JWSObject(
            JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signerKey.keyID).build(),
            Payload(payload)
        )
        val signer = RSASSASigner(signerKey.toPrivateKey() as RSAPrivateKey)
        jwsObject.sign(signer)
        return jwsObject.serialize()
    }

    private fun encryptContent(payload: String): String {
        val jweObject = JWEObject(
            JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                .keyID(encrypterKey.keyID)
                .build(),
            Payload(payload)
        )
        val encrypter = RSAEncrypter(encrypterKey.toPublicKey() as RSAPublicKey)
        jweObject.encrypt(encrypter)
        return jweObject.serialize()
    }

    private fun processDecryption(filePath: String): Boolean {
        val file = File(filePath)
        if (!file.exists()) return false

        // Leer el contenido encriptado
        val encryptedContent = file.readText()

        // Desencriptar el contenido
        val decryptedContent = decryptContent(encryptedContent)

        // Guardar el archivo desencriptado
        val outputFilePath = "$filePath.decrypted"
        File(outputFilePath).writeText(decryptedContent)

        return true
    }

    private fun decryptContent(encryptedContent: String): String {
        val jweObject = JWEObject.parse(encryptedContent)

        // Crear un desencriptador con la clave privada
        val decrypter = RSADecrypter(encrypterKey.toPrivateKey() as RSAPrivateKey)

        // Desencriptar el contenido
        jweObject.decrypt(decrypter)

        // Retornar el texto desencriptado
        return jweObject.payload.toString()
    }

    companion object {
        fun generateRSAKey(): RSAKey {
            return RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate()
        }
    }
}
