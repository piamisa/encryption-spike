package com.example.demo.controller

import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/gpg")
class GPGController {

    @PostMapping("/sign")
    fun signFile(@RequestParam filePath: String): String {
        val success = signFileWithGPG(filePath)
        return if (success) "Archivo firmado exitosamente: $filePath.gpg"
        else "Error al firmar el archivo."
    }

    @PostMapping("/encrypt")
    fun encryptFile(@RequestParam filePath: String, @RequestParam recipient: String): String {
        val success = encryptFileWithGPG(filePath, recipient)
        return if (success) "Archivo encriptado exitosamente: $filePath.gpg"
        else "Error al encriptar el archivo."
    }

    @PostMapping("/decrypt")
    fun decryptFile(@RequestParam filePath: String): String {
        val success = decryptFileWithGPG(filePath)
        return if (success) "Archivo desencriptado exitosamente: $filePath.decrypted"
        else "Error al desencriptar el archivo."
    }

    @PostMapping("/sign-encrypt")
    fun signAndEncryptFile(@RequestParam filePath: String, @RequestParam recipient: String): String {
        val file = java.io.File(filePath)
        if (!file.exists()) return "El archivo especificado no existe: $filePath"

        // Intentar firmar el archivo
        val signed = signFileWithGPG(filePath)
        if (!signed) return "Error al firmar el archivo."

        // El archivo firmado tiene la extensión .gpg
        val signedFilePath = "$filePath.gpg"
        val signedFile = java.io.File(signedFilePath)
        if (!signedFile.exists()) return "Error: No se generó el archivo firmado: $signedFilePath"

        // Intentar encriptar el archivo firmado
        val encrypted = encryptFileWithGPG(signedFilePath, recipient)
        return if (encrypted) "Archivo firmado y encriptado exitosamente: $signedFilePath.gpg"
        else "Archivo firmado, pero ocurrió un error al encriptar."
    }

    private fun signFileWithGPG(filePath: String): Boolean {
        val process = ProcessBuilder(
            "gpg", "--sign", filePath
        ).redirectErrorStream(true).start()

        // Leer y mostrar la salida del comando para depuración
        process.inputStream.bufferedReader().use { reader ->
            reader.lines().forEach { println(it) }
        }

        return process.waitFor() == 0
    }

    private fun encryptFileWithGPG(filePath: String, recipient: String): Boolean {
        val process = ProcessBuilder(
            "gpg", "--encrypt", "--recipient", recipient, filePath
        ).redirectErrorStream(true).start()

        // Leer y mostrar la salida del comando para depuración
        process.inputStream.bufferedReader().use { reader ->
            reader.lines().forEach { println(it) }
        }

        return process.waitFor() == 0
    }

    private fun decryptFileWithGPG(filePath: String): Boolean {
        val outputFile = "$filePath.decrypted" // Archivo de salida desencriptado
        val process = ProcessBuilder(
            "gpg", "--output", outputFile, "--decrypt", filePath
        ).redirectErrorStream(true).start()

        // Leer y mostrar la salida del comando para depuración
        process.inputStream.bufferedReader().use { reader ->
            reader.lines().forEach { println(it) }
        }

        return process.waitFor() == 0
    }
}
