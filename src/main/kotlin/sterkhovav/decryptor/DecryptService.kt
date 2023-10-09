package sterkhovav.decryptor

import org.springframework.stereotype.Service
import java.nio.ByteBuffer
import java.nio.ByteOrder

interface DecryptService {
    fun decrypt(input: String, cryptoKey: String): Data
}

data class Data(val imei: ULong, val payload: String)

@Service
class DecryptServiceImpl : DecryptService {

    override fun decrypt(input: String, cryptoKey: String): Data {

        check(input.startsWith("c0") && input.endsWith("c2")) {
            throw Exception("Отсутствует идентификатор начала/конца пакета")
        }

        //Удаляем идентификаторы начала/конца пакета
        val inputSB = StringBuilder(input.substring(2, input.length - 2))

        // Получаем imei и удаляем первые 8 байтов из inputSB которые imei
        val imei = littleEndianToULong(inputSB.substring(0, 16))
        inputSB.delete(0, 16)

        //Поиск и замена байт-стаффинга
        val payloadWithByteStuffing =
            ByteArray(inputSB.length / 2) { inputSB.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

        val cryptedPayload = getCleanedPayload(payloadWithByteStuffing)

        val payload = StringBuilder()

        for (i in cryptedPayload.indices step 8) {
            val range = i until (i + 8).coerceAtMost(cryptedPayload.size)
            val part = cryptedPayload.sliceArray(range)
            val decryptedBlock = decryptXTEA(cryptoKey.toByteArray(), part)
            decryptedBlock.forEach { payload.append(String.format("%02x", it)) }
        }

        //Удаляем контрольную сумму в конце
        payload.delete(payload.length - 4, payload.length)

        return Data(imei, payload.toString())

    }

    private fun littleEndianToULong(hexString: String): ULong {
        val bytes = hexString.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).long.toULong()
    }

    private fun decryptXTEA(key: ByteArray, block: ByteArray, rounds: Int = 32): ByteArray {
        require(key.size == 16) { "Key size must be 128 bits." }
        require(block.size == 8) { "Block size must be 64 bits." }

        val k = IntArray(4)
        val end = ByteArray(8)
        val v = IntArray(2)
        val delta = 0x9E3779B9.toInt()
        var sum = delta * rounds

        ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(k)
        ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(v)

        repeat(rounds) {
            v[1] -= (((v[0] shl 4) xor (v[0] ushr 5)) + v[0]) xor (sum + k[sum ushr 11 and 3])
            sum -= delta
            v[0] -= (((v[1] shl 4) xor (v[1] ushr 5)) + v[1]) xor (sum + k[sum and 3])
        }

        ByteBuffer.wrap(end).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().put(v[0]).put(v[1])
        return end
    }

    private fun getCleanedPayload(payloadWithByteStuffing: ByteArray): ByteArray {
        val c4 = 0xC4.toByte()
        val cleanedPayload = mutableListOf<Byte>()

        var i = 0
        while (i < payloadWithByteStuffing.size) {
            if (payloadWithByteStuffing[i] == c4) {
                if (i < payloadWithByteStuffing.size - 1 && payloadWithByteStuffing[i + 1] == c4) {
                    cleanedPayload.add(c4)
                    i += 2  // Пропускаем следующий байт C4 (следующий байт не трогаем)
                    continue
                }
                // Если следующий байт существует и это не байт C4, уменьшаем его значение на 1
                // (опытным путем и исходя из примера пришел к этому)
                if (i < payloadWithByteStuffing.size - 1 && payloadWithByteStuffing[i + 1] != c4) {
                    payloadWithByteStuffing[i + 1] = (payloadWithByteStuffing[i + 1] - 1).toByte()
                }
                i++ // Не пишем одиночный байт C4
            } else {
                cleanedPayload.add(payloadWithByteStuffing[i])
                i++
            }
        }
        return cleanedPayload.toByteArray()
    }
}


