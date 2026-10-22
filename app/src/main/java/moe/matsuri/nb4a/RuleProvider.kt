package moe.matsuri.nb4a

import android.os.Handler
import android.os.Looper
import android.widget.Toast
import io.nekohasekai.sagernet.SagerNet
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Rule provider ala Clash: URL daftar aturan diunduh oleh aplikasi, disimpan di
 * filesDir/ruleset, lalu dipakai sing-box sebagai rule_set lokal. Dengan begitu
 * gagal-unduh tidak pernah membuat inti sing-box gagal start.
 *
 * Cara pakai di editor aturan (kolom Domain atau IP): ruleset:https://contoh.com/daftar.srs
 */
object RuleProvider {

    class Resolved(val path: String, val format: String)

    private const val FRESH_MS = 12L * 60 * 60 * 1000
    private const val RETRY_BLOCK_MS = 60L * 1000
    private const val MAX_BYTES = 10 * 1024 * 1024

    private val failedAt = HashMap<String, Long>()
    private val failed = LinkedHashSet<String>()

    private fun dir(): File = File(SagerNet.application.filesDir, "ruleset").apply { mkdirs() }

    /** URL yang gagal diproses sejak pemanggilan terakhir, lalu daftarnya dikosongkan. */
    @Synchronized
    fun takeFailed(): List<String> {
        val l = failed.toList()
        failed.clear()
        return l
    }

    @Synchronized
    private fun markFailed(u: String) {
        failedAt[u] = System.currentTimeMillis()
        failed.add(u)
    }

    /** Menampilkan pesan di thread utama (aman dipanggil dari thread mana pun). */
    fun warn(msg: String) {
        Handler(Looper.getMainLooper()).post {
            Toast.makeText(SagerNet.application, msg, Toast.LENGTH_LONG).show()
        }
    }

    fun resolve(url: String): Resolved? {
        val u = url.trim()
        if (!(u.startsWith("http://") || u.startsWith("https://"))) {
            markFailed(u)
            return null
        }
        synchronized(this) {
            val last = failedAt[u]
            if (last != null && System.currentTimeMillis() - last < RETRY_BLOCK_MS) {
                failed.add(u)
                return null
            }
        }

        val key = RuleProviderCore.sha1(u)
        val d = dir()
        val cached = cachedFile(d, key)
        if (cached != null && System.currentTimeMillis() - cached.lastModified() < FRESH_MS) {
            return toResolved(cached)
        }

        // Unduh di thread terpisah supaya aman dari larangan jaringan di thread utama.
        var data: ByteArray? = null
        val th = Thread { data = download(u) }
        th.start()
        th.join(25_000)
        val bytes = data
        if (bytes != null) {
            val stored = store(d, key, bytes)
            if (stored != null) return toResolved(stored)
        }
        // Unduhan gagal: pakai salinan lama jika ada.
        if (cached != null) return toResolved(cached)
        markFailed(u)
        return null
    }

    private fun cachedFile(d: File, key: String): File? {
        return listOf("srs", "json")
            .map { File(d, "$key.$it") }
            .filter { it.isFile && it.length() > 0 }
            .maxByOrNull { it.lastModified() }
    }

    private fun toResolved(f: File): Resolved {
        return Resolved(f.absolutePath, if (f.extension == "srs") "binary" else "source")
    }

    private fun download(u: String): ByteArray? {
        return try {
            val c = URL(u).openConnection() as HttpURLConnection
            c.connectTimeout = 8000
            c.readTimeout = 12000
            c.setRequestProperty("User-Agent", "NekoBox-RuleProvider")
            if (c.responseCode != 200 || c.contentLengthLong > MAX_BYTES) {
                c.disconnect()
                null
            } else {
                val bytes = c.inputStream.use { it.readBytes() }
                c.disconnect()
                if (bytes.size > MAX_BYTES) null else bytes
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun store(d: File, key: String, bytes: ByteArray): File? {
        return try {
            val format = RuleProviderCore.sniff(bytes)
            val out: ByteArray
            val ext: String
            when (format) {
                RuleProviderCore.BINARY -> {
                    out = bytes
                    ext = "srs"
                }
                RuleProviderCore.SOURCE -> {
                    if (!String(bytes, Charsets.UTF_8).contains("\"rules\"")) return null
                    out = bytes
                    ext = "json"
                }
                RuleProviderCore.TEXT -> {
                    val json = RuleProviderCore.textToSourceJson(String(bytes, Charsets.UTF_8))
                        ?: return null
                    out = json.toByteArray(Charsets.UTF_8)
                    ext = "json"
                }
                else -> return null
            }
            val tmp = File(d, "$key.tmp")
            tmp.writeBytes(out)
            File(d, if (ext == "srs") "$key.json" else "$key.srs").delete()
            val dst = File(d, "$key.$ext")
            if (dst.exists()) dst.delete()
            if (tmp.renameTo(dst)) dst else null
        } catch (e: Exception) {
            null
        }
    }
}
