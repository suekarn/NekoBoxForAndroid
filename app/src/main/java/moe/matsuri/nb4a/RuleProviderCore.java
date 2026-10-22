package moe.matsuri.nb4a;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Logika murni (tanpa dependensi Android) untuk rule provider ala Clash:
 * mendeteksi jenis berkas yang diunduh dan mengubah daftar teks/YAML Clash
 * menjadi rule-set sumber (JSON) milik sing-box.
 */
public final class RuleProviderCore {

    private RuleProviderCore() {
    }

    public static final String BINARY = "binary";
    public static final String SOURCE = "source";
    public static final String TEXT = "text";
    public static final String UNSUPPORTED = "unsupported";

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}(/\\d{1,2})?$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(/\\d{1,3})?$");
    private static final Pattern DOMAIN = Pattern.compile("^[A-Za-z0-9_.-]+$");

    public static String sha1(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] h = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(s.hashCode());
        }
    }

    /** Deteksi jenis isi berkas dari byte-nya, bukan dari ekstensi URL. */
    public static String sniff(byte[] d) {
        if (d == null || d.length < 3) return UNSUPPORTED;
        if (d[0] == 'S' && d[1] == 'R' && d[2] == 'S') return BINARY; // sing-box .srs
        if (d[0] == 'M' && d[1] == 'R' && d[2] == 'S') return UNSUPPORTED; // mihomo .mrs
        if (d.length >= 4 && (d[0] & 0xFF) == 0x28 && (d[1] & 0xFF) == 0xB5
                && (d[2] & 0xFF) == 0x2F && (d[3] & 0xFF) == 0xFD) return UNSUPPORTED; // zstd (.mrs)
        String head = new String(d, 0, Math.min(d.length, 64), StandardCharsets.UTF_8)
                .replace("\uFEFF", "").trim();
        if (head.startsWith("{")) return SOURCE;
        return TEXT;
    }

    private static String esc(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String stripQuotes(String s) {
        if (s.length() >= 2) {
            char a = s.charAt(0), b = s.charAt(s.length() - 1);
            if ((a == '\'' || a == '"') && a == b) return s.substring(1, s.length() - 1).trim();
        }
        return s;
    }

    private static boolean looksLikeIp(String s) {
        return IPV4.matcher(s).matches() || IPV6.matcher(s).matches();
    }

    private static String withPrefix(String ip) {
        if (ip.contains("/")) return ip;
        return ip.contains(":") ? ip + "/128" : ip + "/32";
    }

    private static void addRule(List<String> out, String key, LinkedHashSet<String> values) {
        if (values.isEmpty()) return;
        StringBuilder sb = new StringBuilder("{\"").append(key).append("\":[");
        boolean first = true;
        for (String v : values) {
            if (!first) sb.append(',');
            sb.append('"').append(esc(v)).append('"');
            first = false;
        }
        sb.append("]}");
        out.add(sb.toString());
    }

    /**
     * Mengubah daftar teks bergaya Clash menjadi rule-set sumber sing-box.
     * Mendukung: payload YAML, behavior domain (+.x, .x, x), ipcidr, dan classical
     * (DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX, IP-CIDR, IP-CIDR6).
     * Tipe lain diabaikan. Mengembalikan null jika tidak ada aturan yang dikenali.
     */
    public static String textToSourceJson(String text) {
        LinkedHashSet<String> domain = new LinkedHashSet<>();
        LinkedHashSet<String> suffix = new LinkedHashSet<>();
        LinkedHashSet<String> keyword = new LinkedHashSet<>();
        LinkedHashSet<String> regex = new LinkedHashSet<>();
        LinkedHashSet<String> cidr = new LinkedHashSet<>();

        for (String raw : text.replace("\uFEFF", "").split("\\r?\\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) continue;
            if (line.equalsIgnoreCase("payload:") || line.equals("-")) continue;
            if (line.startsWith("- ")) line = line.substring(2).trim();
            int hash = line.indexOf(" #");
            if (hash >= 0) line = line.substring(0, hash).trim();
            line = stripQuotes(line);
            if (line.isEmpty()) continue;

            int comma = line.indexOf(',');
            if (comma > 0) {
                String kind = line.substring(0, comma).trim().toUpperCase(Locale.ROOT);
                String rest = line.substring(comma + 1);
                int c2 = rest.indexOf(',');
                if (c2 >= 0) rest = rest.substring(0, c2);
                rest = rest.trim();
                if (rest.isEmpty()) continue;
                switch (kind) {
                    case "DOMAIN": domain.add(rest.toLowerCase(Locale.ROOT)); break;
                    case "DOMAIN-SUFFIX": suffix.add(rest.toLowerCase(Locale.ROOT)); break;
                    case "DOMAIN-KEYWORD": keyword.add(rest.toLowerCase(Locale.ROOT)); break;
                    case "DOMAIN-REGEX": regex.add(rest); break;
                    case "IP-CIDR":
                    case "IP-CIDR6": cidr.add(withPrefix(rest)); break;
                    default: break; // PROCESS-NAME, GEOIP, dll. tidak didukung
                }
                continue;
            }

            if (line.startsWith("+.")) {
                suffix.add(line.substring(2).toLowerCase(Locale.ROOT));
            } else if (line.startsWith("*.")) {
                suffix.add("." + line.substring(2).toLowerCase(Locale.ROOT));
            } else if (line.startsWith(".")) {
                suffix.add(line.toLowerCase(Locale.ROOT));
            } else if (looksLikeIp(line)) {
                cidr.add(withPrefix(line));
            } else if (DOMAIN.matcher(line).matches()) {
                domain.add(line.toLowerCase(Locale.ROOT));
            }
        }

        // Satu objek aturan per jenis: sing-box meng-OR daftar aturan,
        // tetapi meng-AND field di dalam satu aturan.
        List<String> rules = new ArrayList<>();
        addRule(rules, "domain", domain);
        addRule(rules, "domain_suffix", suffix);
        addRule(rules, "domain_keyword", keyword);
        addRule(rules, "domain_regex", regex);
        addRule(rules, "ip_cidr", cidr);
        if (rules.isEmpty()) return null;
        StringBuilder sb = new StringBuilder("{\"version\":1,\"rules\":[");
        for (int i = 0; i < rules.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(rules.get(i));
        }
        return sb.append("]}").toString();
    }
}
