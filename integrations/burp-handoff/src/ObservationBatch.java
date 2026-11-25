// © Nasser Aldin Farag (0xFarag). All rights reserved.
package ch.zeroxfarag.authzledger.handoff;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

final class ObservationBatch {
    static final int MAX_ROWS = 500;
    private static final Set<String> LITERALS = Set.of("api","v1","v2","v3","users","user","accounts","account",
            "invoices","invoice","orders","order","items","item","objects","object","projects","project",
            "organizations","teams","profile","status","health","public","private","auth","login","logout",
            "session","me","control","admin");
    private static final Set<String> METHODS = Set.of("GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS","TRACE","CONNECT");

    record Observation(String id, String host, String method, String path, int status) { }

    static String host(String input) {
        if (input == null) throw invalid();
        String s = input.toLowerCase(Locale.ROOT);
        if (s.startsWith("[") && s.endsWith("]")) s = s.substring(1, s.length()-1);
        if (s.contains(":")) {
            if (!s.matches("[0-9a-f:]+") || URI.create("http://[" + s + "]/").getHost() == null) throw invalid();
        } else {
            if (s.length() > 253) throw invalid();
            for (String part : s.split("\\.", -1)) {
                if (!part.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) throw invalid();
            }
        }
        return s;
    }

    static Set<String> allowlist(String csv) {
        if (csv.length() > 4096) throw invalid();
        Set<String> hosts = new HashSet<>();
        for (String part : csv.split(",", -1)) hosts.add(host(part.strip()));
        return Set.copyOf(hosts);
    }

    static List<Observation> selected(List<HttpRequestResponse> selection, Set<String> allowed) {
        if (selection.isEmpty() || selection.size() > MAX_ROWS) throw invalid();
        List<Observation> result = new ArrayList<>();
        Map<String, Integer> occurrences = new HashMap<>();
        for (HttpRequestResponse entry : selection) {
            var request = entry.request();
            if (request == null || !request.isInScope() || !entry.hasResponse()) throw invalid();
            String raw = request.url();
            if (raw == null || raw.length() > 8192) throw invalid();
            URI url;
            try { url = URI.create(raw); } catch (IllegalArgumentException error) { throw invalid(); }
            if (!Set.of("https","http").contains(url.getScheme()) || url.getRawUserInfo() != null
                    || url.getPort() == 0 || url.getPort() > 65535) throw invalid();
            String sourceHost = host(url.getHost());
            if (!allowed.contains(sourceHost)) throw new IllegalArgumentException("Eine Auswahl liegt ausserhalb der Host-Allowlist.");
            String method = request.method();
            int status = entry.response().statusCode();
            if (!METHODS.contains(method) || status < 100 || status > 599) throw invalid();
            String path = path(url.getRawPath());
            String key = method + " " + sourceHost + " " + path; // Stable across a status change.
            int ordinal = occurrences.merge(key, 1, Integer::sum);
            result.add(new Observation("burp-" + digest(key + " " + ordinal), sourceHost, method, path, status));
        }
        return List.copyOf(result);
    }

    static String path(String raw) {
        if (raw.isEmpty()) return "/";
        if (raw.length() > 2048 || raw.indexOf('\\') >= 0 || !raw.startsWith("/") || raw.startsWith("//") ||
                raw.matches("(?is).*(?:%2f|%5c|%2e|%25|%0[0-9a-f]|%1[0-9a-f]|%7f).*")) throw invalid();
        String[] segments = raw.substring(1).split("/", -1);
        if (segments.length > 63) throw invalid();
        for (int i = 0; i < segments.length; i++) {
            String part = segments[i];
            if (part.equals(".") || part.equals("..")) throw invalid();
            if (!part.isEmpty() && !LITERALS.contains(part) && !part.matches("[0-9]{1,9}|redacted-[a-f0-9]{24}"))
                segments[i] = "redacted-" + digest(part);
        }
        String result = "/" + String.join("/", segments);
        if (result.length() > 2048) throw invalid();
        return result;
    }

    static String json(List<Observation> rows, Set<String> checked) {
        // Interpolated strings only come from strict allowlists, lower-case hex digests and numeric IDs.
        StringJoiner output = new StringJoiner(",", "{\"observations\":[", "]}");
        for (Observation o : rows) output.add("{\"id\":\"" + o.id + "\",\"host\":\"" + o.host +
                "\",\"method\":\"" + o.method + "\",\"path\":\"" + o.path + "\",\"status\":" + o.status +
                ",\"marker\":" + checked.contains(o.id) + ",\"rule\":\"authorization\",\"source\":\"Burp\"}");
        return output.toString();
    }

    private static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)), 0, 12);
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Auswahl, Hostliste oder beobachtete Metadaten sind ungültig.");
    }
}
