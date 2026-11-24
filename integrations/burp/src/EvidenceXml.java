// © Nasser Aldin Farag (0xFarag). All rights reserved.
package ch.zeroxfarag.authzledger.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import java.util.List;

final class EvidenceXml {
    static final int MAX_FILE = 1024 * 1024;
    static final int MAX_ROWS = 500;
    private static final byte[] PREFIX = utf8("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<!-- © Nasser Aldin Farag (0xFarag). All rights reserved. -->\n<items>\n");
    private static final byte[] MID = utf8("</request><response base64=\"true\">");
    private static final byte[] END_ITEM = utf8("</response></item>\n");
    private static final byte[] END = utf8("</items>\n");

    static final class InvalidSelection extends IllegalArgumentException {
        InvalidSelection(String message) { super(message); }
    }

    static byte[] encode(List<HttpRequestResponse> selection) {
        if (selection.isEmpty() || selection.size() > MAX_ROWS)
            throw new InvalidSelection("Select between 1 and " + MAX_ROWS + " exchanges.");
        ByteArrayOutputStream xml = new ByteArrayOutputStream();
        xml.writeBytes(PREFIX);
        int index = 0;
        for (HttpRequestResponse exchange : selection) {
            index++;
            HttpRequest request = exchange.request();
            if (request == null || !request.isInScope()) throw invalid(index, "outside the current Burp scope");
            HttpResponse response = exchange.hasResponse() ? exchange.response() : null;
            if (response == null) throw invalid(index, "missing recorded response");
            String url = request.url();
            if (!validUrl(url)) throw invalid(index, "unsupported URL");
            String method = request.method();
            int status = response.statusCode();
            if (method == null || !method.matches("[A-Za-z]{1,16}") || status < 100 || status > 599)
                throw invalid(index, "unsupported method or status");

            ByteArray requestBytes = request.toByteArray();
            ByteArray responseBytes = response.toByteArray();
            int reqSize = requestBytes.length(), resSize = responseBytes.length();
            if (reqSize < 1 || resSize < 1) throw invalid(index, "empty recorded message");
            byte[] start = utf8("<item><url>" + url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    + "</url><method>" + method + "</method><status>" + status
                    + "</status><request base64=\"true\">");
            long size = (long) xml.size() + start.length + MID.length + END_ITEM.length + END.length
                    + base64Size(reqSize) + base64Size(resSize);
            if (size > MAX_FILE) throw invalid(index, "export exceeds the 1 MiB import limit");
            xml.writeBytes(start);
            xml.writeBytes(Base64.getEncoder().encode(requestBytes.getBytes()));
            xml.writeBytes(MID);
            xml.writeBytes(Base64.getEncoder().encode(responseBytes.getBytes()));
            xml.writeBytes(END_ITEM);
        }
        xml.writeBytes(END);
        return xml.toByteArray();
    }

    private static boolean validUrl(String value) {
        if (value == null || value.length() > 8192 || !value.chars().allMatch(c -> c > 32 && c < 127)) return false;
        try {
            URI url = URI.create(value);
            String host = url.getHost();
            if (host == null || host.isBlank() || host.contains("%")) return false;
            if (!host.startsWith("[")) {
                String domain = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
                if (domain.length() > 253) return false;
                for (String label : domain.split("\\.", -1)) {
                    if (label.length() < 1 || label.length() > 63) return false;
                }
            }
            int port = url.getPort();
            return ("https".equalsIgnoreCase(url.getScheme()) || "http".equalsIgnoreCase(url.getScheme()))
                    && url.getUserInfo() == null && url.getFragment() == null && port != 0 && port <= 65535
                    && !url.getRawAuthority().endsWith(":");
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static long base64Size(int n) { return 4L * ((n + 2L) / 3); }
    private static InvalidSelection invalid(int index, String detail) {
        return new InvalidSelection("Selection " + index + ": " + detail + ".");
    }
    private static byte[] utf8(String text) { return text.getBytes(StandardCharsets.UTF_8); }

    /** Publish only a complete new file. An existing file or symlink is never replaced. */
    static void saveNew(Path destination, byte[] xml) throws IOException {
        Path folder = destination.toAbsolutePath().getParent();
        Path temp = Files.getFileAttributeView(folder, PosixFileAttributeView.class) != null
                ? Files.createTempFile(folder, ".authzledger-", ".tmp",
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                : Files.createTempFile(folder, ".authzledger-", ".tmp");
        try {
            Files.write(temp, xml, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.createLink(destination, temp);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private EvidenceXml() { }
}
