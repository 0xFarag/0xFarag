// © Nasser Aldin Farag (0xFarag). All rights reserved.
package ch.zeroxfarag.authzledger.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import javax.swing.JMenuItem;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.BiFunction;

public final class ExportTest {
    static final String URL = "https://evidence.example.test/a?x=1&y=2";

    // Every host method must be explicitly allowed by the test.
    static <T> T api(Class<T> type, BiFunction<String, Object[], Object> handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, args) -> handler.apply(method.getName(), args)));
    }
    static Object unexpected(String name) { throw new AssertionError("Unexpected Burp API call: " + name); }
    static void check(boolean condition) { if (!condition) throw new AssertionError(); }

    static ByteArray bytes(byte[] raw, int length) {
        return api(ByteArray.class, (method, args) -> switch (method) {
            case "length" -> length;
            case "getBytes" -> { check(length == raw.length); yield raw; }
            default -> unexpected(method);
        });
    }

    static final byte[] REQUEST = ("POST /a?x=1&y=2 HTTP/1.1\r\nHost: evidence.example.test\r\n"
            + "Content-Length: 3\r\n\r\n\u0000\u00ffx").getBytes(StandardCharsets.ISO_8859_1);
    static final byte[] RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\u00fe\u0000"
            .getBytes(StandardCharsets.ISO_8859_1);

    static HttpRequestResponse exchange(boolean scoped, boolean complete, String url, int length) {
        HttpRequest req = api(HttpRequest.class, (method, args) -> switch (method) {
            case "isInScope" -> scoped;
            case "url" -> url;
            case "method" -> "POST";
            case "toByteArray" -> bytes(REQUEST, length);
            default -> unexpected(method);
        });
        HttpResponse res = api(HttpResponse.class, (method, args) -> switch (method) {
            case "statusCode" -> (short) 200;
            case "toByteArray" -> bytes(RESPONSE, RESPONSE.length);
            default -> unexpected(method);
        });
        return api(HttpRequestResponse.class, (method, args) -> switch (method) {
            case "hasResponse" -> complete;
            case "request" -> req;
            case "response" -> { check(complete); yield res; }
            default -> unexpected(method);
        });
    }

    static ContextMenuEvent event(InvocationType type, List<HttpRequestResponse> rows) {
        return api(ContextMenuEvent.class, (name, args) -> switch (name) {
            case "invocationType" -> type;
            case "selectedRequestResponses" -> rows;
            default -> unexpected(name);
        });
    }

    static void invalid(List<HttpRequestResponse> rows, String fragment) {
        try { EvidenceXml.encode(rows); throw new AssertionError("Missing refusal"); }
        catch (EvidenceXml.InvalidSelection expected) { check(expected.getMessage().contains(fragment)); }
    }

    public static void main(String[] args) throws Exception {
        var plugin = new AuthzLedgerExtension();
        boolean[] registered = new boolean[2];
        Extension ext = api(Extension.class, (name, a) -> {
            if (!name.equals("setName")) return unexpected(name);
            registered[0] = "AuthzLedger Evidence Export".equals(a[0]); return null;
        });
        UserInterface ui = api(UserInterface.class, (name, a) -> {
            if (!name.equals("registerContextMenuItemsProvider")) return unexpected(name);
            registered[1] = a[0] == plugin; return null;
        });
        plugin.initialize(api(MontoyaApi.class, (name, a) -> switch (name) {
            case "extension" -> ext;
            case "userInterface" -> ui;
            default -> unexpected(name);
        }));
        check(registered[0] && registered[1]);
        var sample = exchange(true, true, URL, REQUEST.length);
        check(plugin.provideMenuItems(event(InvocationType.MESSAGE_EDITOR_REQUEST, List.of(sample))).isEmpty());
        check(plugin.provideMenuItems(event(InvocationType.PROXY_HISTORY, List.of())).isEmpty());
        var menu = plugin.provideMenuItems(event(InvocationType.PROXY_HISTORY, List.of(sample)));
        check(menu.size() == 1 && ((JMenuItem)menu.getFirst()).getText().equals("Export selected evidence to AuthzLedger…"));
        check(!plugin.provideMenuItems(event(InvocationType.PROXY_HISTORY,
                Collections.nCopies(EvidenceXml.MAX_ROWS + 1, sample))).getFirst().isEnabled());
        invalid(List.of(), "between");
        invalid(Collections.nCopies(EvidenceXml.MAX_ROWS + 1, sample), "between");
        invalid(List.of(sample, exchange(false, true, URL, REQUEST.length)), "Selection 2: outside");
        invalid(List.of(exchange(true, false, URL, REQUEST.length)), "missing recorded response");
        invalid(List.of(exchange(true, true, URL, Integer.MAX_VALUE)), "1 MiB");
        invalid(List.of(exchange(true, true, URL, 0)), "empty");
        for (String bad : List.of("ftp://example.test/", "https://name@example.test/", "https://localhost:99999/",
                "https://localhost:/", "https://localhost/a#anchor", "https://a.test/\u0000"))
            invalid(List.of(exchange(true, true, bad, REQUEST.length)), "unsupported URL");
        check(EvidenceXml.encode(Collections.nCopies(EvidenceXml.MAX_ROWS, sample)).length < EvidenceXml.MAX_FILE);
        byte[] xml = EvidenceXml.encode(List.of(sample, sample));
        check(Arrays.equals(xml, EvidenceXml.encode(List.of(sample, sample))));
        Path dir = Path.of(args[0]);
        Path destination = dir.resolve("export.xml");
        EvidenceXml.saveNew(destination, xml);
        check(Arrays.equals(xml, Files.readAllBytes(destination)));
        if (Files.getFileAttributeView(dir, PosixFileAttributeView.class) != null)
            check("rw-------".equals(PosixFilePermissions.toString(Files.getPosixFilePermissions(destination))));
        try { EvidenceXml.saveNew(destination, new byte[]{4}); throw new AssertionError(); }
        catch (FileAlreadyExistsException expected) { check(Arrays.equals(xml, Files.readAllBytes(destination))); }
        try (var files = Files.list(dir)) { check(files.count() == 1); }
        System.out.println("Burp registration, menu, scope, bounds, binary export and exclusive writes passed.");
    }
}
