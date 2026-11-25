// © Nasser Aldin Farag (0xFarag). All rights reserved.
package ch.zeroxfarag.authzledger.handoff;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import com.sun.net.httpserver.HttpServer;
import javax.swing.JMenuItem;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.function.Function;

public final class HandoffTest {
    static void check(boolean yes) { if (!yes) throw new AssertionError(); }
    static <T> T mock(Class<T> type, Function<String,Object> method) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (self, m, args) -> method.apply(m.getName())));
    }
    static Object unused(String name) { throw new AssertionError("Unexpected Montoya access: " + name); }

    static HttpRequestResponse capture(String url) {
        var req = mock(HttpRequest.class, method -> switch(method) {
            case "isInScope" -> true;
            case "url" -> url;
            case "method" -> "GET";
            default -> unused(method); // Any header, body, cookie, or raw-request method fails the test.
        });
        var res = mock(HttpResponse.class, method -> method.equals("statusCode") ? (short)403 : unused(method));
        return mock(HttpRequestResponse.class, method -> switch(method) {
            case "request" -> req; case "response" -> res; case "hasResponse" -> true; default -> unused(method);
        });
    }

    static void invalid(Runnable task) {
        try { task.run(); throw new AssertionError("Invalid value accepted"); } catch (IllegalArgumentException expected) { }
    }

    public static void main(String[] args) throws Exception {
        var allow = ObservationBatch.allowlist("engagement.example.test, example.test");
        var one = capture("https://engagement.example.test/invoices/1042?token=redsecret#fragment");
        var two = capture("https://engagement.example.test/invoices/1043");
        var menu = new AuthzLedgerHandoff().provideMenuItems(mock(ContextMenuEvent.class, name -> switch(name) {
            case "invocationType" -> InvocationType.PROXY_HISTORY; case "selectedRequestResponses" -> List.of(one, two);
            default -> unused(name);
        }));
        check(menu.size() == 1 && ((JMenuItem)menu.getFirst()).getText().equals("An AuthzLedger übergeben"));
        var rows = ObservationBatch.selected(List.of(one, two), allow);
        var body = ObservationBatch.json(rows, Set.of(rows.getFirst().id()));
        check(rows.size()==2 && body.contains("/invoices/1042") && body.contains("/invoices/1043"));
        check(body.contains("\"marker\":true") && body.contains("\"marker\":false"));
        for (var secret : List.of("redsecret","fragment","cookie","Authorization","Bearer","body","headers")) check(!body.contains(secret));
        check(ObservationBatch.json(rows, Set.of()).indexOf(":true") < 0);
        check(ObservationBatch.path("/api/abc123sensitive").matches("/api/redacted-[a-f0-9]{24}"));
        for (var path : List.of("/api/%2fsecret", "/api/%0Dheader", "//account", "/api/../invoices", "/api/%25value"))
            invalid(() -> ObservationBatch.path(path));
        invalid(() -> ObservationBatch.selected(List.of(one,capture("https://engagement.example.test.evil.test/")), allow));
        invalid(() -> ObservationBatch.selected(List.of(capture("https://alice:private@engagement.example.test/")), allow));
        for (var target : List.of("http://example.test/api/proof-import", "https://example.test/a",
                "https://user@e.test/api/proof-import", "https://e.test/api/proof-import?token=1",
                "https://e.test/api/proof-import#x")) invalid(() -> Handoff.destination(target));

        AtomicInteger hits = new AtomicInteger(), redirected = new AtomicInteger(), code = new AtomicInteger(200);
        String token = "fixture_token_12345678";
        HttpServer fixture = HttpServer.create(new InetSocketAddress("127.0.0.1", 0),0);
        var url = Handoff.destination("http://127.0.0.1:" + fixture.getAddress().getPort() + "/api/proof-import");
        fixture.createContext("/api/proof-import", x -> {
            hits.incrementAndGet();
            check(x.getRequestMethod().equals("POST"));
            check(x.getRequestHeaders().getFirst("Authorization").equals("Bearer " + token));
            check(x.getRequestHeaders().getFirst("Cookie") == null);
            check(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).equals(body));
            x.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            x.getResponseHeaders().set("Location", "/unexpected");
            var reply = (code.get() == 202 ? "{}" : "{\"runId\":\"r1\",\"accepted\":2}").getBytes(StandardCharsets.UTF_8);
            x.sendResponseHeaders(code.get(), reply.length);
            try (var output = x.getResponseBody()) { output.write(reply); }
        });
        fixture.createContext("/unexpected", x -> {redirected.incrementAndGet();x.sendResponseHeaders(204,-1);x.close();});
        fixture.start();
        try {
            Handoff.send(url, token, body, 2);
            for (int status : List.of(401,307,202,500)) {
                code.set(status);
                try { Handoff.send(url,token,body,2);throw new AssertionError("HTTP error silently accepted"); }
                catch (IOException expected) { check(expected.getMessage().equals("HTTP " + status)); }
            }
            check(hits.get()==5 && redirected.get()==0);
        } finally { fixture.stop(0); }
        if (args.length == 2) {
            var real = Handoff.destination(args[1]);
            var grant = System.getenv("WORKBENCH_FIXTURE_TOKEN");
            Handoff.send(real, grant, body, 2);
            try { Handoff.send(real, grant, body, 2); throw new AssertionError("Token reusable"); }
            catch (IOException expected) { check(expected.getMessage().equals("HTTP 401")); }
        }
        Files.writeString(Path.of(args[0]), body);
        System.out.println("Selected metadata, independent markers, denied hosts, 401 and no redirects verified.");
    }
}
