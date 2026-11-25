// © Nasser Aldin Farag (0xFarag). All rights reserved.
package ch.zeroxfarag.authzledger.handoff;

import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.Flow;
import java.util.regex.Pattern;

final class Handoff {
    static URI destination(String value) {
        URI uri;
        try { uri = URI.create(value); } catch (IllegalArgumentException e) { throw invalid(); }
        if (uri.getHost() == null || uri.getRawAuthority().endsWith(":") || uri.getRawUserInfo() != null || uri.getRawFragment() != null
                || uri.getRawQuery() != null || !"/api/proof-import".equals(uri.getRawPath())
                || uri.getPort() == 0 || uri.getPort() > 65535) throw invalid();
        boolean local = "127.0.0.1".equals(uri.getHost()) || "[::1]".equals(uri.getHost());
        if (!"https".equals(uri.getScheme()) && !("http".equals(uri.getScheme()) && local)) throw invalid();
        return uri;
    }

    static void send(URI destination, String token, String body, int expected) throws Exception {
        destination(destination.toASCIIString());
        if (token == null || !token.matches("[A-Za-z0-9._~-]{16,512}"))
            throw new IllegalArgumentException("Das Workspace-Token ist ungültig.");
        if (body.length() > 1_048_576) throw new IllegalArgumentException("Auswahl zu gross.");
        var request = HttpRequest.newBuilder(destination).timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + token).header("Content-Type", "application/json")
                .header("Accept", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
        try (var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4))
                .proxy(ProxySelector.of(null)).followRedirects(HttpClient.Redirect.NEVER).build()) {
            var task = client.sendAsync(request, info -> new BoundedReply());
            try {
                var reply = task.get(12, TimeUnit.SECONDS);
                if (reply.statusCode() != 200) throw new IOException("HTTP " + reply.statusCode());
                String type = reply.headers().firstValue("Content-Type").orElse("").split(";", 2)[0].strip();
                String ack = new String(reply.body(), StandardCharsets.UTF_8);
                String count = "\"accepted\"\\s*:\\s*" + expected, run = "\"runId\"\\s*:\\s*\"[A-Za-z0-9_.-]{1,128}\"";
                if (!type.equalsIgnoreCase("application/json") || !Pattern.matches(
                        "\\s*\\{\\s*(?:" + count + "\\s*,\\s*" + run + "|" + run + "\\s*,\\s*" + count + ")\\s*}\\s*", ack))
                    throw new IOException("Der Server hat die Übernahme nicht bestätigt.");
            } catch (TimeoutException e) {
                task.cancel(true);
                throw new IOException("Zeitüberschreitung.");
            } catch (InterruptedException e) {
                task.cancel(true);
                Thread.currentThread().interrupt();
                throw e;
            } catch (ExecutionException e) {
                throw new IOException("Die Übergabe ist fehlgeschlagen.");
            }
        }
    }

    private static final class BoundedReply implements HttpResponse.BodySubscriber<byte[]> {
        final HttpResponse.BodySubscriber<byte[]> delegate = HttpResponse.BodySubscribers.ofByteArray();
        Flow.Subscription subscription;
        int remaining = 4096;
        public CompletionStage<byte[]> getBody() { return delegate.getBody(); }
        public void onSubscribe(Flow.Subscription s) { subscription = s; delegate.onSubscribe(s); }
        public void onNext(List<ByteBuffer> buffers) {
            for (var buffer : buffers) {
                if (buffer.remaining() > remaining) {
                    subscription.cancel();
                    delegate.onError(new IOException("Antwort zu gross."));
                    return;
                }
                remaining -= buffer.remaining();
            }
            delegate.onNext(buffers);
        }
        public void onError(Throwable cause) { delegate.onError(cause); }
        public void onComplete() { delegate.onComplete(); }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Ziel muss die HTTPS-URL /api/proof-import des Workspace sein. HTTP ist nur auf 127.0.0.1 oder [::1] möglich.");
    }
}
