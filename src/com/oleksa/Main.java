package com.oleksa;

import com.oleksa.service.EncryptionWithSignatureService;
import com.oleksa.service.RSAService;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.concurrent.*;

public class Main {

    public static void main(String[] args) {

        if (args.length < 3 ||
                !args[0].matches("(server)|(client)") ||
                !args[1].matches("[0-9A-Za-z.-:]+") ||
                !args[2].matches("[0-9]+")) {
            System.out.println("Usage: java Main server/client host port");
            return;
        }

        final String type = args[0];
        final String host = args[1];
        final int port = Integer.parseInt(args[2]);

        final ExecutorService pool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        CompletableFuture<RSAService.RSAPrivateKey> certFuture =
                CompletableFuture.supplyAsync(RSAService::generatePrivateKey, pool);
        CompletableFuture<String> certB64Future = certFuture
                .thenApply(key -> EncryptionWithSignatureService.publicKeyToString(key.getPublicKey()));

        final RSAService.RSAPrivateKey cert;
        final RSAService.RSAPublicKey remoteCert;

        final BufferedReader in;
        final PrintWriter out;

        try {
            if ("server".equals(type)) {
                ServerSocket serverSocket = new ServerSocket(port);
                Socket clientSocket = serverSocket.accept();
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            } else {
                Socket socket = new Socket(host, port);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);
            }
            CompletableFuture<Void> certExchange = certB64Future
                    .thenAccept(out::println);
            System.out.println("Starting certificate exchange...");
            remoteCert = EncryptionWithSignatureService.publicKeyFromString(in.readLine());
            cert = certFuture.join();
            certExchange.join();
            System.out.println("... done!");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        pool.submit(input(out, remoteCert, cert, pool));
        pool.submit(output(in, cert, remoteCert, pool));

        // no close socket or stream
        // terminate by tcp connection timeout !
    }

    private static Runnable input(PrintWriter out, RSAService.RSAPublicKey remoteKey, RSAService.RSAPrivateKey key, ExecutorService executorService) {
        return () -> {
            try {
                Scanner scanner = new Scanner(System.in);
                String input;
                do {
                    input = scanner.nextLine();
                    final String line = input;
                    if ("\\q".equals(input)) {
                        break;
                    }
                    executorService.submit(() -> out.println(EncryptionWithSignatureService.encryptWithSignature(line, remoteKey, key, executorService)));
                } while (true);

                executorService.shutdown();
                executorService.shutdownNow();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    private static Runnable output(BufferedReader in, RSAService.RSAPrivateKey key, RSAService.RSAPublicKey remoteKey, ExecutorService executorService) {
        return () -> {
            try {
                String output = in.readLine();
                executorService.submit(output(in, key, remoteKey, executorService));
                final String line = EncryptionWithSignatureService.decryptWithSignature(output, key, remoteKey, executorService);
                System.out.println(line);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }
}
