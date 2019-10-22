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

        if (args.length < 3) {
            System.out.println("Usage: java Main server/client host port");
            return;
        }

        // input data validation!
        String type = args[0];
        String host = args[1];
        int port = Integer.parseInt(args[2]);

        ExecutorService pool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        final RSAService.RSAPrivateKey cert;
        CompletableFuture<RSAService.RSAPrivateKey> certFuture =
                CompletableFuture.supplyAsync(RSAService::generatePrivateKey, pool);
        CompletableFuture<String> certB64Future = certFuture
                .thenApply(key -> EncryptionWithSignatureService.publicKeyToString(key.getPublicKey()));

        final RSAService.RSAPublicKey remoteCert;

        BufferedReader in;
        PrintWriter out;

        try {
            if ("server".equals(type)) {
                ServerSocket serverSocket = new ServerSocket(port);
                Socket clientSocket = serverSocket.accept();
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                cert = certFuture.join();
                out.println(certB64Future.join());
                remoteCert = EncryptionWithSignatureService.publicKeyFromString(in.readLine());
            } else {
                Socket socket = new Socket(host, port);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);
                remoteCert = EncryptionWithSignatureService.publicKeyFromString(in.readLine());
                cert = certFuture.join();
                out.println(certB64Future.join());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        System.out.println(remoteCert.getModulus());

        pool.submit(input(out, remoteCert, pool));
        pool.submit(output(in, cert, pool));

        // no close socket or stream
        // terminate by tcp connection timeout !

    }

    private static Runnable input(PrintWriter out, RSAService.RSAPublicKey remoteKey, ExecutorService executorService) {
        return () -> {
            Scanner scanner = new Scanner(System.in);
            String input;
            do {
                input = scanner.nextLine();
                final String line = input;
                executorService.submit(() -> out.println(EncryptionWithSignatureService.encrypt(line, remoteKey)));
            } while (!"\\q".equals(input));
            try {
                executorService.shutdown();
                executorService.awaitTermination(1, TimeUnit.MILLISECONDS);
                executorService.shutdownNow();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        };
    }

    private static Runnable output(BufferedReader in, RSAService.RSAPrivateKey key, ExecutorService executorService) {
        return () -> {
            try {
                String output = in.readLine();
                executorService.submit(output(in, key, executorService));
                final String line = EncryptionWithSignatureService.decrypt(output, key);
                System.out.println(line);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }
}
