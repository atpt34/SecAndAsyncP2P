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

//        System.out.println(remoteCert.getModulus());

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
