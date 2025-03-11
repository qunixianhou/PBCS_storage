package org.example;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class E2seMain {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Too few arguments!");
            System.out.println("Try: java -cp target/classes org.example.E2seMain authserver");
            System.out.println("Try: java -cp target/classes org.example.E2seMain client ./DataFile/source");
            System.out.println("Try: java -cp target/classes org.example.E2seMain view");
            return;
        }

        String bucketName = "test-bucket";
        String localS3Path = args.length > 3 ? args[3] : "DataFile/local-s3";
        Scanner scanner = new Scanner(System.in);

        if (args[0].equals(Constants.AUTH_SERVER)) {
            AuthServer authServer = new AuthServer();
            authServer.start();
        } else if (args[0].equals(Constants.CLIENT)) {
            if (args.length < 2) {
                System.out.println("Client mode requires source file path!");
                return;
            }
            String sourceFilePath = args[1];
            File sourceFile = new File(sourceFilePath);
            if (!sourceFile.exists()) {
                System.out.println("Source file does not exist: " + sourceFilePath);
                return;
            }

            // 用户输入 userID 和 passphrase
            System.out.print("Enter your user ID: ");
            String userID = scanner.nextLine().trim();
            System.out.print("Enter your passphrase: ");
            String passphrase = scanner.nextLine().trim();

            Client client = new Client(bucketName, localS3Path, userID);
            client.start(sourceFilePath, passphrase);
        } else if (args[0].equals("view")) {
            // 用户输入 userID 和 passphrase
            System.out.print("Enter your user ID: ");
            String userID = scanner.nextLine().trim();
            System.out.print("Enter your passphrase: ");
            String passphrase = scanner.nextLine().trim();

            Client client = new Client(bucketName, localS3Path, userID);
            client.view(passphrase);
        } else {
            System.out.println("Unknown command: " + args[0]);
        }
    }
}