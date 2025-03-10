package org.example;

public class E2seMain {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Too few arguments!");
            System.out.println("Try: java -cp target/classes org.example.E2seMain authserver");
            System.out.println("Try: java -cp target/classes org.example.E2seMain client ./DataFile/source");
            return;
        }

        String bucketName = "test-bucket";
        String sourceFilePath = args[1];
        String localS3Path = args.length > 2 ? args[2] : "DataFile/local-s3";
        if (args[0].equals(Constants.CLIENT)) {
            System.out.println("authserverName:  " + Constants.AUTH_SERVER_NAME);
            Client client = new Client(bucketName, localS3Path);
            client.start(sourceFilePath); // 单次运行，便于调试
        }
    }
}