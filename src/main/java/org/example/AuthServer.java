package org.example;

import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class AuthServer {
    private static final boolean verbose = true;
    private static AuthServer instance;
    final private static SimpleEcCurve SIMPLE_EC_CURVE = new SimpleEcCurve(Constants.CURVE_NAME);
    final private static String mSecretKey = "addd";

    // 使用 ConcurrentHashMap 确保线程安全
    private final ConcurrentHashMap<String, UserRecord> usersRec = new ConcurrentHashMap<>();
    final ConcurrentHashMap<String, UserRegister> usersReg = new ConcurrentHashMap<>();

    class UserRecord {
        byte[] tao, ct;
        int c;
        public UserRecord(byte[] tao, byte[] ct) {
            this.tao = tao;
            this.ct = ct;
            this.c = 0;
        }
    }

    class UserRegister {
        byte[] t;
        int c;
        public UserRegister(byte[] t) {
            this.t = t;
            this.c = 0;
        }
    }

    AuthServer() {}

    public static AuthServer getInstance() {
        if (instance == null) {
            synchronized (AuthServer.class) {
                if (instance == null) {
                    instance = new AuthServer();
                }
            }
        }
        return instance;
    }

    public void start() throws Exception {
        String msg = "AuthServer starting on port " + Constants.AUTH_SERVER_PORT_NUMBER + "...";
        System.out.println(msg);

        ServerSocket serverListener = null;
        try {
            serverListener = new ServerSocket(Constants.AUTH_SERVER_PORT_NUMBER);
            System.out.println("AuthServer successfully bound to port " + Constants.AUTH_SERVER_PORT_NUMBER);

            while (true) {
                Socket clientSocket = serverListener.accept();
                if (verbose) System.out.println("Client connected from " + clientSocket.getInetAddress());

                InputStream in = clientSocket.getInputStream();
                byte requestType = (byte) in.read();

                int useridLength = in.read();
                byte[] userIDBytes = new byte[useridLength];
                in.read(userIDBytes);
                String userID = new String(userIDBytes);

                System.out.println("Request type: " + requestType + ", UserID: " + userID);

                switch (requestType) {
                    case Constants.REQ_TYPE_AUTHSERVER_OPRF:
                        if (verbose) System.out.println("Received a OPRF Request.");
                        byte[] ecPBytes = new byte[in.read()];
                        in.read(ecPBytes);
                        ECPoint ecPoint = SIMPLE_EC_CURVE.ecDomainParameters.getCurve().decodePoint(ecPBytes);
                        BigInteger keyId = SIMPLE_EC_CURVE.hashToGroup2(mSecretKey.getBytes(StandardCharsets.UTF_8), userIDBytes);
                        ECPoint bEcPoint = ecPoint.multiply(keyId).normalize();
                        byte[] bytebEcPiont = bEcPoint.getEncoded(true);
                        clientSocket.getOutputStream().write(Constants.RESP_TYPE_OK);
                        clientSocket.getOutputStream().write(bytebEcPiont.length);
                        clientSocket.getOutputStream().write(bytebEcPiont);
                        if (verbose) System.out.println("OPRF derivation request for " + userID + " succeeded.");
                        break;

                    case Constants.REQ_TYPE_AUTHSERVER_REGISTER:
                        if (verbose) System.out.println("Received a Register Request.");
                        byte[] t = new byte[in.read()];
                        in.read(t);
                        if (usersReg.containsKey(userID)) {
                            System.out.println("User " + userID + " already registered. Register request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                        } else {
                            usersReg.put(userID, new UserRegister(t));
                            if (verbose) System.out.println("Register for " + userID + " succeeded.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_OK);
                        }
                        break;

                    case Constants.REQ_TYPE_AUTHSERVER_DEPOSIT:
                        if (verbose) System.out.println("Received a Deposit Request.");
                        if (!usersReg.containsKey(userID)) {
                            System.out.println("User " + userID + " did not register. Deposit request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }
                        if (usersRec.containsKey(userID)) {
                            System.out.println("User " + userID + " already deposited. Deposit request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }
                        byte[] tReceive = new byte[in.read()];
                        in.read(tReceive);
                        UserRegister userR = usersReg.get(userID);
                        if (!Arrays.equals(userR.t, tReceive)) {
                            System.out.println("User " + userID + " did not enter a valid password. Deposit request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }
                        byte[] tao = new byte[in.read()];
                        in.read(tao);
                        byte[] ct = new byte[in.read()];
                        in.read(ct);
                        usersRec.put(userID, new UserRecord(tao, ct));
                        if (verbose) System.out.println("Deposit for " + userID + " succeeded.");
                        clientSocket.getOutputStream().write(Constants.RESP_TYPE_OK);
                        break;

                    case Constants.REQ_TYPE_AUTHSERVER_RETRIEVAL:
                        if (verbose) System.out.println("Received a Retrieval Request.");
                        byte[] tReceiveRetrieval = new byte[Constants.R_LENGTH];
                        in.read(tReceiveRetrieval);
                        if (!usersReg.containsKey(userID)) {
                            System.out.println("User " + userID + " did not register. Retrieval request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }
                        if (!usersRec.containsKey(userID)) {
                            System.out.println("User " + userID + " did not deposit a key. Retrieval request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }
                        UserRegister userReg = usersReg.get(userID);
                        if (!Arrays.equals(userReg.t, tReceiveRetrieval)) {
                            System.out.println("User " + userID + " did not enter a correct password. Retrieval request ignored.");
                            clientSocket.getOutputStream().write(Constants.RESP_TYPE_ERROR);
                            break;
                        }
                        UserRecord userC = usersRec.get(userID);
                        clientSocket.getOutputStream().write(Constants.RESP_TYPE_OK);
                        clientSocket.getOutputStream().write(userC.ct.length);
                        clientSocket.getOutputStream().write(userC.ct);
                        clientSocket.getOutputStream().write(userC.tao.length);
                        clientSocket.getOutputStream().write(userC.tao);
                        if (verbose) System.out.println("Retrieval request for " + userID + " succeeded.");
                        clientSocket.getOutputStream().write(Constants.RESP_TYPE_OK);
                        break;

                    default:
                        System.out.println("Received an unknown request: " + requestType);
                        break;
                }

                clientSocket.close();

                if (Thread.interrupted()) {
                    break;
                }

                if (serverListener.isClosed()) {
                    break;
                }
            }
        } catch (Exception e) {
            System.err.println("Error in AuthServer loop: " + e.getMessage());
            e.printStackTrace();
            throw e;
        } finally {
            if (serverListener != null && !serverListener.isClosed()) {
                try {
                    serverListener.close();
                } catch (IOException e) {
                    System.out.println("Error closing server socket: " + e.getMessage());
                }
            }
        }
    }

    public boolean isUserRegistered(String userId) {
        return usersReg.containsKey(userId);
    }

    public boolean authenticateUser(String userId, String passphrase) throws Exception {
        UserRegister user = usersReg.get(userId);
        if (user == null) return false;

        Client tempClient = new Client("temp-bucket", "DataFile/local-s3", userId);
        String hardenedPWD = tempClient.ibOPRF(userId, passphrase);
        byte[] computedT = Utils.KDF(tempClient.take(userId, passphrase, "temp-bucket", userId + "/rid", userId + "/sid"),
                passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, Constants.KDF_HASH_REPETITIONS);
        return Arrays.equals(computedT, user.t);
    }

    public List<String> getRegisteredUserIds() {
        List<String> users = new ArrayList<>(usersReg.keySet());
        System.out.println("Registered users in AuthServer: " + users);
        return users;
    }
}