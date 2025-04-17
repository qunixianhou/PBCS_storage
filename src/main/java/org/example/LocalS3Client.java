package org.example;

import java.io.*;
import java.nio.file.*;
import java.util.HashMap;
import java.util.Map;

public class LocalS3Client {
    private final String baseDirectory;
    private final Map<String, Boolean> accelerateConfig;

    // 模拟的请求类
    public static class PutObjectRequest {
        private final String bucketName;
        private final String key;
        private final File file;
        private final InputStream inputStream;
        private final ObjectMetadata metadata;

        public PutObjectRequest(String bucketName, String key, File file) {
            this(bucketName, key, file, null, null);
        }

        public PutObjectRequest(String bucketName, String key, InputStream inputStream, ObjectMetadata metadata) {
            this(bucketName, key, null, inputStream, metadata);
        }

        private PutObjectRequest(String bucketName, String key, File file, InputStream inputStream, ObjectMetadata metadata) {
            this.bucketName = bucketName;
            this.key = key;
            this.file = file;
            this.inputStream = inputStream;
            this.metadata = metadata;
        }

        public String getBucketName() { return bucketName; }
        public String getKey() { return key; }
        public File getFile() { return file; }
        public InputStream getInputStream() { return inputStream; }
        public ObjectMetadata getMetadata() { return metadata; }
    }

    public static class GetObjectRequest {
        private final String bucketName;
        private final String key;

        public GetObjectRequest(String bucketName, String key) {
            this.bucketName = bucketName;
            this.key = key;
        }

        public String getBucketName() { return bucketName; }
        public String getKey() { return key; }
    }

    public static class SetBucketAccelerateConfigurationRequest {
        private final String bucketName;
        private final BucketAccelerateConfiguration configuration;

        public SetBucketAccelerateConfigurationRequest(String bucketName,
                                                       BucketAccelerateConfiguration configuration) {
            this.bucketName = bucketName;
            this.configuration = configuration;
        }

        public String getBucketName() { return bucketName; }
        public BucketAccelerateConfiguration getConfiguration() { return configuration; }
    }

    public static class BucketAccelerateConfiguration {
        private final String status;

        public BucketAccelerateConfiguration(String status) {
            this.status = status;
        }

        public String getStatus() { return status; }
    }

    public static class ObjectMetadata {
        private long contentLength;

        public void setContentLength(long length) {
            this.contentLength = length;
        }

        public long getContentLength() {
            return contentLength;
        }
    }

    public static class S3Object {
        private final File file;

        public S3Object(File file) {
            this.file = file;
        }

        public InputStream getObjectContent() throws FileNotFoundException {
            return new FileInputStream(file);
        }
    }

    public LocalS3Client(String baseDir) {
        this.baseDirectory = baseDir;
        this.accelerateConfig = new HashMap<>();
        try {
            Files.createDirectories(Paths.get(baseDir));
        } catch (IOException e) {
            throw new RuntimeException("Failed to create base directory", e);
        }
    }

    public void putObject(PutObjectRequest request) {
        try {
            Path bucketPath = Paths.get(baseDirectory, request.getBucketName()).normalize();
            Files.createDirectories(bucketPath);
            Path targetPath = bucketPath.resolve(request.getKey()).normalize();
            Files.createDirectories(targetPath.getParent());

            if (request.getFile() != null) {
                Files.copy(request.getFile().toPath(), targetPath, StandardCopyOption.REPLACE_EXISTING);
                System.out.println("LocalS3: Put object to " + targetPath + " (size: " + Files.size(targetPath) + " bytes)");
            } else if (request.getInputStream() != null) {
                try (InputStream in = request.getInputStream();
                     OutputStream out = Files.newOutputStream(targetPath)) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    long totalBytes = 0;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                        totalBytes += bytesRead;
                    }
                    System.out.println("LocalS3: Put object to " + targetPath + " (size: " + totalBytes + " bytes)");
                }
            } else {
                throw new IllegalArgumentException("No valid input provided for putObject");
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to put object locally", e);
        }
    }

    public S3Object getObject(GetObjectRequest request) {
        try {
            Path filePath = Paths.get(baseDirectory, request.getBucketName(), request.getKey()).normalize();
            File file = filePath.toFile();

            if (!file.exists()) {
                throw new RuntimeException("Object not found: " + filePath);
            }

            System.out.println("LocalS3: Get object from " + filePath);
            return new S3Object(file);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get object locally", e);
        }
    }

    public void getObject(String bucketName, String key, String filePath) {
        try {
            Path sourcePath = Paths.get(baseDirectory, bucketName, key).normalize();
            File sourceFile = sourcePath.toFile();
            if (!sourceFile.exists()) {
                throw new RuntimeException("Object not found: " + sourcePath);
            }

            Path targetPath = Paths.get(filePath).normalize();
            Files.createDirectories(targetPath.getParent());
            Files.copy(sourcePath, targetPath, StandardCopyOption.REPLACE_EXISTING);

            System.out.println("LocalS3: Get object from " + sourcePath + " and saved to " + targetPath +
                    " (size: " + Files.size(targetPath) + " bytes)");
        } catch (IOException e) {
            throw new RuntimeException("Failed to get object and save to " + filePath, e);
        }
    }

    public void setBucketAccelerateConfiguration(SetBucketAccelerateConfigurationRequest request) {
        accelerateConfig.put(request.getBucketName(),
                "Enabled".equals(request.getConfiguration().getStatus()));
        System.out.println("LocalS3: Set accelerate configuration for " +
                request.getBucketName() + " to " + request.getConfiguration().getStatus());
    }

    public static class Builder {
        private String baseDir;

        public static Builder standard() {
            return new Builder();
        }

        public Builder withRegion(String region) {
            return this;
        }

        public Builder withCredentials(Object credentials) {
            return this;
        }

        public Builder enableAccelerateMode() {
            return this;
        }

        public LocalS3Client build() {
            if (baseDir == null) {
                baseDir = "DataFile/local-s3";
            }
            return new LocalS3Client(baseDir);
        }

        public Builder withBaseDirectory(String dir) {
            this.baseDir = dir;
            return this;
        }
    }
}
