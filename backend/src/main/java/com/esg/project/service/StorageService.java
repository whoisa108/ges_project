package com.esg.project.service;

import io.minio.BucketExistsArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class StorageService {
    private final MinioClient minioClient;
    private final String bucket;

    public StorageService(
            @Value("${minio.url}") String url,
            @Value("${minio.access-key}") String accessKey,
            @Value("${minio.secret-key}") String secretKey,
            @Value("${minio.bucket-name}") String bucket) {
        this.bucket = bucket;
        this.minioClient = MinioClient.builder()
                .endpoint(url)
                .credentials(accessKey, secretKey)
                .build();
    }

    @PostConstruct
    public void init() {
        try {
            if (!minioClient.bucketExists(BucketExistsArgs.builder().bucket(bucket).build())) {
                minioClient.makeBucket(MakeBucketArgs.builder().bucket(bucket).build());
            }
        } catch (Exception e) { System.err.println("MinIO Init Delayed: " + e.getMessage()); }
    }

    public String uploadFile(MultipartFile file, String fileName) {
        try {
            minioClient.putObject(PutObjectArgs.builder()
                .bucket(bucket).object(fileName)
                .stream(file.getInputStream(), file.getSize(), -1)
                .contentType(file.getContentType())
                .build());
            return fileName;
        } catch (Exception e) { throw new RuntimeException("Upload failed", e); }
    }

    public io.minio.GetObjectResponse getFile(String fileName) {
        try {
            return minioClient.getObject(io.minio.GetObjectArgs.builder()
                .bucket(bucket).object(fileName).build());
        } catch (Exception e) { throw new RuntimeException("Download failed", e); }
    }

    public void deleteFile(String fileName) {
        try {
            minioClient.removeObject(io.minio.RemoveObjectArgs.builder()
                .bucket(bucket).object(fileName).build());
        } catch (Exception e) { System.err.println("File deletion failed: " + e.getMessage()); }
    }
}
