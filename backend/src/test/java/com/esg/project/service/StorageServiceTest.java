package com.esg.project.service;

import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.RemoveObjectArgs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class StorageServiceTest {

    private StorageService storageService;

    @Mock
    private MinioClient minioClient;

    @BeforeEach
    void setUp() {
        storageService = new StorageService("http://localhost:9000", "acc", "sec", "bucket");
        ReflectionTestUtils.setField(storageService, "minioClient", minioClient);
    }

    @Test
    void uploadFile_CallsMinio() throws Exception {
        MultipartFile file = mock(MultipartFile.class);
        when(file.getInputStream()).thenReturn(new ByteArrayInputStream("test".getBytes()));
        when(file.getSize()).thenReturn(4L);
        when(file.getContentType()).thenReturn("application/pdf");

        String result = storageService.uploadFile(file, "test.pdf");

        assertThat(result).isEqualTo("test.pdf");
        verify(minioClient).putObject(any(PutObjectArgs.class));
    }

    @Test
    void deleteFile_CallsMinio() throws Exception {
        storageService.deleteFile("test.pdf");
        verify(minioClient).removeObject(any(RemoveObjectArgs.class));
    }
}
