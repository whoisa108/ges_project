# Backend Testing Documentation

這是 ESG 專案後端測試的綜合指南，說明了測試架構、工具使用以及如何維護測試覆蓋率。

## 1. 測試哲學 (Testing Philosophy)

我們主要採用 **單元測試 (Unit Testing)**，核心原則如下：
- **隔離性**：不依賴真實的資料庫 (MongoDB) 或外部服務 (MinIO)。
- **Mocking**：使用 Mockito 來模擬相依組件的行為。
- **速度**：測試應該在幾秒鐘內執行完畢，以便在開發過程中頻繁執行。
- **穩定性**：測試結果不應受到網路環境或外部狀態影響。

## 2. 工具棧 (Testing Stack)

| 工具 | 用途 |
| :--- | :--- |
| **JUnit 5** | 核心測試框架 (Annotations like `@Test`, `@BeforeEach`) |
| **Mockito** | Mocking 框架，用於模擬 Repository 和 Service |
| **MockMvc** | Spring 提供的工具，用於測試 Controller 而不需要啟動完整 Web Server |
| **JaCoCo** | 程式碼覆蓋率分析工具，整合在 Maven 中 |
| **AssertJ** | 提供更具可讀性的斷言語法 (`assertThat(...)`) |

## 3. 測試覆蓋率要求 (Coverage Requirements)

我們在 `pom.xml` 中設定了嚴格的守門規則：
- **最低門檻**：總體行覆蓋率 (Line Coverage) 必須 **> 80%**。
- **自動驗證**：執行 `mvn verify` 時，若未達標則會導致 Build Failure。

### 排除規則 (Exclusions)
為了讓測試聚焦在真正的業務邏輯，我們排除了以下不需要測試的類別：
- `model/**`：純實體類別（已使用 Lombok 自動產生 Getter/Setter）。
- `dto/**`：資料傳輸類別。
- `config/**`：Spring 配置類別。
- `repository/**`：Spring Data 介面（由框架保證正確性）。
- `DemoApplication.class`：應用啟動類。

## 4. 如何執行測試 (How to Run)

### 執行所有測試並檢查覆蓋率
```bash
mvn clean verify
```

### 僅執行測試 (不檢查覆蓋率門檻)
```bash
mvn test
```

## 5. 檢視報告 (How to Read Report)

每次執行 `mvn verify` 或 `mvn report` 後，JaCoCo 會產生網頁版報告：
- **路徑**：`backend/target/site/jacoco/index.html`
- **內容**：你可以點進包名 (Package) 與類別名，查看具體哪一行程式碼（綠色為已覆蓋，紅色為未覆蓋）。

## 6. 已實作的測試內容

### Services
- `ProposalServiceTest`：涵蓋了截止日期判斷、管理權限、檔案邏輯。
- `AuthServiceTest`：涵蓋了登入、註冊、Token 邏輯。
- `AdminServiceTest`：涵蓋了用戶管理與截止日期設定。

### Controllers
- `ProposalControllerTest`：使用 MockMvc 測試 REST API 接口。
- `AuthControllerTest`：測試註冊與登入的 HTTP 回應。
- `AdminControllerTest`：測試管理介面的 API。

### Infrastructure
- `JwtServiceTest`：測試 JWT 的產生與解析。
- `StorageServiceTest`：模擬 MinIO 檔案上傳行為。

## 7. 常見問題與技巧

### 為什麼測試會報 403 (Forbidden)?
因為許多 Controller 會調用 `SecurityContextHolder.getContext().getAuthentication().getPrincipal()`。在單元測試中，你需要手動 Mock 這個 Context：
```java
Authentication auth = mock(Authentication.class);
when(auth.getPrincipal()).thenReturn(mockUser);
SecurityContextHolder.getContext().setAuthentication(auth);
```

### 如何測試選填參數 (Optional Parameters)?
當使用 Mockito 且參數可能為 null 時，請使用 `ArgumentMatchers.any()` 而非 `anyString()`。
