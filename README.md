# ESG Idea Competition Proposal Website

> [!IMPORTANT]
> **AI Agents**: Please read [CONTRIBUTING_AGENTS.md](file:///home/jpeng/projects/esg_collection/esg_project/CONTRIBUTING_AGENTS.md) before starting any task. It contains critical workflow and architectural alignment instructions.

A web application designed for an ESG (Environmental, Social, and Governance) idea competition. Employees can register, setup their accounts, and submit innovative ideas to contribute to the company's ESG goals.

## 🚀 Features

### For Proposers (Employees)
- **Account Setup**: Register with unique employee ID and department.
- **Idea Submission**: Upload ideas with titles, summaries, and supporting documents (PDF/PPT).
- **Team Management**: Form teams of 1-5 members.
- **Deadline Awareness**: Real-time countdown to the submission deadline.
- **Manage Submissions**: View, edit, and delete personal proposals.

### For Administrators
- **User Management**: Monitor and manage registered users.
- **Proposal Oversight**: Review and delete submitted proposals.
- **Deadline Control**: Set and update the competition end time.

### Security & Audit
- **Authentication**: JWT-based security for both frontend and backend.
- **Validation**: Strict size limits (5MB) and format requirements for uploads.
- **Audit Logs**: Comprehensive tracking of all critical API actions.

## 🛠 Tech Stack

- **Frontend**: React + Vite (Vanilla CSS for premium design)
- **Backend**: Java Spring Boot
- **Database**: MongoDB
- **File Storage**: MinIO (Object Storage)
- **Deployment**: Docker Compose

## 📦 Project Structure

```text
esg_project/
├── backend/            # Spring Boot Application
├── frontend/           # React + Vite Application
├── docker-compose.yml  # Infrastructure (MongoDB, MinIO)
└── README.md           # Project Documentation
```

## 🛠 Setup & Development

### Prerequisites
- Docker & Docker Compose
- JDK 17+
- Node.js 18+

### 1. Infrastructure
Start the database and storage services:
```bash
docker-compose up -d
```

### 2. Backend
```bash
cd backend
./mvnw spring-boot:run
```


### 3. Frontend
```bash
cd frontend
npm install
npm run dev
```

## 📖 API Documentation

The backend includes interactive API documentation powered by Swagger/OpenAPI.

1. **Access Swagger UI**: [http://localhost:8080/swagger-ui/index.html](http://localhost:8080/swagger-ui/index.html)
2. **Access OpenAPI Spec (JSON)**: [http://localhost:8080/v3/api-docs](http://localhost:8080/v3/api-docs)

The UI lists all available endpoints for:
- `AdminController`
- `AuthController`
- `ProposalController`

> [!TIP]
> Use the **Authorize** button in Swagger UI to provide a JWT token (from `/api/auth/login`) to test protected endpoints.

## 📝 Configuration

- **MinIO**: Accessible at `localhost:9000` (Console at `localhost:9001`)
- **MongoDB**: Accessible at `localhost:27017`
- **Default Admin**: `admin` / `admin123` (Initial setup)
