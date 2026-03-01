# ESG Idea Competition API Specification

This document provides a detailed specification for the ESG Idea Competition backend API. It is designed to be easily understood by both human developers and AI agents.

**Base URL**: `http://localhost:8080/api` (Default development environment)

---

## Authentication & Security

The API uses **JWT (JSON Web Token)** for authentication.

1.  **Obtain Token**: Use the `/auth/login` endpoint with valid credentials. This returns a `token` and user metadata.
2.  **Use Token**: Include the token in the `Authorization` header of every request requiring authentication:
    `Authorization: Bearer <your_jwt_token>`
3.  **Roles**:
    *   `PROPOSER`: Standard employee role. Can create, view, edit, and delete their own proposals.
    *   `ADMIN`: Administrative role. Can manage all users, all proposals, system settings, and view audit logs.
4.  **Password Reset**: New accounts or reset accounts may have `needsPasswordReset: true`. The user must call `/auth/reset-password` before performing other actions.

---

## Data Models

### User
| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | String | Unique MongoDB document ID. |
| `employeeId` | String | Unique corporate employee identifier (used for login). |
| `name` | String | Full name of the user. |
| `department` | String | User's department. |
| `role` | String | `PROPOSER` or `ADMIN`. |
| `needsPasswordReset` | Boolean | True if the user must change their password on next login. |

### TeamMember
| Field | Type | Description |
| :--- | :--- | :--- |
| `name` | String | Full name of the team member. |
| `employeeId` | String | Employee identifier. |

### Proposal
| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | String | Unique identifier for the proposal. |
| `creatorId` | String | `employeeId` of the creator. |
| `creatorName` | String | Name of the creator. |
| `category` | String | ESG category (e.g., "Environmental", "Social", "Governance"). |
| `direction` | String | specific innovation direction. |
| `title` | String | Title of the proposal. |
| `summary` | String | Brief summary of the idea. |
| `fileName` | String | Name of the attached file in MinIO storage. |
| `teamMembers` | Array[TeamMember] | List of team members (max 5). |
| `createdAt` | ISO8601 String | Timestamp of creation. |

---

## Endpoints

### Authentication

#### POST /auth/register
**Summary**: Register a new user.
**Description**: Creates a new user account with the `PROPOSER` role. Fails if the `employeeId` already exists.
**Request Body**: `User` object (required: `employeeId`, `name`, `department`, `password`).
**Responses**:
*   `200 OK`: "User registered successfully"
*   `400 Bad Request`: "Employee ID already exists"

#### POST /auth/login
**Summary**: Authenticate and obtain a JWT.
**Description**: Validates credentials and returns a JWT token along with user profile information.
**Request Body**: `{ "employeeId": "...", "password": "..." }` <!-- pragma: allowlist secret -->
**Responses**:
*   `200 OK`: Returns token and user metadata.
    *   Example: `{ "token": "...", "role": "ADMIN", "name": "John Doe", "employeeId": "E123", "needsPasswordReset": false }`
*   `401 Unauthorized`: "Invalid credentials"

#### POST /auth/reset-password
**Summary**: Reset current user's password.
**Description**: Updates the password for the currently authenticated user and clears the `needsPasswordReset` flag.
**Security**: Requires Bearer Token.
**Request Body**: `{ "password": "<new_password>" }` <!-- pragma: allowlist secret -->
**Responses**:
*   `200 OK`: "Password updated"

---

### Proposals

#### GET /proposals
**Summary**: List proposals.
**Description**: Returns a list of proposals. `ADMIN` users see all proposals; `PROPOSER` users see only their own.
**Security**: Requires Bearer Token.
**Responses**:
*   `200 OK`: Array of `Proposal` objects.

#### POST /proposals
**Summary**: Submit a new proposal.
**Description**: Creates a new ESG proposal. Includes file upload (Max 5MB) and optional team members list. Fails if the title is a duplicate for the user or if the competition deadline has passed.
**Security**: Requires Bearer Token.
**Content-Type**: `multipart/form-data`
**Parameters (Form Data)**:
*   `title` (String, Required): Proposal title.
*   `category` (String, Required): e.g., "Environment".
*   `direction` (String, Required): Detailed direction.
*   `summary` (String, Required): Brief explanation.
*   `teamMembers` (JSON String, Optional): Serialized list of `TeamMember` objects.
*   `file` (File, Required): PDF or PPT document.
**Responses**:
*   `200 OK`: The created `Proposal` object.
*   `400 Bad Request`: Duplicate title, deadline passed, or invalid team format.

#### PUT /proposals/{id}
**Summary**: Update an existing proposal.
**Description**: Modifies an existing proposal. Only the creator can edit. File replacement is optional. Deadline check applies.
**Security**: Requires Bearer Token.
**Content-Type**: `multipart/form-data`
**Parameters (Form Data)**: Same as POST, but `file` is optional.
**Responses**:
*   `200 OK`: Updated `Proposal` object.
*   `403 Forbidden`: "Only creator can edit"
*   `404 Not Found`: Proposal ID doesn't exist.

#### DELETE /proposals/{id}
**Summary**: Delete a proposal.
**Description**: Removes a proposal and its associated file. Allowed for the creator or an `ADMIN`.
**Security**: Requires Bearer Token.
**Responses**:
*   `200 OK`: "Deleted"
*   `403 Forbidden`: "Forbidden" (if not owner or admin)
*   `404 Not Found`: Proposal ID doesn't exist.

#### GET /proposals/{id}/download
**Summary**: Download proposal file.
**Description**: Streams the attached file from storage. Allowed for the creator or an `ADMIN`.
**Security**: Requires Bearer Token.
**Responses**:
*   `200 OK`: File stream with appropriate `Content-Type`.
*   `403 Forbidden`
*   `404 Not Found`

---

### Admin Controls

#### GET /admin/users
**Summary**: List all users.
**Security**: Requires Bearer Token (ADMIN role).
**Responses**:
*   `200 OK`: Array of `User` objects.

#### DELETE /admin/users/{id}
**Summary**: Delete a user.
**Security**: Requires Bearer Token (ADMIN role).
**Responses**:
*   `200 OK`: "User deleted"

#### PUT /admin/users/{id}
**Summary**: Update user profile (Department/Role).
**Description**: Allows admins to modify a user's department or role (`PROPOSER`/`ADMIN`).
**Security**: Requires Bearer Token (ADMIN role).
**Request Body**: `{ "department": "New Dept", "role": "ADMIN" }` (fields optional)
**Responses**:
*   `200 OK`: Updated `User` object.

#### POST /admin/set-password
**Summary**: Force update a user's password.
**Description**: Allows admins to reset any user's password.
**Security**: Requires Bearer Token (ADMIN role).
**Request Body**: `{ "employeeId": "target_id", "password": "<new_password>" }` <!-- pragma: allowlist secret -->
**Responses**:
*   `200 OK`: "Password updated"

#### POST /admin/deadline
**Summary**: Set competition deadline.
**Security**: Requires Bearer Token (ADMIN role).
**Request Body**: `{ "deadline": "2026-12-31T23:59:59" }`
**Responses**:
*   `200 OK`: "Deadline updated"

#### GET /admin/audit-logs
**Summary**: View system audit logs.
**Description**: Returns a history of all critical POST/PUT/DELETE actions.
**Security**: Requires Bearer Token (ADMIN role).
**Responses**:
*   `200 OK`: Array of `AuditLog` objects.

---

### Public Endpoints

#### GET /api/deadline
**Summary**: Get current competition deadline.
**Description**: Publicly accessible endpoint to check the submission deadline.
**Responses**:
*   `200 OK`: `{ "key": "deadline", "value": "2026-03-17T23:59:59" }`
