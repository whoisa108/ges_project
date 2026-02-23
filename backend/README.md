# ESG Idea Competition - Backend API Documentation

This document describes the REST API endpoints available in the backend service. All endpoints are prefixed with `/api`.

## Base URL
`http://localhost:8080/api` (default)

---

## Authentication Endpoints

### Register User
`POST /auth/register`
- **Body**: `User` object
- **Description**: Registers a new user with the `PROPOSER` role.

### Login
`POST /auth/login`
- **Body**: `{"employeeId": "...", "password": "..."}`
- **Response**: JWT token, user role, name, and employee ID.

### Reset Password
`POST /auth/reset-password`
- **Body**: `{"password": "..."}`
- **Security**: Requires JWT authentication.
- **Description**: Resets the current user's password.

---

## Proposal Endpoints

### List Proposals
`GET /proposals`
- **Security**: Requires JWT authentication.
- **Description**: Returns all proposals if the user is an `ADMIN`, otherwise returns proposals created by the current user.

### Create Proposal
`POST /proposals`
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `title` (String)
  - `category` (String)
  - `direction` (String)
  - `summary` (String)
  - `teamMembers` (JSON String, optional)
  - `file` (MultipartFile)
- **Security**: Requires JWT authentication.

### Update Proposal
`PUT /proposals/{id}`
- **Content-Type**: `multipart/form-data`
- **Parameters**: Same as create, `file` and `teamMembers` are optional.
- **Security**: Only the creator can edit.

### Delete Proposal
`DELETE /proposals/{id}`
- **Security**: Accessible by creator or `ADMIN`.

### Download Proposal File
`GET /proposals/{id}/download`
- **Security**: Accessible by creator or `ADMIN`.

---

## Admin Endpoints
*All admin endpoints require the user to have the `ADMIN` role.*

### User Management
- `GET /admin/users`: List all registered users.
- `DELETE /admin/users/{id}`: Delete a user by ID.
- `PUT /admin/users/{id}`: Update user department or role.
- `POST /admin/set-password`: Force reset a user's password.

### System Control
- `POST /admin/deadline`: Set the competition submission deadline.
- `GET /admin/audit-logs`: Retrieve all system audit logs.

---

## Public Endpoints

### Get Deadline
`GET /deadline`
- **Description**: Returns the current competition deadline.

## CRUD Method Table

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/proposals` | List all proposals |
| POST | `/proposals` | Create a new proposal |
| PUT | `/proposals/{id}` | Update a proposal |
| DELETE | `/proposals/{id}` | Delete a proposal |
| GET | `/proposals/{id}/download` | Download a proposal file |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/admin/users` | List all registered users |
| DELETE | `/admin/users/{id}` | Delete a user by ID |
| PUT | `/admin/users/{id}` | Update user department or role |
| POST | `/admin/set-password` | Force reset a user's password |
| POST | `/admin/deadline` | Set the competition submission deadline |
| GET | `/admin/audit-logs` | Retrieve all system audit logs |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/deadline` | Returns the current competition deadline |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Login |
| POST | `/auth/reset-password` | Reset password |