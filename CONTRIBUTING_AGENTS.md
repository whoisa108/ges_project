# 🤖 Guidelines for AI Agents

Welcome, Agent. This document defines the standards and workflows for contributing to the ESG Idea Competition project. Follow these steps to ensure consistency across parallel worktrees.

## 🏗 Knowledge & Context
Before making any changes, you **MUST** read:
1.  [README.md](file:///home/jpeng/projects/esg_collection/esg_project/README.md): High-level project overview and tech stack.
2.  [api_spec.md](file:///home/jpeng/projects/esg_collection/esg_project/api_spec.md): The source of truth for all backend/frontend communication. **Do not deviate from the spec.**
3.  [backend/README.md](file:///home/jpeng/projects/esg_collection/esg_project/backend/README.md) & [frontend/README.md](file:///home/jpeng/projects/esg_collection/esg_project/frontend/README.md): Sub-module specific implementation details.

## 🛠 Workflow Steps
When assigned a task/module:
1.  **Analyze**: Map the requirement to existing endpoints in `api_spec.md`.
2.  **Verify Status**: Check `docker compose ps` to ensure infrastructure (MongoDB, MinIO) is healthy.
3.  **Plan**: Create an `implementation_plan.md` in the user's brain directory for review.
4.  **Execute**:
    *   **Backend**: Use Java Spring Boot. adhere to the existing consolidated structure unless refactoring is explicitly requested.
    *   **Frontend**: Use React + Vite. Maintain the premium, glassmorphism design aesthetic.
5.  **Document**: If you add/change an endpoint, you **MUST** update `api_spec.md` as the first step of your execution.

## ⚖ Standards
- **Terse Code**: Avoid verbose boilerplate. Use the existing consolidated patterns.
- **No Placeholders**: Generate real assets/images using tools if needed.
- **Casual Tone**: Communicate clearly but casually with the user.
- **Parallel Safety**: If working in a separate worktree, ensure your changes don't break the global `api_spec.md`.

## 🚀 Getting Started
If you are new here, start by exploring the `ApiController.java` for logic flow and `App.tsx` for UI structure.
