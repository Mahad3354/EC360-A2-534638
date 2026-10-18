# EC360-A2-534616 — QuickCart Microservices

EC360 Software Engineering, Assignment 2 (DE-46 B, Fall 2026).

This repository holds the feature-branch work for the QuickCart Microservices
Scrum project tracked in Jira Cloud under the project key **QM**. Every commit
message starts with the Jira issue key so that Jira can link the code back to
its user story.

| Item | Detail |
|---|---|
| Author | Hamza Tariq |
| Registration No. | 534616 |
| Jira project | QuickCart Microservices (QM) |
| Story covered | QM-5 — Customer Registration with Email Verification |

## Files
- `auth_service.py` — registration service with password hashing and email verification tokens
- `test_auth.py` — unit tests for the registration workflow

## Running the tests
```
python -m unittest -v test_auth.py
```
