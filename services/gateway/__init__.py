"""HTTP gateway package.

Ownership is FILE-LEVEL here (hard-constraints.md Repo & File Boundary Rules):
Group 2 owns the upload / RBAC surface; Group 3 owns the CVE HTTP surface
(`cve_api.py` — RAG chat + analyst feedback). Group 2's application should mount
the Group 3 router via `include_router(services.gateway.cve_api.router)`.
"""
