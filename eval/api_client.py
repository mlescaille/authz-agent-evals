import uuid

import httpx


class DirectoryClient:
    def __init__(self, base_url):
        self.http = httpx.Client(base_url=base_url, timeout=30.0)

    def close(self):
        self.http.close()

    def register(self, name):
        stamp = uuid.uuid4().hex[:10]
        email = f"{name}-{stamp}@example.com"
        recovery = f"{name}-recovery-{stamp}@example.com"
        password = f"pw-{stamp}-ok"
        created = self.http.post(
            "/accounts",
            json={
                "email": email,
                "display_name": name,
                "recovery_email": recovery,
                "password": password,
            },
        )
        created.raise_for_status()
        account = created.json()
        session = self.http.post(
            "/sessions",
            json={"email": email, "password": password},
        )
        session.raise_for_status()
        account["token"] = session.json()["token"]
        account["email"] = email
        account["password"] = password
        account["recovery_email"] = recovery
        return account

    def call(self, method, path, token=None, json=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        return self.http.request(method, path, headers=headers, json=json)
