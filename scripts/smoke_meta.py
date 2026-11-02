import os

import httpx
from dotenv import load_dotenv


def main() -> None:
    load_dotenv()
    response = httpx.post(
        os.environ["META_BASE_URL"].rstrip("/") + "/chat/completions",
        headers={"Authorization": "Bearer " + os.environ["META_API_KEY"]},
        json={
            "model": os.environ["META_MODEL"],
            "messages": [{"role": "user", "content": "Reply with the single word: ready"}],
            "max_tokens": 1000,
        },
        timeout=60,
    )
    print(response.status_code)
    print(response.text[:600])


if __name__ == "__main__":
    main()
