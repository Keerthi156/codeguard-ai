import os

import httpx
from dotenv import load_dotenv


def main() -> None:
    load_dotenv()
    response = httpx.post(
        os.environ["FIREWORKS_BASE_URL"].rstrip("/") + "/chat/completions",
        headers={"Authorization": "Bearer " + os.environ["FIREWORKS_API_KEY"]},
        json={
            "model": os.environ["FIREWORKS_MODEL"],
            "messages": [{"role": "user", "content": "Reply with the single word: ready"}],
            "max_tokens": 1000,
        },
        timeout=60,
    )
    print(response.status_code)
    print(response.text[:500])


if __name__ == "__main__":
    main()
