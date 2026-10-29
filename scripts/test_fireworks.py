import os
import httpx
from dotenv import load_dotenv

load_dotenv()
r = httpx.post(
    os.environ["FIREWORKS_BASE_URL"].rstrip("/") + "/chat/completions",
    headers={"Authorization": "Bearer " + os.environ["FIREWORKS_API_KEY"]},
    json={
        "model": os.environ["FIREWORKS_MODEL"],
        "messages": [{"role": "user", "content": "Reply with the single word: ready"}],
        "max_tokens": 1000,
    },
    timeout=60,
)
print(r.status_code)
print(r.text[:500])
