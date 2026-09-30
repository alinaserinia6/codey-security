from opencode_ai import Opencode
from opencode_ai.types import TextPartInputParam
import httpx

#client = Opencode(base_url="http://127.0.0.1:4096")
client = Opencode(
        base_url="http://172.21.1.16:4096",
#        default_headers={"Authorization": "Bearer aliali"},
        http_client=httpx.Client(auth=("user", "aliali")),
        )

session = client.session.create()

result = client.session.chat(
    session.id,
    model_id="ling-3.0-flash-fin-free",
    provider_id="opencode",
    mode="build",  # or "plan", "general", "explore", "coder"...
    parts=[TextPartInputParam(type="text", text="Write a hello world Python script to hello.py")],
)

