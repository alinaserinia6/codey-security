from opencode_ai import Opencode
from opencode_ai.types import TextPartInputParam

client = Opencode(base_url="http://127.0.0.1:4096")

session = client.session.create()

result = client.session.chat(
    session.id,
    model_id="opencode/deepseek-v4-flash-free",
    provider_id="opencode",
    mode="build",  # or "plan", "general", "explore", "coder"...
    parts=[TextPartInputParam(type="text", text="Write a hello world Python script to hello.py")],
)