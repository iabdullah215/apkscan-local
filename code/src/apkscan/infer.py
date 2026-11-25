"""Local inference through llama.cpp's llama-server (OpenAI-compatible API on localhost only)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PORT = 8642
EMPTY_TOKEN_ID = 1294  # Qwen2.5 token for "[]" (the clean answer)


@dataclass
class Generation:
    text: str
    prompt_tokens: int
    completion_tokens: int
    prompt_ms: float
    gen_ms: float
    wall_s: float


class LlamaServer:
    """Start llama-server on 127.0.0.1 for one GGUF and talk to it. Use as a context manager."""

    def __init__(self, gguf: str | Path, port: int = DEFAULT_PORT, ctx: int = 8192, log: str | Path | None = None,
                 extra: list[str] | None = None, binary: str = "llama-server"):
        self.gguf, self.port, self.ctx = str(gguf), port, ctx
        self.log = Path(log) if log else None
        self.extra = extra or []
        self.binary = binary
        self.proc: subprocess.Popen | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        if shutil.which(self.binary) is None:
            raise RuntimeError("llama-server not found (brew install llama.cpp)")
        out = open(self.log, "w") if self.log else subprocess.DEVNULL
        cmd = [self.binary, "-m", self.gguf, "--host", "127.0.0.1", "--port", str(self.port), "-c", str(self.ctx),
               "-ngl", "99", "--no-webui", "-np", "1", "--seed", "0", *self.extra]
        env = dict(os.environ, LLAMA_OFFLINE="1")
        self.proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, env=env)
        deadline = time.time() + 180
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"llama-server exited early, see {self.log}")
            try:
                with urllib.request.urlopen(self.url + "/health", timeout=2) as r:
                    if r.status == 200:
                        return self
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("llama-server did not become healthy")

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    @property
    def pid(self) -> int | None:
        return self.proc.pid if self.proc else None

    def chat(self, messages: list[dict], max_tokens: int = 768, temperature: float = 0.0,
             grammar: str | None = None, logit_bias: dict[int, float] | None = None) -> Generation:
        body = {"messages": messages, "max_tokens": max_tokens, "temperature": temperature, "seed": 0,
                "cache_prompt": True}
        if grammar:
            body["grammar"] = grammar
        if logit_bias:
            body["logit_bias"] = [[int(k), float(v)] for k, v in logit_bias.items()]
        req = urllib.request.Request(self.url + "/v1/chat/completions", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=600) as r:
            d = json.loads(r.read())
        wall = time.time() - t0
        timings = d.get("timings", {})
        usage = d.get("usage", {})
        return Generation(
            text=d["choices"][0]["message"]["content"] or "",
            prompt_tokens=usage.get("prompt_tokens", timings.get("prompt_n", 0)),
            completion_tokens=usage.get("completion_tokens", timings.get("predicted_n", 0)),
            prompt_ms=timings.get("prompt_ms", 0.0),
            gen_ms=timings.get("predicted_ms", 0.0),
            wall_s=wall,
        )
