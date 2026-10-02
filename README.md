# SecureAI

A security gateway that sits between a user and an LLM. Every prompt is
scanned for secrets, PII, and prompt-injection attempts before it reaches
the model; every response is scanned again before it reaches the user.
The security decision (ALLOW / SANITIZE / BLOCK) is made by a
deterministic policy engine, never by an LLM.
