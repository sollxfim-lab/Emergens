"""
AI Chat handler – supports multiple backends:
  - Anthropic (Claude) via the official SDK
  - DeepSeek R1 via an OpenAI‑compatible API (e.g. https://app.siputzx.my.id)

Conversation history is stored in a JSON file.

Author: Yanxzyx
"""

import json
import os
import hashlib
import requests
from datetime import datetime, timezone
from typing import List, Dict, Optional

from config import Config


# ---------------------------------------------------------------------------
# Anthropic ChatHandler (unchanged)
# ---------------------------------------------------------------------------
class ChatHandler:
    """Manages chat history and calls the Anthropic API."""

    def __init__(self, storage_path: str = Config.CHAT_DB,
                 api_key: str = Config.ANTHROPIC_API_KEY):
        self.storage_path = storage_path
        self.api_key = api_key
        self._ensure_file()

    def _ensure_file(self) -> None:
        if not os.path.exists(self.storage_path):
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump([], f)

    def _load(self) -> List[Dict]:
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _save(self, history: List[Dict]) -> None:
        with open(self.storage_path, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)

    def get_history(self) -> List[Dict]:
        return self._load()

    def add_message(self, role: str, content: str) -> None:
        history = self._load()
        history.append({
            'role': role,
            'content': content,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })
        self._save(history)

    def clear_history(self) -> None:
        self._save([])

    def send(self, message: str) -> Dict[str, str]:
        """Process a user message and return the assistant's reply."""
        if not message.strip():
            return {'reply': 'Please enter a message.'}

        self.add_message('user', message)

        if self.api_key:
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=self.api_key)
                history = self._load()
                api_messages = [
                    {'role': m['role'], 'content': m['content']}
                    for m in history[-20:]
                ]
                response = client.messages.create(
                    model='claude-3-5-sonnet-20241022',
                    max_tokens=1024,
                    system='You are the Oxysintx AI Security Assistant. '
                           'Provide helpful, accurate information about '
                           'security testing, OSINT, and web application '
                           'security. Be concise and professional.',
                    messages=api_messages,
                )
                reply = response.content[0].text
            except Exception:
                reply = self._fallback_response(message)
        else:
            reply = self._fallback_response(message)

        self.add_message('assistant', reply)
        return {'reply': reply}

    def _fallback_response(self, message: str) -> str:
        responses = [
            "That's a great question about security testing. "
            "When performing reconnaissance, always ensure you have "
            "proper authorization before scanning any target. Passive "
            "techniques like WHOIS lookups and DNS queries are "
            "generally safe starting points.",
            "For web application security, the OWASP Top 10 is the "
            "essential reference. Start with injection flaws (SQL, XSS), "
            "broken authentication, and sensitive data exposure — "
            "these are the most common vulnerabilities found in "
            "real‑world assessments.",
            "SSL/TLS certificates should be monitored regularly. An "
            "expired certificate breaks HTTPS for all visitors. Set up "
            "automated checks that alert you at least 30 days before "
            "expiry.",
            "Security headers like Content‑Security‑Policy and "
            "Strict‑Transport‑Security are simple to implement but "
            "surprisingly effective. They prevent entire classes of "
            "attacks like XSS and downgrade attacks.",
            "All tools in Oxysintx are passive and read‑only. They do "
            "not send exploit payloads or attempt to bypass security "
            "controls. Always operate within the scope of your "
            "authorization.",
        ]
        idx = int(hashlib.md5(message.encode()).hexdigest(), 16) % len(responses)
        return responses[idx]


# ---------------------------------------------------------------------------
# DeepSeek R1 ChatHandler (OpenAI‑compatible API)
# ---------------------------------------------------------------------------
class DeepSeekChatHandler:
    """
    Manages chat history and calls the DeepSeek R1 model via an
    OpenAI‑compatible HTTP API (e.g. https://app.siputzx.my.id).
    """

    def __init__(self,
                 storage_path: str = os.path.join(Config.BASE_DIR, 'data', 'deepseek_chat.json'),
                 api_key: str = Config.DEEPSEEK_API_KEY,          # add to config
                 base_url: str = Config.DEEPSEEK_BASE_URL,        # https://app.siputzx.my.id/v1
                 model: str = Config.DEEPSEEK_MODEL):             # e.g. deepseek-r1
        self.storage_path = storage_path
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.model = model
        self._ensure_file()

    def _ensure_file(self) -> None:
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        if not os.path.exists(self.storage_path):
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump([], f)

    def _load(self) -> List[Dict]:
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _save(self, history: List[Dict]) -> None:
        with open(self.storage_path, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)

    def get_history(self) -> List[Dict]:
        return self._load()

    def add_message(self, role: str, content: str) -> None:
        history = self._load()
        history.append({
            'role': role,
            'content': content,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })
        self._save(history)

    def clear_history(self) -> None:
        self._save([])

    def send(self, message: str) -> Dict[str, str]:
        """Send a user message to DeepSeek R1 and return the reply."""
        if not message.strip():
            return {'reply': 'Please enter a message.'}

        self.add_message('user', message)

        if not self.api_key:
            return {'reply': 'DeepSeek API key is not configured.'}

        try:
            # Build messages array from stored history (last 20 turns)
            history = self._load()
            messages = [
                {'role': m['role'], 'content': m['content']}
                for m in history[-20:]
            ]

            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json',
            }
            payload = {
                'model': self.model,
                'messages': messages,
                'max_tokens': 1024,
                'temperature': 0.7,
            }

            response = requests.post(
                f'{self.base_url}/chat/completions',
                headers=headers,
                json=payload,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            reply = data['choices'][0]['message']['content'].strip()
        except Exception as e:
            # Fallback to a generic security‑themed response
            reply = self._fallback_response(message, str(e))

        self.add_message('assistant', reply)
        return {'reply': reply}

    def _fallback_response(self, message: str, error: str = '') -> str:
        responses = [
            "The DeepSeek model is currently unavailable. "
            "Please verify your API key and endpoint. "
            "Meanwhile, you can continue using the offline tools.",

            "I encountered a problem reaching the AI service. "
            "Ensure that the server is running and the configuration "
            "is correct. You can still perform scans and lookups.",

            "DeepSeek R1 is an advanced reasoning model. "
            "For the best experience, check your network connection "
            "and API credentials. In the meantime, try a different query.",

            "The AI backend returned an error. This could be due to "
            "rate limiting, invalid API key, or an incorrect base URL. "
            "Check the server logs for more details.",

            "Offline mode: The AI service is not responding. "
            "You can still use all the passive reconnaissance tools "
            "built into Oxysintx.",
        ]
        # Deterministic fallback based on message hash
        idx = int(hashlib.md5(message.encode()).hexdigest(), 16) % len(responses)
        return responses[idx]