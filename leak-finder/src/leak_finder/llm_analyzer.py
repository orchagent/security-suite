"""LLM-based analysis to validate findings and reduce false positives."""

import json
import os
from pathlib import Path

from .models import Finding


# Load the analysis prompt
PROMPTS_DIR = Path(__file__).parent / "prompts"


def get_analysis_prompt() -> str:
    """Load the analysis prompt from file."""
    prompt_file = PROMPTS_DIR / "analysis.txt"
    if prompt_file.exists():
        return prompt_file.read_text()
    # Fallback prompt if file doesn't exist
    return """You are a security expert analyzing potential secret/credential findings.
For each finding, determine if it's a true positive or false positive.

Respond with a JSON array of objects, each with:
- "index": the finding index (0-based)
- "is_secret": true if this is a real secret, false if it's a false positive
- "confidence": your confidence score from 0.0 to 1.0
- "reason": brief explanation of your decision

Common false positives:
- Example/placeholder values in documentation
- Test fixtures with fake credentials
- Environment variable references (not actual values)
- Hash values that aren't secrets
- Public keys (only private keys are secrets)
"""


def _detect_provider() -> tuple[str | None, str | None]:
    """
    Detect which LLM provider is available based on environment variables.

    Returns:
        Tuple of (provider_name, api_key) or (None, None) if no provider available.
    """
    # Check providers in order: OpenAI, Anthropic, Gemini
    if api_key := os.environ.get("OPENAI_API_KEY"):
        return ("openai", api_key)
    if api_key := os.environ.get("ANTHROPIC_API_KEY"):
        return ("anthropic", api_key)
    if api_key := os.environ.get("GEMINI_API_KEY"):
        return ("gemini", api_key)
    return (None, None)


async def _validate_with_openai(full_prompt: str, api_key: str) -> list[dict] | None:
    """Validate findings using OpenAI API."""
    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=api_key)

    response = await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
            {"role": "user", "content": full_prompt}
        ],
        response_format={"type": "json_object"},
        temperature=0.1,
    )

    content = response.choices[0].message.content
    if not content:
        return None

    result = json.loads(content)
    # Handle both direct array and wrapped object responses
    if isinstance(result, list):
        return result
    if isinstance(result, dict) and "findings" in result:
        return result["findings"]
    if isinstance(result, dict) and "results" in result:
        return result["results"]
    return None


async def _validate_with_anthropic(full_prompt: str, api_key: str) -> list[dict] | None:
    """Validate findings using Anthropic API."""
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic(api_key=api_key)

    response = await client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        messages=[
            {"role": "user", "content": full_prompt + "\n\nRespond with only valid JSON array, no other text."}
        ],
        temperature=0.1,
    )

    content = response.content[0].text
    if not content:
        return None

    # Anthropic may wrap JSON in markdown code blocks
    content = content.strip()
    if content.startswith("```json"):
        content = content[7:]
    if content.startswith("```"):
        content = content[3:]
    if content.endswith("```"):
        content = content[:-3]
    content = content.strip()

    result = json.loads(content)
    if isinstance(result, list):
        return result
    if isinstance(result, dict) and "findings" in result:
        return result["findings"]
    if isinstance(result, dict) and "results" in result:
        return result["results"]
    return None


async def _validate_with_gemini(full_prompt: str, api_key: str) -> list[dict] | None:
    """Validate findings using Google Gemini API."""
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=api_key)

    response = await client.aio.models.generate_content(
        model="gemini-2.5-flash",
        contents=full_prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1,
        ),
    )

    content = response.text
    if not content:
        return None

    result = json.loads(content)
    if isinstance(result, list):
        return result
    if isinstance(result, dict) and "findings" in result:
        return result["findings"]
    if isinstance(result, dict) and "results" in result:
        return result["results"]
    return None


async def validate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Use an LLM to validate findings and filter out false positives.

    Automatically detects available LLM provider from environment variables.
    Checks in order: OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY.

    Args:
        findings: List of findings to validate

    Returns:
        Filtered list of findings with confidence scores
    """
    if not findings:
        return []

    provider, api_key = _detect_provider()
    if not provider or not api_key:
        # Return findings unchanged if no API key available
        return findings

    try:
        # Build the prompt with findings
        prompt = get_analysis_prompt()
        findings_text = "\n".join([
            f"{i}. Type: {f.type}, File: {f.file}, Line: {f.line}, Preview: {f.preview}"
            for i, f in enumerate(findings)
        ])
        full_prompt = f"{prompt}\n\nFindings to analyze:\n{findings_text}"

        # Call the appropriate provider
        if provider == "openai":
            validations = await _validate_with_openai(full_prompt, api_key)
        elif provider == "anthropic":
            validations = await _validate_with_anthropic(full_prompt, api_key)
        elif provider == "gemini":
            validations = await _validate_with_gemini(full_prompt, api_key)
        else:
            return findings

        if not validations:
            return findings

        # Filter findings based on LLM validation
        validated_findings = []
        for validation in validations:
            idx = validation.get("index", -1)
            is_secret = validation.get("is_secret", True)
            confidence = validation.get("confidence", 1.0)

            if 0 <= idx < len(findings) and is_secret and confidence >= 0.5:
                finding = findings[idx]
                # Add confidence to recommendation
                finding.recommendation = f"[Confidence: {confidence:.0%}] {finding.recommendation}"
                validated_findings.append(finding)

        return validated_findings

    except Exception:
        # On any error, return original findings
        return findings


def validate_findings_sync(findings: list[Finding]) -> list[Finding]:
    """
    Synchronous wrapper for validate_findings.

    Args:
        findings: List of findings to validate

    Returns:
        Filtered list of findings
    """
    import asyncio
    return asyncio.run(validate_findings(findings))
