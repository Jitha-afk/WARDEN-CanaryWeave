from canaryweave_fides.normalization import has_hidden_unicode_structure, normalize_text, redact_for_judge


def test_normalize_text_reports_hidden_unicode_without_exposing_raw_text():
    value = "review" + "\u200b" + "note"
    normalized = normalize_text(value)
    assert normalized.length == len(value)
    assert normalized.hidden_char_count == 1
    assert normalized.normalization_changed is True
    assert normalized.sha256.startswith("sha256:")
    assert "review" not in normalized.redacted


def test_redact_for_judge_replaces_sensitive_shapes():
    token_label = "api" + "_" + "key"
    text = f"see CANARY_ALPHA and {token_label}=abc123"
    redacted = redact_for_judge(text)
    assert "CANARY_ALPHA" not in redacted
    assert token_label not in redacted
    assert "[CANARY]" in redacted
    assert "[CREDENTIAL]" in redacted


def test_hidden_unicode_detection_is_false_for_plain_text():
    assert has_hidden_unicode_structure("plain benign task note") is False
