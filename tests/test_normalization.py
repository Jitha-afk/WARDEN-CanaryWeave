from canaryweave_fides.normalization import has_hidden_unicode_structure, normalize_text


def test_normalize_text_reports_hidden_unicode_and_keeps_raw_text():
    value = "review" + "\u200b" + "note"
    normalized = normalize_text(value)
    assert normalized.length == len(value)
    assert normalized.hidden_char_count == 1
    assert normalized.normalization_changed is True
    assert normalized.sha256.startswith("sha256:")
    assert normalized.text == value


def test_hidden_unicode_detection_is_false_for_plain_text():
    assert has_hidden_unicode_structure("plain benign task note") is False
