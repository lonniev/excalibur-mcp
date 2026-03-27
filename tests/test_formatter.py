"""Tests for the markdown → Unicode formatter."""


from excalibur_mcp.formatter import (
    markdown_to_unicode,
    to_bold,
    to_bold_italic,
    to_italic,
    to_monospace,
)

# ---------------------------------------------------------------------------
# Individual conversion functions
# ---------------------------------------------------------------------------


class TestToBold:
    def test_lowercase(self):
        assert to_bold("hello") == "𝗵𝗲𝗹𝗹𝗼"

    def test_uppercase(self):
        assert to_bold("HELLO") == "𝗛𝗘𝗟𝗟𝗢"

    def test_mixed_case(self):
        assert to_bold("Hello") == "𝗛𝗲𝗹𝗹𝗼"

    def test_digits(self):
        assert to_bold("2026") == "𝟮𝟬𝟮𝟲"

    def test_punctuation_passthrough(self):
        assert to_bold("hi!") == "𝗵𝗶!"

    def test_spaces_passthrough(self):
        assert to_bold("a b") == "𝗮 𝗯"

    def test_empty(self):
        assert to_bold("") == ""


class TestToItalic:
    def test_lowercase(self):
        assert to_italic("hello") == "𝘩𝘦𝘭𝘭𝘰"

    def test_uppercase(self):
        assert to_italic("HELLO") == "𝘏𝘌𝘓𝘓𝘖"

    def test_no_digit_conversion(self):
        """Italic block has no digit range — digits pass through as ASCII."""
        assert to_italic("abc123") == "𝘢𝘣𝘤123"

    def test_empty(self):
        assert to_italic("") == ""


class TestToBoldItalic:
    def test_lowercase(self):
        assert to_bold_italic("hello") == "𝙝𝙚𝙡𝙡𝙤"

    def test_uppercase(self):
        assert to_bold_italic("HELLO") == "𝙃𝙀𝙇𝙇𝙊"

    def test_no_digit_conversion(self):
        """Bold italic block has no digit range — digits pass through."""
        assert to_bold_italic("x99") == "𝙭99"

    def test_empty(self):
        assert to_bold_italic("") == ""


class TestToMonospace:
    def test_lowercase(self):
        assert to_monospace("code") == "𝚌𝚘𝚍𝚎"

    def test_uppercase(self):
        assert to_monospace("CODE") == "𝙲𝙾𝙳𝙴"

    def test_digits(self):
        assert to_monospace("42") == "𝟺𝟸"

    def test_mixed(self):
        assert to_monospace("fn()") == "𝚏𝚗()"

    def test_empty(self):
        assert to_monospace("") == ""


# ---------------------------------------------------------------------------
# Full markdown_to_unicode pipeline
# ---------------------------------------------------------------------------


class TestMarkdownToUnicode:
    def test_bold(self):
        result = markdown_to_unicode("**hello**")
        assert result == "𝗵𝗲𝗹𝗹𝗼"

    def test_italic(self):
        result = markdown_to_unicode("*hello*")
        assert result == "𝘩𝘦𝘭𝘭𝘰"

    def test_bold_italic(self):
        result = markdown_to_unicode("***hello***")
        assert result == "𝙝𝙚𝙡𝙡𝙤"

    def test_monospace(self):
        result = markdown_to_unicode("`code`")
        assert result == "𝚌𝚘𝚍𝚎"

    def test_mixed_in_sentence(self):
        result = markdown_to_unicode("This is **bold** and *italic* text")
        assert "𝗯𝗼𝗹𝗱" in result
        assert "𝘪𝘵𝘢𝘭𝘪𝘤" in result
        assert result.startswith("This is ")
        assert result.endswith(" text")

    def test_all_four_styles(self):
        text = "**B** *I* ***BI*** `M`"
        result = markdown_to_unicode(text)
        assert "𝗕" in result  # bold B
        assert "𝘐" in result  # italic I
        assert "𝘽𝙄" in result  # bold-italic BI
        assert "𝙼" in result  # mono M

    def test_no_formatting(self):
        """Plain text passes through unchanged."""
        text = "Just a normal tweet"
        assert markdown_to_unicode(text) == text

    def test_unmatched_single_asterisk(self):
        """Unmatched asterisk left as-is."""
        text = "this * is not italic"
        assert markdown_to_unicode(text) == text

    def test_unmatched_double_asterisk(self):
        """Unmatched double asterisk left as-is."""
        text = "this ** is not bold"
        assert markdown_to_unicode(text) == text

    def test_unmatched_backtick(self):
        """Single unmatched backtick left as-is."""
        text = "this ` is not mono"
        assert markdown_to_unicode(text) == text

    def test_adjacent_styles(self):
        """Bold immediately followed by italic."""
        result = markdown_to_unicode("**bold***italic*")
        assert "𝗯𝗼𝗹𝗱" in result
        assert "𝘪𝘵𝘢𝘭𝘪𝘤" in result

    def test_emoji_passthrough(self):
        """Emoji characters pass through unchanged."""
        result = markdown_to_unicode("**hello** 🚀")
        assert result.endswith(" 🚀")

    def test_newlines_preserved(self):
        """Newlines within text are preserved."""
        result = markdown_to_unicode("line1\n**bold**\nline3")
        assert "\n" in result
        assert "𝗯𝗼𝗹𝗱" in result

    def test_multiword_bold(self):
        """Bold spanning multiple words."""
        result = markdown_to_unicode("**two words**")
        assert result == "𝘁𝘄𝗼 𝘄𝗼𝗿𝗱𝘀"

    def test_numbers_in_bold(self):
        """Digits inside bold get converted."""
        result = markdown_to_unicode("**v2.0**")
        assert "𝘃" in result  # bold 'v'
        assert "𝟮" in result  # bold '2'
        assert "." in result  # period passes through

    def test_empty_string(self):
        assert markdown_to_unicode("") == ""
