"""canon/1 (SPEC §9.1): parse, lines, characters, relative times, whitespace."""
import unittest

from claim_witness.canon import canon1


class Canon1(unittest.TestCase):
    def test_plain_text_whitespace_and_lines(self):
        self.assertEqual(canon1("  Hello   world \n\n\t second\tline  \r\n", "text/plain"), "Hello world\nsecond line")

    def test_characters_quotes_dashes_ellipsis_spaces(self):
        text = "‘a’ ‚b′ “c” „d″ e–f—g‒h−i wait… x y z"
        self.assertEqual(canon1(text, "text/plain"), "'a' 'b' \"c\" \"d\" e-f-g-h-i wait... x y z")

    def test_nfkc(self):
        self.assertEqual(canon1("ﬁne Ａ", "text/plain"), "fine A")

    def test_relative_times(self):
        self.assertEqual(canon1("posted 3 hours ago, edited just now, seen yesterday; 1 day ago", "text/plain"),
                         "posted <reltime>, edited <reltime>, seen <reltime>; <reltime>")

    def test_case_kept(self):
        self.assertEqual(canon1("MiXeD Case", "text/plain"), "MiXeD Case")

    def test_html_drops_invisible_and_non_content(self):
        html = ("<html><head><title>T</title><style>p{}</style></head><body>"
                "<script>var x=1</script><noscript>ns</noscript><template>tp</template><svg><text>s</text></svg>"
                "<iframe>if</iframe><p>Visible</p><p hidden>H1</p><div aria-hidden=\"true\">H2</div>"
                "<span style=\"color:red; display : none\">H3</span><span style=\"visibility:hidden\">H4</span>"
                "<p>After</p></body></html>")
        self.assertEqual(canon1(html, "text/html"), "Visible\nAfter")

    def test_html_block_elements_end_lines(self):
        html = "<div>one<p>two</p>three<br>four<ul><li>a</li><li>b</li></ul><h2>h</h2><span>in</span>line</div>"
        self.assertEqual(canon1(html, "text/html"), "one\ntwo\nthree\nfour\na\nb\nh\ninline")

    def test_html_entities_and_inline_whitespace(self):
        self.assertEqual(canon1("<p>a&amp;b&nbsp;&nbsp;c   d</p>", "text/html"), "a&b c d")

    def test_witness_hidden_only_at_rendered_layer(self):
        html = "<p>keep</p><p data-witness-hidden>menu</p>"
        self.assertEqual(canon1(html, "text/html", layer="response"), "keep\nmenu")
        self.assertEqual(canon1(html, "text/html", layer="rendered"), "keep")

    def test_bytes_input_utf8(self):
        self.assertEqual(canon1("café  ok".encode("utf-8"), "text/plain"), "café ok")


if __name__ == "__main__":
    unittest.main()
