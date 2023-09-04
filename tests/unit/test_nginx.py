import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, mock_open, patch

from nginx import NginxConfigurer


class TestNginxConfigurer(unittest.TestCase):
    @patch("nginx.apt")
    def setUp(self, mock_apt):
        self.charm = MagicMock()
        self.config = MagicMock()
        self.mock_apt = mock_apt
        self.nginx = NginxConfigurer(self.charm, self.config)

    @patch("os.remove")
    @patch("shutil.copy")
    def test__configure_daemon(self, mock_copy, mock_remove):
        context = {"main": {"foo": "bar"}, "events": {"baz": "test"}, "http": {"plugh": "xyzzy"}}

        with open("./templates/nginx.conf") as f:
            input = f.read()

        with patch("builtins.open", mock_open(read_data=input)) as mock_write, patch.object(
            self.nginx, "_verify_nginx_config"
        ):
            self.nginx.configure_daemon(context)

            (rendered_content,) = mock_write.return_value.write.call_args[0]
            expected_content = ("foo bar;", "baz test;", "plugh xyzzy;")

            for content in expected_content:
                assert content in rendered_content

    def test__render_template(self):
        context = {"name": "CK"}
        # Create test template
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as test_template:
            test_template.write("Hello {{ name }}!")
            test_template_path = Path(test_template.name)

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_dst:
            temp_dst_path = Path(temp_dst.name)

        try:
            self.nginx._render_template(test_template_path, temp_dst_path, context)

            with open(temp_dst_path) as f:
                rendered_content = f.read()

            expected_content = "Hello CK!"

            self.assertEqual(rendered_content, expected_content)

        finally:
            test_template.close()
            temp_dst.close()
            test_template_path.unlink()
            temp_dst_path.unlink()

    def test_upgrade_nginx(self):
        mock_apt = self.mock_apt
        mock_event = MagicMock()
        self.nginx._upgrade_nginx(mock_event)
        mock_apt.add_package.return_value.ensure.assert_called_once()

    @patch("nginx.Path.exists", return_value=True)
    @patch("nginx.Path.unlink")
    @patch("nginx.Path.symlink_to")
    def test_configure_site(self, mock_symlink_to, mock_unlink, mock_exists: MagicMock):
        site_name = "test-site"
        template_file_path = Path("/path/to/template")
        context = {"key": "value"}

        self.nginx._load_site = MagicMock(return_value={})
        self.nginx._render_template = MagicMock()

        self.nginx.configure_site(site_name, template_file_path, **context)

        mock_exists.assert_has_calls(
            [
                call(),
                call(),
            ]
        )
        mock_unlink.assert_has_calls(
            [
                call(),
                call(),
            ]
        )
        self.nginx._render_template.assert_called_once_with(
            template_file=template_file_path,
            dest=Path("/etc/nginx/sites-available/test-site"),
            context=context,
        )
        mock_symlink_to.assert_called_once_with(Path("/etc/nginx/sites-available/test-site"))

    @patch("nginx.Path.exists", return_value=True)
    @patch("nginx.Path.unlink")
    def test_remove_default_site(self, mock_unlink, mock_exists):
        self.nginx.remove_default_site()

        mock_exists.assert_called_once_with()
        mock_unlink.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
