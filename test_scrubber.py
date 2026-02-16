"""Tests for the secret scrubber module."""
# pylint: disable=missing-function-docstring,too-many-public-methods

from scrubber import REDACTED, scrub_arguments, scrub_text, scrub_url


# -----------------------------------------------------------------------
# Tier 1 — Known secret prefix patterns
# -----------------------------------------------------------------------

class TestTier1Patterns:
    """High-confidence prefix-based secret detection."""

    def test_openai_key(self):
        assert scrub_text("sk-abc123def456ghi789jkl012mno345pqr678stu901vwx") == REDACTED

    def test_openai_proj_key(self):
        assert scrub_text("sk-proj-abcdefghijklmnopqrstuvwxyz1234567890") == REDACTED

    def test_anthropic_key(self):
        assert scrub_text("sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890") == REDACTED

    def test_aws_access_key(self):
        assert scrub_text("AKIAIOSFODNN7EXAMPLE") == REDACTED

    def test_github_pat(self):
        assert scrub_text("ghp_ABCDEFghijklmnopqrstuv1234567890") == REDACTED

    def test_github_oauth(self):
        assert scrub_text("gho_ABCDEFghijklmnopqrstuv1234567890") == REDACTED

    def test_github_app(self):
        assert scrub_text("ghs_ABCDEFghijklmnopqrstuv1234567890") == REDACTED

    def test_github_refresh(self):
        assert scrub_text("ghr_ABCDEFghijklmnopqrstuv1234567890") == REDACTED

    def test_gitlab_pat(self):
        assert scrub_text("glpat-abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_slack_bot_token(self):
        assert scrub_text("xoxb-123456789012-1234567890123-AbCdEfGhIjKl") == REDACTED

    def test_slack_user_token(self):
        assert scrub_text("xoxp-123456789012-1234567890123") == REDACTED

    def test_stripe_live_key(self):
        assert scrub_text("sk_live_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_stripe_test_key(self):
        assert scrub_text("sk_test_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_stripe_publishable_key(self):
        assert scrub_text("pk_live_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_google_api_key(self):
        assert scrub_text("AIzaSyA1234567890abcdefghijklmnopqrstuv") == REDACTED

    def test_huggingface_token(self):
        assert scrub_text("hf_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_npm_token(self):
        assert scrub_text("npm_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_jwt(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert scrub_text(token) == REDACTED

    def test_sendgrid_key(self):
        assert scrub_text("SG.abcdefghijklmnopqrstuv.wxyz1234567890abcdefg") == REDACTED

    def test_twilio_api_key_sid(self):
        assert scrub_text("SK" + "a1b2c3d4" * 4) == REDACTED

    def test_databricks_token(self):
        assert scrub_text("dapi" + "a1b2c3d4" * 4) == REDACTED

    def test_digitalocean_token(self):
        token = "dop_v1_" + "a" * 64
        assert scrub_text(token) == REDACTED

    def test_shopify_token(self):
        token = "shpat_" + "a" * 32
        assert scrub_text(token) == REDACTED

    def test_atlassian_token(self):
        assert scrub_text("ATATT" + "x" * 30) == REDACTED

    def test_pypi_token(self):
        assert scrub_text("pypi-AgEIcHlwaS5vcmcABCD1234567890") == REDACTED

    def test_vault_token(self):
        assert scrub_text("hvs.CAESIJ1234567890abcdefghijk") == REDACTED

    def test_grafana_cloud_token(self):
        assert scrub_text("glc_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_grafana_sa_token(self):
        assert scrub_text("glsa_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_linear_api_key(self):
        assert scrub_text("lin_api_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_planetscale_token(self):
        assert scrub_text("pscale_tkn_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_postman_key(self):
        assert scrub_text("PMAK-abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_pulumi_token(self):
        assert scrub_text("pul-abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_doppler_token(self):
        assert scrub_text("dp.st.abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_notion_token(self):
        assert scrub_text("ntn_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_telegram_bot_token(self):
        assert scrub_text("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw") == REDACTED

    def test_private_key_block(self):
        result = scrub_text("-----BEGIN RSA PRIVATE KEY-----")
        assert REDACTED in result

    def test_generic_live_key(self):
        assert scrub_text("live_aw2aglwrZrpQ1234567890abcdefghijklm") == REDACTED

    def test_generic_test_key(self):
        assert scrub_text("test_aw2aglwrZrpQ1234567890abcdefghijklm") == REDACTED

    def test_vercel_token(self):
        assert scrub_text("vercel_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_resend_token(self):
        assert scrub_text("re_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_figma_token(self):
        assert scrub_text("figd_abcdefghijklmnopqrstuvwxyz") == REDACTED

    def test_key_embedded_in_sentence(self):
        text = "Use key sk-abc123def456ghi789jkl012mno345pqr678stu901vwx for auth"
        result = scrub_text(text)
        assert REDACTED in result
        assert "sk-abc123" not in result

    def test_multiple_secrets(self):
        text = "key1=ghp_ABCDEFghijklmnopqrstuv1234567890 key2=sk_live_abcdefghijklmnopqrstuvwxyz"
        result = scrub_text(text)
        assert result.count(REDACTED) == 2


# -----------------------------------------------------------------------
# Tier 2 — Contextual patterns
# -----------------------------------------------------------------------

class TestTier2Patterns:
    """Patterns that need surrounding context to match."""

    def test_env_var_api_key(self):
        result = scrub_text("API_KEY=mysecretvalue123")
        assert REDACTED in result
        assert "mysecretvalue123" not in result

    def test_export_token(self):
        result = scrub_text('export TOKEN="my-secret-token"')
        assert REDACTED in result
        assert "my-secret-token" not in result

    def test_env_var_password(self):
        result = scrub_text("DB_PASSWORD=hunter2")
        assert REDACTED in result
        assert "hunter2" not in result

    def test_env_var_secret(self):
        result = scrub_text("MY_SECRET=verysecret")
        assert REDACTED in result
        assert "verysecret" not in result

    def test_env_var_credentials(self):
        result = scrub_text("AWS_CREDENTIALS=abc123xyz")
        assert REDACTED in result
        assert "abc123xyz" not in result

    def test_bearer_token(self):
        result = scrub_text("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
        assert "Bearer" in result
        assert result.count(REDACTED) >= 1

    def test_basic_auth(self):
        result = scrub_text("Basic dXNlcjpwYXNz")
        assert "Basic" in result
        assert "dXNlcjpwYXNz" not in result

    def test_connection_string_postgres(self):
        result = scrub_text("postgres://admin:s3cret@db.example.com:5432/mydb")
        assert REDACTED in result
        assert "s3cret" not in result

    def test_connection_string_mongodb(self):
        result = scrub_text("mongodb+srv://user:pass123@cluster.mongodb.net/db")
        assert REDACTED in result
        assert "pass123" not in result

    def test_connection_string_mysql(self):
        result = scrub_text("mysql://root:password@localhost/mydb")
        assert REDACTED in result
        assert "password" not in result

    def test_cli_password_flag(self):
        result = scrub_text("mysql --password secretpass -u root")
        assert REDACTED in result
        assert "secretpass" not in result

    def test_cli_token_flag_equals(self):
        result = scrub_text("curl --token=abc123secret")
        assert REDACTED in result
        assert "abc123secret" not in result

    def test_cli_api_key_flag(self):
        result = scrub_text("tool --api-key mykey123")
        assert REDACTED in result
        assert "mykey123" not in result

    def test_header_authorization(self):
        result = scrub_text('-H "Authorization: Bearer tok123"')
        assert REDACTED in result
        assert "tok123" not in result

    def test_header_x_api_key(self):
        result = scrub_text("-H 'X-Api-Key: secret-key-value'")
        assert REDACTED in result
        assert "secret-key-value" not in result

    def test_header_long_form(self):
        result = scrub_text('--header "Authorization: Bearer mytoken123"')
        assert REDACTED in result
        assert "mytoken123" not in result

    def test_header_x_api_key_long_form(self):
        result = scrub_text('--header "X-Api-Key: live_aw2aglwrZrpQ"')
        assert REDACTED in result
        assert "live_aw2aglwrZrpQ" not in result

    def test_json_api_key_field(self):
        result = scrub_text('"api_key": "sk-ant-o1234567890abcdef"')
        assert REDACTED in result
        assert "sk-ant-o1234567890abcdef" not in result

    def test_json_token_field(self):
        result = scrub_text('"token": "my-secret-token-value"')
        assert REDACTED in result
        assert "my-secret-token-value" not in result

    def test_json_password_field(self):
        result = scrub_text('"password": "hunter2"')
        assert REDACTED in result
        assert "hunter2" not in result

    def test_json_secret_field(self):
        result = scrub_text('"secret": "abcdef123456"')
        assert REDACTED in result
        assert "abcdef123456" not in result

    def test_curl_basic_auth(self):
        result = scrub_text("curl -u admin:secretpass https://api.example.com")
        assert REDACTED in result
        assert "admin:secretpass" not in result

    def test_colon_separated_token(self):
        result = scrub_text("token:sk-ant-o12345678901234567890")
        assert REDACTED in result
        assert "sk-ant-o12345678901234567890" not in result

    def test_colon_separated_api_key(self):
        result = scrub_text("api_key:mySecretKeyValue1234")
        assert REDACTED in result
        assert "mySecretKeyValue1234" not in result


# -----------------------------------------------------------------------
# Negative tests — should NOT be redacted
# -----------------------------------------------------------------------

class TestNegatives:
    """Normal commands and strings should pass through untouched."""

    def test_git_status(self):
        assert scrub_text("git status") == "git status"

    def test_npm_install(self):
        assert scrub_text("npm install express") == "npm install express"

    def test_ls_command(self):
        assert scrub_text("ls -la /home/user") == "ls -la /home/user"

    def test_python_script(self):
        assert scrub_text("python main.py --verbose") == "python main.py --verbose"

    def test_curl_no_auth(self):
        assert scrub_text("curl https://example.com/api/health") == "curl https://example.com/api/health"

    def test_short_sk_not_key(self):
        # "sk-" alone or with very short suffix should not match
        assert scrub_text("sk-short") == "sk-short"

    def test_normal_path(self):
        assert scrub_text("/usr/local/bin/node") == "/usr/local/bin/node"

    def test_docker_run(self):
        text = "docker run -p 8080:80 nginx:latest"
        assert scrub_text(text) == text

    def test_env_var_non_sensitive(self):
        text = "NODE_ENV=production"
        assert scrub_text(text) == text


# -----------------------------------------------------------------------
# URL scrubbing
# -----------------------------------------------------------------------

class TestScrubUrl:
    """URL-specific scrubbing of query params and userinfo."""

    def test_sensitive_query_param_api_key(self):
        url = "https://api.example.com/v1?api_key=secret123&format=json"
        result = scrub_url(url)
        assert "secret123" not in result
        assert "format=json" in result
        assert REDACTED in result

    def test_sensitive_query_param_token(self):
        url = "https://example.com/data?token=abc123"
        result = scrub_url(url)
        assert "abc123" not in result
        assert REDACTED in result

    def test_sensitive_query_param_access_token(self):
        url = "https://example.com/api?access_token=mytoken&page=1"
        result = scrub_url(url)
        assert "mytoken" not in result
        assert "page=1" in result

    def test_sensitive_query_param_password(self):
        url = "https://example.com/login?password=hunter2"
        result = scrub_url(url)
        assert "hunter2" not in result

    def test_userinfo_password(self):
        url = "https://admin:supersecret@db.example.com/data"
        result = scrub_url(url)
        assert "supersecret" not in result
        assert "admin" in result
        assert REDACTED in result

    def test_safe_url_untouched(self):
        url = "https://example.com/path?page=1&sort=asc"
        assert scrub_url(url) == url

    def test_empty_url(self):
        assert scrub_url("") == ""

    def test_nonsense_url_falls_back(self):
        # Non-URL string still gets text scrubbing
        result = scrub_url("ghp_ABCDEFghijklmnopqrstuv1234567890")
        assert REDACTED in result

    def test_multiple_sensitive_params(self):
        url = "https://api.com/v1?api_key=k1&secret=s2&mode=test"
        result = scrub_url(url)
        assert "k1" not in result
        assert "s2" not in result
        assert "mode=test" in result

    def test_sensitive_query_param_refresh_token(self):
        url = "https://example.com/auth?refresh_token=abc123"
        result = scrub_url(url)
        assert "abc123" not in result
        assert REDACTED in result

    def test_sensitive_query_param_session_token(self):
        url = "https://example.com/api?session_token=xyz789"
        result = scrub_url(url)
        assert "xyz789" not in result
        assert REDACTED in result

    def test_sensitive_query_param_auth(self):
        url = "https://example.com/api?auth=secretvalue&page=1"
        result = scrub_url(url)
        assert "secretvalue" not in result
        assert "page=1" in result

    def test_sensitive_query_param_credentials(self):
        url = "https://example.com/api?credentials=mytoken123"
        result = scrub_url(url)
        assert "mytoken123" not in result
        assert REDACTED in result


# -----------------------------------------------------------------------
# Dict / argument scrubbing
# -----------------------------------------------------------------------

class TestScrubArguments:
    """Walk dicts/lists, scrub strings, leave other types alone."""

    def test_simple_dict(self):
        args = {"command": "export API_KEY=secret123"}
        result = scrub_arguments(args)
        assert "secret123" not in result["command"]
        assert REDACTED in result["command"]

    def test_url_value(self):
        args = {"url": "https://api.com/v1?api_key=secret"}
        result = scrub_arguments(args)
        assert "secret" not in result["url"]

    def test_nested_dict(self):
        args = {"outer": {"command": "ghp_ABCDEFghijklmnopqrstuv1234567890"}}
        result = scrub_arguments(args)
        assert REDACTED in result["outer"]["command"]

    def test_list_values(self):
        args = {"commands": ["git status", "export TOKEN=abc123"]}
        result = scrub_arguments(args)
        assert result["commands"][0] == "git status"
        assert "abc123" not in result["commands"][1]

    def test_non_string_values_pass_through(self):
        args = {"count": 42, "enabled": True, "data": None}
        result = scrub_arguments(args)
        assert result == args

    def test_no_mutation(self):
        original = {"command": "export API_KEY=secret123"}
        _ = scrub_arguments(original)
        assert original["command"] == "export API_KEY=secret123"

    def test_mixed_types(self):
        args = {
            "command": "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx",
            "timeout": 30,
            "verbose": True,
            "url": "https://example.com?token=secret",
        }
        result = scrub_arguments(args)
        assert REDACTED in result["command"]
        assert result["timeout"] == 30
        assert result["verbose"] is True
        assert "secret" not in result["url"]

    def test_empty_dict(self):
        assert scrub_arguments({}) == {}

    def test_non_dict_input(self):
        assert scrub_arguments(42) == 42
        assert scrub_arguments(None) is None
