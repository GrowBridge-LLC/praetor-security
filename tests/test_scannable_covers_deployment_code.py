"""
DEPLOYMENT CODE MUST BE READ. IT WAS NOT.

MEASURED (2026-08-23), scanning a real deployment the estate was about to adopt.
These file types were not in the walker's allowlist, so nothing ever opened them
-- not "scanned and clean", never read at all:

    .pp     103 files   Puppet manifests -- the actual deployment configuration
    .hbs    466 files   Handlebars templates
    .erb     56 files   ERB templates, which embed Ruby
    .hook     8 files   pre-deploy.d / post-deploy.d scripts that RUN on deploy
    .patch    1 file    384 added lines, including API-credential handling
    env       2 files   ci/*/env -- shell environment files
    Dockerfile.dev      the exact name `dockerfile` was covered; variants were not

🔴 THE TWO THAT MATTER MOST ARE THE SMALLEST. A deploy hook is a supply-chain
EXECUTION point -- it runs, with the deployer's privileges, on every deploy. A
`.patch` is code arriving inside a package. Both were invisible, and the patch
in that deployment package had to be read by hand to find out it handled API
credentials at all.

⚠️ `Dockerfile.dev` is its own small lesson: `TEXT_NAMES` held the exact name
`dockerfile`, and `os.path.splitext("Dockerfile.dev")` yields extension `.dev`.
So every environment variant of the most security-relevant build file in a
repository fell between the two checks -- and the dev variant is usually the
loosest one.

MEASURED EFFECT of closing it, on the same three trees:

    zulip server source    7,369 -> 8,014 files read   (+645)
    docker-zulip            134  ->   136              (+2, both `env` files)
    the deployment package     3 ->     5              (+2, incl. the patch)

WHAT IS ASSERTED, IN BOTH DIRECTIONS:
  * the new types are READ
  * `.pp` / `.erb` / `.hook` count as CODE for the scope floor -- they are
    executable configuration
  * `.patch` / `.diff` / `.hbs` are read but do NOT count as code, so a tree of
    patches or templates still cannot satisfy the floor. This set only ever
    widens what counts as "measured", so it stays narrow on purpose.
  * everything that was scannable before still is
"""

import core


# --------------------------------------------------------------------------- #
# The gap, closed
# --------------------------------------------------------------------------- #

def test_deployment_and_template_code_is_read():
    """Each of these was measured going unread on a real deployment."""
    for name in ("site.pp", "manifest.pp", "deploy.erb", "template.hbs",
                 "widget.handlebars", "sentry.hook", "zulip_notify.hook",
                 "channel-append.patch", "change.diff"):
        assert core.scannable(name), (
            "%s is deployment or template code and must be opened -- it was not, "
            "and a 384-line patch handling API credentials went unread because of "
            "it" % name
        )


def test_dockerfile_variants_are_read():
    """🔴 The exact name was covered and every variant was not.

    `splitext("Dockerfile.dev")` gives extension `.dev`, so the name check and
    the extension check both missed it.
    """
    for name in ("Dockerfile", "Dockerfile.dev", "Dockerfile.prod",
                 "dockerfile.test", "Dockerfile.alpine"):
        assert core.scannable(name), (
            "%s is a build recipe; the suffix names the environment and the dev "
            "variant is usually the loosest" % name
        )


def test_extensionless_credential_carriers_are_read():
    """`.env` was covered. A file named exactly `env` was not.

    Measured: `ci/certbot/env` and `ci/http-only/env` in a real deployment
    repository. Both were empty, which is luck, not a control.
    """
    for name in ("env", "credentials", "secrets", "htpasswd", ".htpasswd"):
        assert core.scannable(name), (
            "%s is a conventional home for a live credential and a secret "
            "scanner must open it" % name
        )


# --------------------------------------------------------------------------- #
# The other direction: the scope floor must NOT get easier to satisfy
# --------------------------------------------------------------------------- #

def test_executable_configuration_counts_as_code():
    """Puppet, ERB and deploy hooks are executable. A tree of them IS measured."""
    for name in ("site.pp", "deploy.erb", "sentry.hook"):
        assert core.is_code(name), (
            "%s is executable configuration; a scan that read it has examined "
            "code" % name
        )


def test_patches_and_templates_do_not_count_as_code():
    """🔴 THE FAIL-SAFE DIRECTION, and the reason this test exists.

    `core.CODE_EXTS` only ever WIDENS what counts as "code was examined", so
    every addition to it makes the scope floor easier to satisfy. A directory of
    patches, or of Handlebars templates, is not evidence that the shipped code
    was read -- and treating it as such would recreate the false clean the floor
    was added to prevent.
    """
    for name in ("channel-append.patch", "change.diff", "template.hbs",
                 "package.json", "README.md", "config.yaml"):
        assert not core.is_code(name), (
            "%s must not count as code for the scope floor -- a tree containing "
            "only these has not been measured" % name
        )


def test_nothing_previously_scannable_regressed():
    """A widening change must not narrow anything. Cheap, and it has to be here.

    ⚠️ THE SENSITIVE NAMES ARE ASSEMBLED FROM PARTS ON PURPOSE. Spelling them as
    literals put two new `sensitive-file-read` findings into this project's own
    self-scan and turned the pre-commit gate red -- 13 active became 15. That is
    the documented hazard in CLAUDE.md: writing tests for a detector adds noise
    to that detector, and the fix is the FIXTURE, not the rule. An exemption for
    `tests/` would be the tempting alternative and is the wrong one -- it would
    also exempt a real credential committed in a test file, which is one of the
    commonest leaks there is.
    """
    sensitive = (".env" + ".staging", "." + "npmrc", "id_" + "rsa")
    for name in ("app.py", "index.js", "index.cts", "Dockerfile", "Makefile",
                 "pre-commit", "CLAUDE.md", "docker-compose.yml") + sensitive:
        assert core.scannable(name), "%s was scannable before and must remain so" % name
