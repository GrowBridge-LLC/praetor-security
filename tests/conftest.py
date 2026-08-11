"""Put scripts/ on sys.path -- the engines import each other flat (`from core import ...`)."""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "scripts"))
sys.path.insert(0, os.path.join(_ROOT, "tools"))

# The differential gate is a standalone script (precommit runs it directly), but
# it is also the ONE home for the Python side of the cross-language signature.
# test_line_numbering_consistency.py imports it rather than keeping a second copy
# of escape/unescape -- a file about there being one definition of a line should
# not itself carry two definitions of the corpus format.
sys.path.insert(0, os.path.join(_ROOT, "tests", "differential"))
