"""2026-10-05 — no shipped module leaves a file handle to the garbage collector: every open()/urlopen() in the modules
pyproject.toml ships is a `with` item. scores_emergenza opened the ledger lock outside the try that released it, so a flock
that raised left it to the finalizer instead of closing it; this test was RED on that code (line 162) and is GREEN after
the fix."""
import ast, os, re, unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def shipped():
    with open(os.path.join(HERE, "pyproject.toml"), encoding="utf-8") as f:
        m = re.search(r"py-modules\s*=\s*\[(.*?)\]", f.read(), re.S)
    return [n + ".py" for n in re.findall(r"""['"]([A-Za-z0-9_]+)['"]""", m.group(1))]


def unclosed(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    managed = {id(i.context_expr) for n in ast.walk(tree) if isinstance(n, (ast.With, ast.AsyncWith)) for i in n.items}
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and id(n) not in managed:
            fn = n.func
            fname = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
            is_os = isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id == "os"
            if fname in ("open", "urlopen") and not is_os:
                out.append(f"{name}:{n.lineno}")
    return out


class TestOpenHandles(unittest.TestCase):
    def test_every_open_is_a_with_item(self):
        files = shipped()
        self.assertGreater(len(files), 10)                # the module list was read
        self.assertEqual([x for n in files for x in unclosed(n)], [])


if __name__ == "__main__":
    unittest.main()
