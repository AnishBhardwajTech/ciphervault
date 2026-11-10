from ciphervault import cli


def test_cli_flow(tmp_path, monkeypatch, capsys):
    db = f"sqlite:///{tmp_path / 'v.db'}"
    answers = iter(["a-long-master-password", "a-long-master-password"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_: next(answers))
    monkeypatch.setattr("ciphervault.crypto.DEFAULT_ITERATIONS", 1000)
    assert cli.main(["--db", db, "-u", "anish", "init"]) == 0

    answers = iter(["a-long-master-password", "s3cret"])
    monkeypatch.setattr("builtins.input", lambda *_: "")
    assert cli.main(["--db", db, "-u", "anish", "add", "github"]) == 0

    answers = iter(["a-long-master-password"])
    assert cli.main(["--db", db, "-u", "anish", "get", "github", "--show"]) == 0
    assert "s3cret" in capsys.readouterr().out

    answers = iter(["wrong-password-xx"])
    assert cli.main(["--db", db, "-u", "anish", "list"]) == 1


def test_generate(capsys):
    assert cli.main(["generate", "-n", "30"]) == 0
    assert len(capsys.readouterr().out.strip()) == 30
