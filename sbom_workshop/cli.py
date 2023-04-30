import typer

from . import go, java, python, rust

app = typer.Typer()

app.add_typer(java.app, name="java")
app.add_typer(python.app, name="python")
app.add_typer(go.app, name="go")
app.add_typer(rust.app, name="rust")


if __name__ == "__main__":
    app()
