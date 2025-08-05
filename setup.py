#!/usr/bin/env python3
"""
Setup script for PhishScanner.

This script helps users set up PhishScanner with proper configuration,
creates a virtual environment, installs dependencies, and validates the installation.

Author: 0x4hm3d
Version: 2.0
"""

import sys
import subprocess
from pathlib import Path
import venv
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm
from rich.table import Table

console = Console()


def check_python_version() -> bool:
    if sys.version_info < (3, 8):
        console.print("[red]Error: Python 3.8 or higher is required[/red]")
        console.print(f"Current version: {sys.version}")
        return False
    console.print(f"[green]\u2713[/green] Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True


def create_virtual_environment(venv_path: Path = Path("venv")) -> bool:
    if venv_path.exists():
        console.print(f"[green]\u2713[/green] Virtual environment already exists at {venv_path}")
        return True
    try:
        console.print(f"[cyan]Creating virtual environment at {venv_path}[/cyan]")
        venv.EnvBuilder(with_pip=True).create(venv_path)
        console.print(f"[green]\u2713[/green] Virtual environment created at {venv_path}")
        return True
    except Exception as e:
        console.print(f"[red]Failed to create virtual environment: {e}[/red]")
        return False


def install_dependencies(venv_path: Path = Path("venv")) -> bool:
    requirements_file = Path("requirements.txt")
    pip_path = venv_path / "bin" / "pip"

    if not requirements_file.exists():
        console.print("[red]Error: requirements.txt not found[/red]")
        return False
    if not pip_path.exists():
        console.print(f"[red]Error: pip not found in virtual environment at {pip_path}[/red]")
        return False

    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Installing dependencies...", total=None)
            subprocess.run([str(pip_path), "install", "-r", str(requirements_file)], capture_output=True, text=True, check=True)
            progress.remove_task(task)
        console.print("[green]\u2713[/green] Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error installing dependencies: {e}[/red]")
        console.print(f"Output: {e.stdout}")
        console.print(f"Error: {e.stderr}")
        return False


def create_directories() -> bool:
    directories = [Path("logs"), Path("results"), Path("cache")]
    try:
        for directory in directories:
            directory.mkdir(exist_ok=True)
            console.print(f"[green]\u2713[/green] Created directory: {directory}")
        return True
    except Exception as e:
        console.print(f"[red]Error creating directories: {e}[/red]")
        return False


def setup_configuration() -> bool:
    config_file = Path("config/config.ini")
    if config_file.exists() and not Confirm.ask("Configuration file exists. Overwrite?", default=False):
        console.print("[yellow]Keeping existing configuration[/yellow]")
        return True

    try:
        from config_validator import ConfigValidator
        validator = ConfigValidator()
        success = validator.create_sample_config(config_file)
        if success:
            console.print(f"[green]\u2713[/green] Configuration template created: {config_file}")
            console.print("[yellow]Please edit the configuration file with your API keys[/yellow]")
            return True
        else:
            console.print("[red]Failed to create configuration file[/red]")
            return False
    except ImportError:
        console.print("[red]Error: config_validator module not found[/red]")
        return False


def validate_database_files() -> bool:
    db_files = [
        Path("db/user_agents.db"),
        Path("db/ip_tracking_domains.json"),
        Path("db/url_shortener_domains.db")
    ]
    missing_files = [f for f in db_files if not f.exists()]
    for f in db_files:
        if f.exists():
            console.print(f"[green]\u2713[/green] Found: {f}")
    if missing_files:
        console.print("[red]Missing database files:[/red]")
        for f in missing_files:
            console.print(f"  - {f}")
        return False
    return True


def run_tests() -> bool:
    test_file = Path("test_phishscanner.py")
    if not test_file.exists():
        console.print("[yellow]Test file not found, skipping tests[/yellow]")
        return True
    if not Confirm.ask("Run test suite?", default=True):
        return True

    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Running tests...", total=None)
            result = subprocess.run([sys.executable, str(test_file)], capture_output=True, text=True)
            progress.remove_task(task)

        if result.returncode == 0:
            console.print("[green]\u2713[/green] All tests passed")
            return True
        else:
            console.print("[red]Some tests failed[/red]")
            console.print(result.stdout)
            console.print(result.stderr)
            return False
    except Exception as e:
        console.print(f"[red]Error running tests: {e}[/red]")
        return False


def display_setup_summary(success_steps: List[str], failed_steps: List[str]) -> None:
    table = Table(title="Setup Summary", show_header=True, header_style="bold magenta")
    table.add_column("Step", style="cyan")
    table.add_column("Status", justify="center")
    for step in success_steps:
        table.add_row(step, "[green]\u2713 Success[/green]")
    for step in failed_steps:
        table.add_row(step, "[red]\u2717 Failed[/red]")
    console.print(table)


def display_next_steps() -> None:
    message = """
[bold green]Setup Complete![/bold green]

[bold yellow]Next Steps:[/bold yellow]

1. [cyan]Activate Environment[/cyan]
   [bold]source venv/bin/activate[/bold]

2. [cyan]Configure API Keys[/cyan]
   Edit [bold]config/config.ini[/bold] with your keys:
   • AbuseIPDB, VirusTotal, URLScan

3. [cyan]Test Tool[/cyan]
   [bold]python PhishScanner.py -u https://example.com[/bold]

4. [cyan]Help Menu[/cyan]
   [bold]python PhishScanner.py --help[/bold]

[bold red]🔍 First Check, Then Click![/bold red]
"""
    console.print(Panel(message, title="[bold green]PhishScanner Setup[/bold green]", border_style="green", padding=(1, 2)))


def main():
    console.print(Panel(
        "[bold cyan]PhishScanner v2.0 Setup[/bold cyan]\nThis script will help you set up PhishScanner with all required dependencies.",
        title="[bold red]Setup Wizard[/bold red]", border_style="cyan"))

    setup_steps = [
        ("Python Version Check", check_python_version),
        ("Create Virtual Environment", create_virtual_environment),
        ("Install Dependencies", install_dependencies),
        ("Create Directories", create_directories),
        ("Setup Configuration", setup_configuration),
        ("Validate Database Files", validate_database_files),
        ("Run Tests", run_tests)
    ]

    success_steps, failed_steps = [], []
    for name, func in setup_steps:
        console.print(f"\n[bold blue]Step: {name}[/bold blue]")
        try:
            if func():
                success_steps.append(name)
            else:
                failed_steps.append(name)
                if name in ["Python Version Check", "Install Dependencies"]:
                    break
        except Exception as e:
            console.print(f"[red]Error in {name}: {e}[/red]")
            failed_steps.append(name)

    console.print("\n")
    display_setup_summary(success_steps, failed_steps)
    if not failed_steps:
        display_next_steps()
    else:
        console.print("\n[red]Setup completed with errors. Please resolve the issues above.[/red]")


if __name__ == "__main__":
    main()
