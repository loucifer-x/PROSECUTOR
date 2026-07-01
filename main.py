import importlib.util
import os
import argparse
from crawler import crawl
from rich.console import Console

from spa_parser import parse_spa
console = Console()

import os
import importlib.util

class LazyAddons:
    def __init__(self, folder="scanners"):
        self.paths = {}
        self.cache = {}

        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith(".py"):
                    name = os.path.splitext(file)[0]
                    self.paths[name] = os.path.join(root, file)

    def __str__(self):
        x = " | ".join(self.paths.keys())
        return x.upper()

    def __iter__(self):
        return iter(self.paths)

    def __contains__(self, name):
        return name in self.paths

    def __getitem__(self, name):
        if name in self.cache:
            return self.cache[name]

        import sys

        path = self.paths[name]
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)

        # register before exec for dataclasses/import resolution
        sys.modules[name] = module
        spec.loader.exec_module(module)

        func = getattr(module, name)
        self.cache[name] = func

        return func

def main():
    arg_parser = argparse.ArgumentParser(description="Website")
    arg_parser.add_argument("url", help="Website")
    args = arg_parser.parse_args()
    url = args.url

    parse_spa(url)

    console.rule("[bold red]")
    console.print("""[bold red]
██████╗ ██████╗  ██████╗ ███████╗ ██████╗██╗   ██╗████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝██████╔╝██║   ██║███████╗██║     ██║   ██║   ██║   ██║   ██║██████╔╝
██╔═══╝ ██╔══██╗██║   ██║╚════██║██║     ██║   ██║   ██║   ██║   ██║██╔══██╗
██║     ██║  ██║╚██████╔╝███████║╚██████╗╚██████╔╝   ██║   ╚██████╔╝██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝
    [/]""")
    addons = LazyAddons("scanners")
    console.print(f"[bold red]SCANNERS[/] - [yellow]{addons}[/]")
    console.print(f"[bold red]PROSECUTING[/] - [white]{url}[/]")
    console.print("""[yellow]
WARNING
Perscrutator is intended for authorized security testing,
research, and educational purposes only.
Do NOT use this tool against systems, websites, or networks
without explicit permission from the owner.
Unauthorized scanning may be illegal.
The user is responsible for ensuring they have permission
before running this software.
[/]""")
    console.rule("[bold red]")
    # Map short aliases → actual scanner filename (without .py)
    aliases = {

    }


    while True:
        try:
            command = input(">").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[bold red]Exiting.[/]")
            break

        if not command:
            continue

        # ── url <target> ───────────────────────────────────────────────────────
        if command.startswith("url"):
            parts = command.split()
            if len(parts) < 2:
                console.print("[red]Usage: url <target>[/]")
                continue

            target = parts[1]
            if not target.startswith(("http://", "https://")):
                url = f"https://{target}"
            else:
                url = target

            console.rule("[bold red]")
            console.print(f"[bold red]NEW TARGET - [/][white]{url}[/]")
            console.rule("[bold red]")

        # ── addon commands ─────────────────────────────────────────────────────
# ── addon commands ─────────────────────────────────────────────────────
        else:
            parts = command.split()
            addon_name = parts[0]
            addon_name = aliases.get(addon_name, addon_name)

            crawl_mode = len(parts) > 1 and parts[1].lower() == "crawl"

            if addon_name in addons:
                try:

                    if crawl_mode:
                        console.rule("[bold cyan]Crawler Mode[/]")
                        console.print(f"[cyan]Running {addon_name.upper()} against crawled pages...[/]")
                        console.rule("[bold cyan]")

                        # Your existing crawler
                        pages = crawl(url)

                        findings_found = []

                        for page in pages:
                            try:
                                console.print(f"[blue]Scanning:[/] {page}")

                                asset = parse_spa(page)
                                result = addons[addon_name](asset)

                                if isinstance(result, dict) and result.get("findings"):
                                    for finding in result["findings"]:
                                        findings_found.append({
                                            "url": page,
                                            "finding": finding
                                        })

                            except Exception as e:
                                console.print(
                                    f"[yellow]Error scanning {page}: {e}[/]"
                                )

                        # Final results after crawl finishes
                        console.rule("[bold red]Scan Complete[/]")

                        if findings_found:
                            console.print(
                                f"[bold red]Possible {addon_name.upper()} vulnerability found![/]"
                            )

                            console.rule("[bold red]")

                            for item in findings_found:
                                finding = item["finding"]

                                console.print(
                                    f"[bold red]Possible {addon_name.upper()} vulnerability found on:[/]"
                                )
                                console.print(
                                    f"[white]{item['url']}[/]"
                                )

                                console.print(
                                    "Field   :",
                                    finding["source"].get("field_name")
                                )

                                console.print(
                                    "Payload :",
                                    finding["payload"]
                                )

                                console.print(
                                    "Trigger :",
                                    ", ".join(finding["triggered_by"])
                                )

                                console.print(
                                    "Status  :",
                                    finding["status_code"]
                                )

                                console.print()

                            console.rule("[bold red]")

                        else:
                            console.print(
                                f"[green]No {addon_name.upper()} vulnerabilities found.[/]"
                            )

                    else:
                        # Normal single URL scan
                        asset = parse_spa(url)
                        result = addons[addon_name](asset)

                        try:
                            if result["findings"]:
                                console.rule("[bold red][/]")
                                console.print(
                                    f"[bold red]POSSIBLE {addon_name.upper()} VULNERABILITY FOUND![/]"
                                )
                                console.rule("[bold red]")

                                for finding in result["findings"]:
                                    print(
                                        "Field   :",
                                        finding["source"].get("field_name")
                                    )
                                    print(
                                        "Payload :",
                                        finding["payload"]
                                    )
                                    print(
                                        "Trigger :",
                                        ", ".join(finding["triggered_by"])
                                    )
                                    print(
                                        "Status  :",
                                        finding["status_code"]
                                    )
                                    print()

                                console.rule("[bold red][/]")
                        
                        except:
                            if isinstance(result, str):
                                console.rule("[bold red]Addon output[/]")
                                console.print(f"[white]{result}[/]")
                                console.rule("[bold red]")

                except TypeError as e:
                    console.print(
                        f"[red]Argument error for '{addon_name}': {e}[/]"
                    )

            else:
                console.print(
                    f"[red]Unknown command '{addon_name}'. Type 'help' for options.[/]"
                )
if __name__ == "__main__":
    main()
