
import click
import httpx
from rich.console import Console
from rich.table import Table

from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.database.models import Target
from app.database.session import db_session, init_db
from app.security.authorization import AuthorizationError, TargetAuthorizationGuard

console = Console()
logger = get_logger(__name__)
guard = TargetAuthorizationGuard()

API_BASE_URL = f"http://{settings.api_host}:{settings.api_port}"


def get_api_client() -> httpx.Client:
    return httpx.Client(base_url=API_BASE_URL, timeout=30.0)


@click.group()
@click.option("--debug/--no-debug", default=False)
@click.version_option(version=settings.app_version)
def cli(debug: bool):
    """AI Red Team - Security Testing Platform for AI Applications"""
    configure_logging("DEBUG" if debug else settings.log_level, settings.log_format)
    init_db()


@cli.group()
def target():
    """Manage scan targets"""


@target.command("add")
@click.argument("name")
@click.argument("url")
@click.option("--type", "target_type", type=click.Choice(["llm", "rag", "agent"]), default="llm")
@click.option("--header", "headers", multiple=True, help="Header in format 'Key: Value'")
def add_target(name: str, url: str, target_type: str, headers: tuple):
    """Add a new scan target"""
    try:
        guard.authorize_or_raise(url)
    except AuthorizationError as e:
        console.print(f"[red]Authorization failed: {e}[/red]")
        console.print("[yellow]Use --allow-remote to override (not recommended for production)[/yellow]")
        return

    parsed_headers = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            parsed_headers[k.strip()] = v.strip()

    with db_session() as db:
        target = Target(
            name=name,
            target_type=target_type,
            base_url=url,
            config={},
            is_authorized=True,
        )
        db.add(target)
        db.commit()
        db.refresh(target)

    console.print(f"[green]Target '{name}' added with ID {target.id}[/green]")


@target.command("list")
def list_targets():
    """List all targets"""
    with db_session() as db:
        targets = db.query(Target).all()

    table = Table(title="Scan Targets")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("URL", style="blue")
    table.add_column("Authorized", style="magenta")
    table.add_column("Created", style="dim")

    for t in targets:
        table.add_row(
            str(t.id),
            t.name,
            t.target_type,
            t.base_url,
            "✓" if t.is_authorized else "✗",
            t.created_at.strftime("%Y-%m-%d %H:%M") if t.created_at else "N/A",
        )

    console.print(table)


@target.command("remove")
@click.argument("target_id", type=int)
def remove_target(target_id: int):
    """Remove a target"""
    with db_session() as db:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            console.print(f"[red]Target {target_id} not found[/red]")
            return
        db.delete(target)
        db.commit()
    console.print(f"[green]Target {target_id} removed[/green]")


@cli.group()
def scan():
    """Manage security scans"""


@scan.command("start")
@click.argument("target_id", type=int)
@click.option("--attack", "attack_ids", multiple=True, help="Specific attack IDs to run")
@click.option("--category", "categories", multiple=True, help="Categories to run (e.g., LLM01, LLM02)")
def start_scan(target_id: int, attack_ids: tuple, categories: tuple):
    """Start a security scan"""
    with get_api_client() as client:
        payload = {"target_id": target_id}
        if attack_ids:
            payload["attack_ids"] = list(attack_ids)
        if categories:
            payload["categories"] = list(categories)

        try:
            response = client.post("/scans", json=payload)
            response.raise_for_status()
            scan = response.json()
            console.print(f"[green]Scan started: ID {scan['id']}[/green]")
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Failed to start scan: {e.response.text}[/red]")


@scan.command("list")
def list_scans():
    """List all scans"""
    with get_api_client() as client:
        try:
            response = client.get("/scans")
            response.raise_for_status()
            scans = response.json()
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Failed to list scans: {e.response.text}[/red]")
            return

    table = Table(title="Scans")
    table.add_column("ID", style="cyan")
    table.add_column("Target", style="green")
    table.add_column("Taxonomy", style="yellow")
    table.add_column("Status", style="magenta")
    table.add_column("Started", style="dim")
    table.add_column("Completed", style="dim")

    for s in scans:
        table.add_row(
            str(s["id"]),
            str(s["target_id"]),
            s["taxonomy_version"],
            s["status"],
            s["started_at"] or "N/A",
            s["completed_at"] or "N/A",
        )

    console.print(table)


@scan.command("findings")
@click.argument("scan_id", type=int)
def scan_findings(scan_id: int):
    """Show findings for a scan"""
    with get_api_client() as client:
        try:
            response = client.get(f"/scans/{scan_id}/findings")
            response.raise_for_status()
            findings = response.json()
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Failed to get findings: {e.response.text}[/red]")
            return

    if not findings:
        console.print("[yellow]No findings for this scan[/yellow]")
        return

    table = Table(title=f"Findings for Scan {scan_id}")
    table.add_column("ID", style="cyan")
    table.add_column("Attack ID", style="yellow")
    table.add_column("Category", style="blue")
    table.add_column("Title", style="green")
    table.add_column("Severity", style="red")
    table.add_column("Status", style="magenta")

    for f in findings:
        table.add_row(
            str(f["id"]),
            f["attack_id"],
            f["category"],
            f["title"][:60] + "..." if len(f["title"]) > 60 else f["title"],
            f["severity"],
            f["regression_status"],
        )

    console.print(table)


@cli.group()
def attacks():
    """Manage attack definitions"""


@attacks.command("list")
@click.option("--category", help="Filter by category")
def list_attacks(category: str | None):
    """List available attacks"""
    with get_api_client() as client:
        params = {}
        if category:
            params["category"] = category
        try:
            response = client.get("/attacks", params=params)
            response.raise_for_status()
            attacks = response.json()
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Failed to list attacks: {e.response.text}[/red]")
            return

    table = Table(title="Available Attacks")
    table.add_column("Attack ID", style="cyan")
    table.add_column("Category", style="yellow")
    table.add_column("Name", style="green")
    table.add_column("Severity", style="red")
    table.add_column("Target Types", style="blue")

    for a in attacks:
        table.add_row(
            a["attack_id"],
            a["category"],
            a["name"],
            a["severity"],
            ", ".join(a["target_types"]),
        )

    console.print(table)


@cli.group()
def checklist():
    """Manage project checklist"""


@checklist.command("show")
def show_checklist():
    """Show project checklist"""
    with get_api_client() as client:
        try:
            response = client.get("/checklist")
            response.raise_for_status()
            items = response.json()
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Failed to get checklist: {e.response.text}[/red]")
            return

    current_sprint = None
    for item in items:
        if item["sprint"] != current_sprint:
            current_sprint = item["sprint"]
            console.print(f"\n[bold cyan]{current_sprint}[/bold cyan]")

        status_icon = {
            "TODO": "[ ]",
            "IN_PROGRESS": "[-]",
            "VERIFIED": "[x]",
            "BLOCKED": "[!]",
        }.get(item["status"], "[?]")

        console.print(f"  {status_icon} {item['task']}")


@checklist.command("update")
@click.argument("item_id", type=int)
@click.option("--status", type=click.Choice(["TODO", "IN_PROGRESS", "VERIFIED", "BLOCKED"]))
@click.option("--tests-exist/--no-tests-exist", default=None)
@click.option("--tests-pass/--no-tests-pass", default=None)
@click.option("--docs-updated/--no-docs-updated", default=None)
@click.option("--acceptance-met/--no-acceptance-met", default=None)
def update_checklist(
    item_id: int,
    status: str | None,
    tests_exist: bool | None,
    tests_pass: bool | None,
    docs_updated: bool | None,
    acceptance_met: bool | None,
):
    """Update a checklist item"""
    with get_api_client() as client:
        payload = {}
        if status:
            payload["status"] = status
        if tests_exist is not None:
            payload["tests_exist"] = tests_exist
        if tests_pass is not None:
            payload["tests_pass"] = tests_pass
        if docs_updated is not None:
            payload["docs_updated"] = docs_updated
        if acceptance_met is not None:
            payload["acceptance_criteria_met"] = acceptance_met

        try:
            response = client.patch(f"/checklist/{item_id}", json=payload)
            response.raise_for_status()
            console.print(f"[green]Checklist item {item_id} updated[/green]")
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Failed to update checklist: {e.response.text}[/red]")


@cli.group()
def retest():
    """Retest and regression (Sprint 8)"""


@retest.command("finding")
@click.argument("finding_id", type=int)
def retest_finding(finding_id: int):
    """Retest a finding (real: new scan for same attack, compare before/after, update regression status, store history)"""
    with get_api_client() as client:
        try:
            resp = client.post(f"/findings/{finding_id}/retest")
            resp.raise_for_status()
            data = resp.json()
            console.print(f"[green]Retest {data['retest_id']} for finding {finding_id}: {data['result']} -> {data['regression_status']}[/green]")
            console.print(f"  Retest scan {data['scan_id']}: {data['notes']}")
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Retest failed: {e.response.text}[/red]")


@retest.command("history")
@click.argument("finding_id", type=int)
def retest_history(finding_id: int):
    """Show regression history for a finding"""
    with get_api_client() as client:
        try:
            resp = client.get(f"/findings/{finding_id}/history")
            resp.raise_for_status()
            history = resp.json()
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Failed: {e.response.text}[/red]")
            return
    if not history:
        console.print("[yellow]No retest history[/yellow]")
        return
    table = Table(title=f"Retest History for Finding {finding_id}")
    table.add_column("Retest ID", style="cyan")
    table.add_column("Scan ID", style="green")
    table.add_column("Result", style="yellow")
    table.add_column("Notes", style="dim")
    for r in history:
        table.add_row(str(r["id"]), str(r["scan_id"]), r["result"], r["notes"] or "")
    console.print(table)


@retest.command("compare")
@click.argument("finding_id", type=int)
def retest_compare(finding_id: int):
    """Compare before/after for a finding"""
    with get_api_client() as client:
        try:
            resp = client.get(f"/findings/{finding_id}/compare")
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Failed: {e.response.text}[/red]")
            return
    console.print(f"[cyan]Finding {finding_id} {data['attack_id']}: {data['original_result']} -> {data['latest_retest']['result'] if data['latest_retest'] else 'no retest'} ({data['regression_status']})[/cyan]")
    console.print(f"Original evidence: {data['original_evidence']}")
    if data["latest_retest"]:
        console.print(f"Latest retest evidence: {data['latest_retest']['evidence']}")


@retest.command("lifecycle")
@click.argument("finding_id", type=int)
def retest_lifecycle(finding_id: int):
    """Show finding lifecycle timeline"""
    with get_api_client() as client:
        try:
            resp = client.get(f"/findings/{finding_id}/lifecycle")
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            console.print(f"[red]Failed: {e.response.text}[/red]")
            return
    console.print(f"[green]Finding {finding_id} lifecycle: {data['current_status']} ({data['retest_count']} retests)[/green]")
    for h in data["history"]:
        console.print(f"  Scan {h['scan_id']}: {h['result']} at {h['created_at']}")


@cli.command()
def serve():
    """Start the API server"""
    import uvicorn
    console.print(f"[green]Starting API server on {settings.api_host}:{settings.api_port}[/green]")
    uvicorn.run("app.api.main:app", host=settings.api_host, port=settings.api_port, reload=settings.debug)


@cli.command()
def init():
    """Initialize the database"""
    init_db()
    console.print("[green]Database initialized[/green]")


if __name__ == "__main__":
    cli()
