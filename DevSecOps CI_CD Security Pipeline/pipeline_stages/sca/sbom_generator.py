import os
import sys
import subprocess
from rich.console import Console

console = Console()

def run_sbom_generator(target_dir="."):
    """Generate CycloneDX SBOM using Trivy."""
    console.print(f"[bold blue]▶ Generating CycloneDX SBOM for {target_dir}...[/bold blue]")
    
    sbom_path = "findings/sbom.json"
    os.makedirs("findings", exist_ok=True)
    
    try:
        cmd = [
            "trivy",
            "fs",
            "--format", "cyclonedx",
            "--output", sbom_path,
            target_dir
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if os.path.exists(sbom_path):
            console.print(f"[bold green]✔ SBOM successfully generated → {sbom_path}[/bold green]")
        else:
            console.print("[yellow]⚠ Trivy failed to generate SBOM. Is Trivy installed?[/yellow]")
            
    except Exception as e:
        console.print(f"[red]❌ Error generating SBOM: {str(e)}[/red]")
        
    return 0

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(run_sbom_generator(target))
