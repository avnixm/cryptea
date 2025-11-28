#!/usr/bin/env python3
"""
Automated release script for Cryptea.
Increments version, builds project, creates git tag, and GitHub release.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Tuple

try:
    import requests
except ImportError:
    requests = None


def get_current_version(project_root: Path | None = None) -> str:
    """Get current version from pyproject.toml."""
    if project_root is None:
        project_root = Path(__file__).parent
    
    pyproject = project_root / "pyproject.toml"
    if not pyproject.exists():
        raise FileNotFoundError(f"pyproject.toml not found at {pyproject}")
    
    content = pyproject.read_text(encoding="utf-8")
    match = re.search(r'version\s*=\s*"([^"]+)"', content)
    if not match:
        raise ValueError("Could not find version in pyproject.toml")
    
    return match.group(1)


def increment_version(version: str, bump_type: str = "patch") -> str:
    """
    Increment version number.
    
    Args:
        version: Current version (e.g., "0.1.0")
        bump_type: "major", "minor", or "patch"
    
    Returns:
        New version string
    """
    parts = version.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid version format: {version}")
    
    major, minor, patch = map(int, parts)
    
    if bump_type == "major":
        major += 1
        minor = 0
        patch = 0
    elif bump_type == "minor":
        minor += 1
        patch = 0
    else:  # patch
        patch += 1
    
    return f"{major}.{minor}.{patch}"


def update_version_in_file(
    filepath: Path, old_version: str, new_version: str, project_root: Path | None = None
) -> bool:
    """Update version in a file. Returns True if file was modified."""
    if project_root and not filepath.is_absolute():
        filepath = project_root / filepath
    
    if not filepath.exists():
        return False
    
    content = filepath.read_text(encoding="utf-8")
    original = content
    
    # Replace version strings (handle different quote styles)
    patterns = [
        (rf'version\s*=\s*"{re.escape(old_version)}"', f'version = "{new_version}"'),
        (rf"version\s*:\s*'{re.escape(old_version)}'", f"version: '{new_version}'"),
        (rf'version\s*:\s*"{re.escape(old_version)}"', f'version: "{new_version}"'),
        (rf'APP_VERSION\s*=\s*"{re.escape(old_version)}"', f'APP_VERSION = "{new_version}"'),
        (rf"APP_VERSION\s*=\s*'{re.escape(old_version)}'", f"APP_VERSION = '{new_version}'"),
        # Flatpak manifest version (top-level or module-level)
        (rf'^\s*version\s*:\s*["\']?{re.escape(old_version)}["\']?\s*$', f'version: "{new_version}"'),
    ]
    
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content)
    
    if content != original:
        filepath.write_text(content, encoding="utf-8")
        return True
    
    return False


def update_all_versions(
    old_version: str, new_version: str, project_root: Path | None = None
) -> None:
    """Update version in all relevant files."""
    if project_root is None:
        project_root = Path(__file__).parent
    
    files_to_update = [
        Path("pyproject.toml"),
        Path("meson.build"),
        Path("src/ctf_helper/config.py"),
        Path("src/ctf_helper/config.py.in"),
        Path("org.avnixm.Cryptea.yaml"),
    ]
    
    updated_files = []
    for filepath in files_to_update:
        if update_version_in_file(filepath, old_version, new_version, project_root):
            updated_files.append(filepath)
    
    if not updated_files:
        print(f"⚠️  Warning: No files were updated with new version {new_version}")
    else:
        print(f"✓ Updated version in {len(updated_files)} files:")
        for f in updated_files:
            print(f"  - {f}")


def run_command(cmd: list[str], check: bool = True) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        error_msg = f"Command not found: {cmd[0]}"
        if check:
            raise RuntimeError(error_msg)
        return 1, "", error_msg


def check_git_clean() -> bool:
    """Check if git working directory is clean."""
    returncode, stdout, _ = run_command(["git", "status", "--porcelain"], check=False)
    return returncode == 0 and not stdout


def check_git_remote() -> bool:
    """Check if git remote is configured."""
    returncode, _, _ = run_command(["git", "remote", "get-url", "origin"], check=False)
    return returncode == 0


def get_github_repo() -> str | None:
    """Extract GitHub repo from git remote."""
    returncode, stdout, _ = run_command(["git", "remote", "get-url", "origin"], check=False)
    if returncode != 0:
        return None
    
    # Handle both HTTPS and SSH URLs
    url = stdout.strip()
    # SSH: git@github.com:user/repo.git
    # HTTPS: https://github.com/user/repo.git
    match = re.search(r'(?:github\.com[/:]|git@github\.com:)([^/]+/[^/]+?)(?:\.git)?$', url)
    if match:
        return match.group(1)
    return None


def create_github_release(
    repo: str,
    tag: str,
    version: str,
    release_notes: str | None = None,
    token: str | None = None,
    assets: list[Path] | None = None,
) -> bool:
    """
    Create a GitHub release using gh CLI or GitHub API.
    
    Args:
        repo: GitHub repo (e.g., "user/repo")
        tag: Git tag (e.g., "v0.1.1")
        version: Version string (e.g., "0.1.1")
        release_notes: Optional release notes
        token: Optional GitHub token (for API method)
    
    Returns:
        True if successful
    """
    # Try gh CLI first (simpler)
    returncode, stdout, stderr = run_command(
        ["gh", "--version"],
        check=False,
    )
    
    if returncode == 0:
        print("📦 Creating GitHub release using gh CLI...")
        cmd = ["gh", "release", "create", tag]
        
        if release_notes:
            # Create a temporary file with release notes
            notes_file = Path(f".release_notes_{tag}.md")
            notes_file.write_text(release_notes, encoding="utf-8")
            cmd.extend(["--notes-file", str(notes_file)])
        else:
            cmd.extend(["--notes", f"Release {version}"])
        
        cmd.append("--title")
        cmd.append(f"v{version}")
        
        # Add assets if provided
        if assets:
            for asset in assets:
                if asset.exists():
                    cmd.extend(["--attach", str(asset)])
        
        returncode, stdout, stderr = run_command(cmd, check=False)
        
        if returncode == 0:
            print(f"✓ GitHub release created: {tag}")
            if assets:
                for asset in assets:
                    if asset.exists():
                        file_size = asset.stat().st_size / (1024 * 1024)
                        print(f"  ✓ Uploaded {asset.name} ({file_size:.1f} MB)")
            return True
        else:
            print(f"⚠️  gh CLI failed: {stderr}")
    
    # Fallback to GitHub API
    if requests is None:
        print("⚠️  'requests' library not available and gh CLI failed. Install it with: pip install requests")
        return False
    
    if not token:
        token = get_github_token()
    
    if not token:
        print("⚠️  GitHub token not found. Set GITHUB_TOKEN environment variable or use gh auth token")
        return False
    
    print("📦 Creating GitHub release using GitHub API...")
    
    url = f"https://api.github.com/repos/{repo}/releases"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    data = {
        "tag_name": tag,
        "name": f"v{version}",
        "body": release_notes or f"Release {version}",
        "draft": False,
        "prerelease": False,
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        release_data = response.json()
        release_id = release_data.get("id")
        
        print(f"✓ GitHub release created: {tag}")
        
        # Upload assets if provided
        if assets and release_id:
            upload_url = f"https://uploads.github.com/repos/{repo}/releases/{release_id}/assets"
            
            for asset_path in assets:
                if not asset_path.exists():
                    print(f"⚠️  Asset not found: {asset_path}")
                    continue
                
                asset_name = asset_path.name
                print(f"  Uploading {asset_name}...")
                
                with open(asset_path, "rb") as f:
                    headers_upload = {
                        "Authorization": f"token {token}",
                        "Accept": "application/vnd.github.v3+json",
                        "Content-Type": "application/octet-stream",
                    }
                    
                    params = {"name": asset_name}
                    
                    try:
                        upload_response = requests.post(
                            f"{upload_url}?name={asset_name}",
                            headers=headers_upload,
                            data=f.read(),
                        )
                        upload_response.raise_for_status()
                        file_size = asset_path.stat().st_size / (1024 * 1024)
                        print(f"  ✓ Uploaded {asset_name} ({file_size:.1f} MB)")
                    except requests.exceptions.RequestException as e:
                        print(f"  ⚠️  Failed to upload {asset_name}: {e}")
        
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to create GitHub release: {e}")
        return False


def get_github_token() -> str | None:
    """Get GitHub token from environment or gh CLI."""
    # Check environment variable
    token = os.environ.get("GITHUB_TOKEN")
    
    # Try gh CLI
    if not token:
        returncode, stdout, _ = run_command(["gh", "auth", "token"], check=False)
        if returncode == 0:
            token = stdout.strip()
    
    return token


def generate_release_notes(version: str, old_version: str) -> str:
    """Generate release notes from git log."""
    returncode, stdout, _ = run_command(
        ["git", "log", f"v{old_version}..HEAD", "--pretty=format:- %s", "--reverse"],
        check=False,
    )
    
    if returncode == 0 and stdout:
        return f"""# Cryptea {version}

## Changes

{stdout}

## Installation

See [README.md](README.md) for installation instructions.
"""
    else:
        return f"""# Cryptea {version}

## Installation

See [README.md](README.md) for installation instructions.
"""


def main() -> int:
    """Main release script."""
    parser = argparse.ArgumentParser(
        description="Automated release script for Cryptea",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Increment patch version (0.1.0 -> 0.1.1)
  %(prog)s --minor           # Increment minor version (0.1.0 -> 0.2.0)
  %(prog)s --major           # Increment major version (0.1.0 -> 1.0.0)
  %(prog)s --skip-build      # Skip building
  %(prog)s --skip-release     # Skip GitHub release
  %(prog)s --dry-run          # Show what would be done without making changes
        """,
    )
    
    parser.add_argument(
        "--major",
        action="store_true",
        help="Increment major version",
    )
    parser.add_argument(
        "--minor",
        action="store_true",
        help="Increment minor version",
    )
    parser.add_argument(
        "--patch",
        action="store_true",
        help="Increment patch version (default)",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip building the project",
    )
    parser.add_argument(
        "--flatpak",
        action="store_true",
        help="Build Flatpak package",
    )
    parser.add_argument(
        "--skip-flatpak",
        action="store_true",
        help="Skip building Flatpak package",
    )
    parser.add_argument(
        "--skip-release",
        action="store_true",
        help="Skip creating GitHub release",
    )
    parser.add_argument(
        "--skip-tag",
        action="store_true",
        help="Skip creating git tag",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )
    parser.add_argument(
        "--token",
        help="GitHub token for API (or set GITHUB_TOKEN env var)",
    )
    
    args = parser.parse_args()
    
    # Determine bump type
    if args.major:
        bump_type = "major"
    elif args.minor:
        bump_type = "minor"
    else:
        bump_type = "patch"
    
    print("🚀 Cryptea Release Script")
    print("=" * 50)
    
    # Determine project root (directory containing this script)
    project_root = Path(__file__).parent.resolve()
    print(f"📁 Project root: {project_root}")
    
    # Change to project root directory
    original_cwd = os.getcwd()
    os.chdir(project_root)
    
    try:
        # Get current version
        old_version = get_current_version(project_root)
        print(f"📌 Current version: {old_version}")
        
        # Calculate new version
        new_version = increment_version(old_version, bump_type)
        print(f"📈 New version: {new_version} ({bump_type} bump)")
        
        if args.dry_run:
            print("\n🔍 DRY RUN MODE - No changes will be made")
            print(f"Would update version in: pyproject.toml, meson.build, config.py, config.py.in, org.avnixm.Cryptea.yaml")
            if not args.skip_build:
                print("Would build project with meson")
            if not args.skip_tag:
                print(f"Would create git tag: v{new_version}")
            if not args.skip_release:
                print(f"Would create GitHub release: v{new_version}")
            return 0
        
        # Check git status
        if not check_git_clean():
            print("⚠️  Warning: Git working directory is not clean")
            response = input("Continue anyway? [y/N]: ")
            if response.lower() != "y":
                print("❌ Aborted")
                return 1
        
        if not check_git_remote():
            print("⚠️  Warning: Git remote 'origin' not found")
            if not args.skip_release:
                response = input("Continue without GitHub release? [y/N]: ")
                if response.lower() != "y":
                    print("❌ Aborted")
                    return 1
                args.skip_release = True
        
        # Update version in all files (including Flatpak manifest)
        print("\n📝 Updating version in files...")
        update_all_versions(old_version, new_version, project_root)
        
        # Build project
        if not args.skip_build:
            print("\n🔨 Building project...")
            
            # Check if meson is available
            returncode, _, _ = run_command(["meson", "--version"], check=False)
            if returncode != 0:
                print("⚠️  meson not found. Skipping build step.")
                print("   Install it with:")
                print("     Windows: pip install meson")
                print("     Linux:   sudo dnf install meson  # Fedora")
                print("     Linux:   sudo apt install meson  # Ubuntu")
                print("   Or use --skip-build to skip this step.")
            else:
                # Check if ninja is available
                returncode, _, _ = run_command(["ninja", "--version"], check=False)
                if returncode != 0:
                    print("⚠️  ninja not found. Skipping build step.")
                    print("   Install it with:")
                    print("     Windows: pip install ninja")
                    print("     Linux:   sudo dnf install ninja-build  # Fedora")
                    print("     Linux:   sudo apt install ninja-build  # Ubuntu")
                    print("   Or use --skip-build to skip this step.")
                else:
                    # Check if build directory exists
                    build_dir = Path("build")
                    if build_dir.exists():
                        print("  Cleaning previous build...")
                        returncode, _, _ = run_command(["rm", "-rf", "build"], check=False)
                        if returncode != 0:
                            # Try on Windows
                            import shutil
                            if build_dir.exists():
                                shutil.rmtree(build_dir)
                    
                    # Setup build
                    print("  Running meson setup...")
                    returncode, stdout, stderr = run_command(
                        ["meson", "setup", "build"],
                        check=False,
                    )
                    if returncode != 0:
                        print(f"⚠️  Build setup failed: {stderr}")
                        print("   You can build manually later or use --skip-build")
                    else:
                        # Build
                        print("  Running ninja...")
                        returncode, stdout, stderr = run_command(
                            ["ninja", "-C", "build"],
                            check=False,
                        )
                        if returncode != 0:
                            print(f"⚠️  Build failed: {stderr}")
                            print("   You can build manually later or use --skip-build")
                        else:
                            print("✓ Build successful")
        else:
            print("\n⏭️  Skipping build")
        
        # Build Flatpak package
        build_flatpak = args.flatpak or (not args.skip_flatpak and not args.skip_build)
        flatpak_bundle_path: Path | None = None
        
        if build_flatpak:
            print("\n📦 Building Flatpak package...")
            
            # Check if flatpak-builder is available
            returncode, _, _ = run_command(["flatpak-builder", "--version"], check=False)
            if returncode != 0:
                print("⚠️  flatpak-builder not found. Skipping Flatpak build.")
                print("   Install it with:")
                print("     Windows: Not available (Flatpak requires Linux)")
                print("     Linux:   sudo dnf install flatpak-builder  # Fedora")
                print("     Linux:   sudo apt install flatpak-builder  # Ubuntu")
                print("   Note: Flatpak builds are only supported on Linux.")
            else:
                # Clean previous Flatpak builds
                flatpak_build_dir = project_root / "flatpak-build"
                if flatpak_build_dir.exists():
                    print("  Cleaning previous Flatpak build...")
                    import shutil
                    shutil.rmtree(flatpak_build_dir)
                
                flatpak_cache_dir = project_root / ".flatpak-builder"
                if flatpak_cache_dir.exists():
                    print("  Cleaning Flatpak cache...")
                    import shutil
                    shutil.rmtree(flatpak_cache_dir)
                
                # Build Flatpak
                print("  Running flatpak-builder...")
                flatpak_manifest = project_root / "org.avnixm.Cryptea.yaml"
                if not flatpak_manifest.exists():
                    print("⚠️  Flatpak manifest not found. Skipping Flatpak build.")
                else:
                    returncode, stdout, stderr = run_command(
                        [
                            "flatpak-builder",
                            "--force-clean",
                            "--install",
                            "--user",
                            str(flatpak_build_dir),
                            str(flatpak_manifest),
                        ],
                        check=False,
                    )
                    if returncode != 0:
                        print(f"⚠️  Flatpak build failed: {stderr}")
                        print("   You can build it manually later with:")
                        print(f"   flatpak-builder --force-clean --install --user flatpak-build org.avnixm.Cryptea.yaml")
                    else:
                        print("✓ Flatpak build successful")
                        
                        # Create Flatpak bundle
                        bundle_name = f"cryptea-{new_version}.flatpak"
                        print(f"  Creating Flatpak bundle: {bundle_name}...")
                        
                        # Get Flatpak repo path
                        repo_path = Path.home() / ".local/share/flatpak/repo"
                        if not repo_path.exists():
                            repo_path = Path("/var/lib/flatpak/repo")
                        
                        returncode, stdout, stderr = run_command(
                            [
                                "flatpak",
                                "build-bundle",
                                str(repo_path),
                                bundle_name,
                                "org.avnixm.Cryptea",
                            ],
                            check=False,
                        )
                        if returncode == 0:
                            bundle_path = project_root / bundle_name
                            if bundle_path.exists():
                                flatpak_bundle_path = bundle_path
                                print(f"✓ Flatpak bundle created: {bundle_name}")
                                print(f"  Size: {bundle_path.stat().st_size / (1024 * 1024):.1f} MB")
                        else:
                            print(f"⚠️  Bundle creation failed: {stderr}")
                            print("   You can create it manually with:")
                            print(f"   flatpak build-bundle ~/.local/share/flatpak/repo {bundle_name} org.avnixm.Cryptea")
        else:
            print("\n⏭️  Skipping Flatpak build")
        
        # Check if Flatpak bundle already exists from previous build (even if we skipped building)
        if flatpak_bundle_path is None:
            bundle_name = f"cryptea-{new_version}.flatpak"
            existing_bundle = project_root / bundle_name
            if existing_bundle.exists():
                flatpak_bundle_path = existing_bundle
                print(f"ℹ️  Found existing Flatpak bundle: {bundle_name}")
        
        # Create git commit and tag
        tag = f"v{new_version}"
        
        if not args.skip_tag:
            print(f"\n🏷️  Creating git tag: {tag}")
            
            # Check if tag already exists
            returncode, _, _ = run_command(["git", "show-ref", "--tags", "--quiet", "--", tag], check=False)
            if returncode == 0:
                print(f"⚠️  Tag {tag} already exists")
                response = input("Continue? [y/N]: ")
                if response.lower() != "y":
                    print("❌ Aborted")
                    return 1
            else:
                # Stage version changes
                print("  Staging version changes...")
                files_to_stage = [
                    "pyproject.toml",
                    "meson.build",
                    "src/ctf_helper/config.py",
                    "src/ctf_helper/config.py.in",
                    "org.avnixm.Cryptea.yaml",
                ]
                
                for file in files_to_stage:
                    filepath = project_root / file
                    if filepath.exists():
                        run_command(["git", "add", str(filepath)], check=False)
                
                # Commit
                print(f"  Creating commit: Release {new_version}")
                returncode, _, stderr = run_command(
                    ["git", "commit", "-m", f"Release {new_version}"],
                    check=False,
                )
                if returncode != 0:
                    if "nothing to commit" in stderr:
                        print("  (No changes to commit)")
                    else:
                        print(f"⚠️  Commit failed: {stderr}")
                
                # Create tag
                returncode, _, stderr = run_command(
                    ["git", "tag", "-a", tag, "-m", f"Release {new_version}"],
                    check=False,
                )
                if returncode != 0:
                    print(f"❌ Tag creation failed: {stderr}")
                    return 1
                
                print(f"✓ Tag {tag} created")
        else:
            print("\n⏭️  Skipping git tag")
        
        # Create GitHub release
        if not args.skip_release:
            print(f"\n📦 Creating GitHub release: {tag}")
            
            repo = get_github_repo()
            if not repo:
                print("❌ Could not determine GitHub repository")
                return 1
            
            print(f"  Repository: {repo}")
            
            # Generate release notes
            release_notes = generate_release_notes(new_version, old_version)
            
            # Collect assets to upload
            assets_to_upload = []
            if flatpak_bundle_path and flatpak_bundle_path.exists():
                assets_to_upload.append(flatpak_bundle_path)
            
            # Create release with assets
            success = create_github_release(
                repo=repo,
                tag=tag,
                version=new_version,
                release_notes=release_notes,
                token=args.token,
                assets=assets_to_upload,
            )
            
            if not success:
                print("⚠️  GitHub release creation failed, but tag was created")
                print("   You can create the release manually at:")
                print(f"   https://github.com/{repo}/releases/new?tag={tag}")
        else:
            print("\n⏭️  Skipping GitHub release")
        
        print("\n" + "=" * 50)
        print(f"✅ Release {new_version} completed!")
        print(f"\nNext steps:")
        print(f"  1. Review the changes: git show {tag}")
        if not args.skip_release:
            print(f"  2. Push tag: git push origin {tag}")
            print(f"  3. Push commits: git push origin main")
        else:
            print(f"  2. Push tag: git push origin {tag}")
            print(f"  3. Push commits: git push")
        
    finally:
        # Restore original working directory
        os.chdir(original_cwd)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
