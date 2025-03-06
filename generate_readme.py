#!/usr/bin/env python3

import os
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple

# Constants
EXCLUDE_DIRS: Set[str] = {".git", ".github", "__pycache__", ".data", ".scripts", "vulnerabilities-workflow", ".vscode"}
EXCLUDE_FILES: Set[str] = {"README.md", "LICENSE", "generate_readme.py"}
DOC_TYPES: Dict[str, str] = {
    "sec-design.md": "Security Design Review",
    "sec-design-deep-analysis.md": "Security Design Review - Deep Analysis",
    "threat-modeling.md": "Threat Modeling",
    "attack-surface.md": "Attack Surface",
    "attack-tree.md": "Attack Tree",
    "mitigations.md": "Mitigation Strategies",
    "vulnerabilities-workflow-1.md": "Vulnerabilities Workflow",
    "vulnerabilities-workflow-2.md": "Vulnerabilities Workflow 2",
}

INTRODUCTION = """# 🐛 sec-docs-vulns 

### Current Projects
"""


class ProjectData:
    """Class to store and manage project data and generate README files."""

    def __init__(self, base_dir: Path = Path(".")):
        self.base_dir = base_dir
        self.languages: Dict[str, Dict[str, Dict[str, Dict[str, List[str]]]]] = {}

    def get_github_link(self, project_dir: Path) -> str:
        """Read GitHub repository URL from project config file."""
        config_path = project_dir / "config.json"
        if config_path.is_file():
            try:
                with open(config_path, "r") as config_file:
                    config = json.load(config_file)
                    repo_url = config.get("repo_url", "")
                    if repo_url and not repo_url.startswith("https://github.com/"):
                        return f"https://github.com/{repo_url}"
                    return repo_url
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error reading config file {config_path}: {e}")
        return ""

    def get_metadata(self, version_dir: Path) -> Dict[str, Any]:
        """Read and return metadata from output-metadata.json."""
        metadata_path = version_dir / "output-metadata.json"
        if metadata_path.is_file():
            try:
                with open(metadata_path, "r") as metadata_file:
                    return json.load(metadata_file)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error reading metadata file {metadata_path}: {e}")
        return {}

    def process_version(
        self, language: str, owner: str, project: str, version: str, version_dir: Path
    ) -> Tuple[str, str]:
        """Process a version directory and generate README lines."""
        metadata = self.get_metadata(version_dir)
        analysis_date = version[:10]
        model_name = metadata.get("agent_model", "Unknown Model")

        analyzer_args = metadata.get("analyzer_args", "")
        deep_analysis = "✅" if "deep-analysis" in analyzer_args else ""

        agent_temperature = metadata.get("agent_temperature", 0)

        # Extract secondary agent model from analyzer_args if present
        secondary_model = None
        if "--secondary-agent-model" in analyzer_args:
            parts = analyzer_args.split("--secondary-agent-model")
            if len(parts) > 1:
                model_parts = parts[1].strip().split()
                if model_parts:
                    secondary_model = model_parts[0]

        # Extract secondary agent temperature from analyzer_args if present
        secondary_temp = None
        if "--secondary-agent-temperature" in analyzer_args:
            parts = analyzer_args.split("--secondary-agent-temperature")
            if len(parts) > 1:
                temp_parts = parts[1].strip().split()
                if temp_parts:
                    try:
                        secondary_temp = temp_parts[0]
                    except (ValueError, IndexError):
                        pass

        # Combine models and temperatures if secondary exists
        if secondary_model:
            model_name = f"{model_name} / {secondary_model}"

        if secondary_temp:
            agent_temperature = f"{agent_temperature} / {secondary_temp}"

        # Project README doc links (relative to project directory)
        project_doc_links = []
        # Language README doc links (relative to language directory)
        language_doc_links = []

        for doc_file, doc_name in DOC_TYPES.items():
            doc_path = version_dir / doc_file
            if doc_path.exists():
                project_doc_links.append(f"[{doc_name}]({version}/{doc_file})")
                language_doc_links.append(f"[{doc_name}]({owner}/{project}/{version}/{doc_file})")

        project_line = f"| {analysis_date} | {model_name} | {agent_temperature} | {deep_analysis} | {', '.join(project_doc_links)} |"
        language_line = f"| {analysis_date} | {model_name} | {agent_temperature} | {deep_analysis} | {', '.join(language_doc_links)} |"

        return project_line, language_line

    def collect_data(self) -> None:
        """Collect all project data from the directory structure."""
        top_dirs = [d for d in self.base_dir.iterdir() if d.is_dir() and d.name not in EXCLUDE_DIRS]
        for language_dir in top_dirs:
            language = language_dir.name
            self.languages[language] = {}

            owners = [o for o in language_dir.iterdir() if o.is_dir()]
            for owner_dir in owners:
                owner = owner_dir.name
                self.languages[language][owner] = {}

                projects = [p for p in owner_dir.iterdir() if p.is_dir()]
                for project_dir in projects:
                    project = project_dir.name
                    self.languages[language][owner][project] = {"project_lines": [], "language_lines": []}

                    versions = sorted(
                        [v for v in project_dir.iterdir() if v.is_dir()], key=lambda x: x.name, reverse=True
                    )

                    for version_dir in versions:
                        version = version_dir.name
                        project_line, language_line = self.process_version(
                            language, owner, project, version, version_dir
                        )

                        self.languages[language][owner][project]["project_lines"].append(project_line)
                        self.languages[language][owner][project]["language_lines"].append(language_line)

                    # Generate project README
                    self.generate_project_readme(language, owner, project)

            # Generate language README
            self.generate_language_readme(language)

        # Generate main README
        self.generate_main_readme()

    def generate_project_readme(self, language: str, owner: str, project: str) -> None:
        """Generate README file for a specific project."""
        readme_lines = [f"# {project.title()} Analysis"]

        project_dir = self.base_dir / language / owner / project
        github_link = self.get_github_link(project_dir)
        if github_link:
            readme_lines.append(f"\n[GitHub Repository]({github_link})\n")

        readme_lines.append("| Analysis Date | Model | T | Deep Analysis | Documents |")
        readme_lines.append("|---------------|-------|---|:-------------:|-----------|")
        readme_lines.extend(self.languages[language][owner][project]["project_lines"])

        readme_path = project_dir / "README.md"
        with open(readme_path, "w") as f:
            f.write("\n".join(readme_lines))

    def generate_language_readme(self, language: str) -> None:
        """Generate README file for a language directory."""
        readme_lines = [f"# {language.title()} Projects"]
        readme_lines.append("| Project | Analysis Date | Model | T | Deep Analysis | Documentation |")
        readme_lines.append("|---------|---------------|-------|---|:-------------:|---------------|")

        for owner in self.languages[language]:
            for project, data in self.languages[language][owner].items():
                project_dir = self.base_dir / language / owner / project
                github_link = self.get_github_link(project_dir)
                project_name = f"[{owner}/{project}]({owner}/{project}/)"
                if github_link:
                    project_name += f" ([GitHub]({github_link}))"

                for version_line in data["language_lines"]:
                    parts = version_line.split("|")
                    if len(parts) >= 4:
                        date = parts[1].strip()
                        model = parts[2].strip()
                        temperature = parts[3].strip()
                        deep_analysis = parts[4].strip()
                        docs = parts[5].strip()
                        readme_lines.append(
                            f"| {project_name} | {date} | {model} | {temperature} | {deep_analysis} | {docs} |"
                        )

        readme_path = self.base_dir / language / "README.md"
        with open(readme_path, "w") as f:
            f.write("\n".join(readme_lines))

    def generate_main_readme(self) -> None:
        """Generate the main README file for the repository."""
        readme_lines = [INTRODUCTION]

        for language in self.languages:
            readme_lines.append(f"\n### [{language.title()}]({language}/)\n")
            for owner in self.languages[language]:
                for project in self.languages[language][owner]:
                    project_dir = self.base_dir / language / owner / project
                    github_link = self.get_github_link(project_dir)
                    github_part = f"[GitHub]({github_link})" if github_link else ""
                    readme_lines.append(f"- [{owner}/{project}]({language}/{owner}/{project}) ({github_part})")

        readme_path = self.base_dir / "README.md"
        with open(readme_path, "w") as f:
            f.write("\n".join(readme_lines))


def main() -> None:
    """Main function to generate all README files."""
    project_data = ProjectData()
    project_data.collect_data()


if __name__ == "__main__":
    main()
