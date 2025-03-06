import os
import json
import shutil


def process_first_repo(n=1):
    # Read all lines
    with open("repos_dir.txt", "r") as file:
        lines = file.readlines()
        if not lines:
            return False

        # Process n repos or all repos if n > len(lines)
        repos_to_process = min(n, len(lines))

        for i in range(repos_to_process):
            line = lines[i].strip()
            language, repo_url = line.split(" ")

            # Create directory if it doesn't exist
            owner = repo_url.split("/")[-2]
            repo_name = repo_url.split("/")[-1]
            config_dir = os.path.join(language, owner, repo_name)
            os.makedirs(config_dir, exist_ok=True)

            # Create config.json
            config = {
                "mode": "dir",
                "repo_url": repo_url,
                "analyzer_args": f"-p {language} --vulnerabilities-iterations 8 --exclude '**/.github/**' --vulnerabilities-github-repo-url https://github.com/{repo_url} --recursion-limit 100",
                "agent_provider": "google",
                "agent_model": "gemini-2.0-flash-thinking-exp",
                "agent_temperature": 0.7,
                "agent_prompt_types": ["vulnerabilities-workflow-2"],
            }

            # Write config.json
            config_path = os.path.join(config_dir, "config.json")
            with open(config_path, "w") as f:
                json.dump(config, f, indent=4)

        # Remove processed lines and write back remaining lines
        with open("repos_dir.txt", "w") as file:
            file.writelines(lines[repos_to_process:])

    return True


if __name__ == "__main__":
    import sys

    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1  # Get n from command line args
    process_first_repo(n)
