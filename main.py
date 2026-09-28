import os
import hmac
import hashlib
import json

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from github import Github

load_dotenv()

app = FastAPI()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
@app.get("/")
def read_root():
    return FileResponse("index.html")


def get_github_pr(repository: str, pull_request_number: int):

    if not GITHUB_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="GITHUB_TOKEN is not configured"
        )

    try:
        github = Github(GITHUB_TOKEN)

        repo = github.get_repo(repository)
        pr = repo.get_pull(pull_request_number)

        files = []

        for file in pr.get_files():
            files.append({
                "filename": file.filename,
                "status": file.status,
                "additions": file.additions,
                "deletions": file.deletions,
                "changes": file.changes,
                "patch": file.patch or ""
            })

        return {
            "repository": repository,
            "pull_request_number": pull_request_number,
            "title": pr.title,
            "author": pr.user.login,
            "state": pr.state,
            "files_changed": pr.changed_files,
            "lines_added": pr.additions,
            "lines_removed": pr.deletions,
            "changed_files": files
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"GitHub error: {str(e)}"
        )


@app.get("/analyze/pr")
def analyze_pr(repository: str, pull_request_number: int):

    return get_github_pr(
        repository,
        pull_request_number
    )


@app.get("/review/pr")
def review_pr(repository: str, pull_request_number: int):

    pr_data = get_github_pr(
        repository,
        pull_request_number
    )

    issues = []

    for file in pr_data["changed_files"]:

        filename = file["filename"]
        patch = file["patch"]
        lower_patch = patch.lower()

        # 1. eval()
        if "eval(" in patch:
            issues.append({
                "severity": "high",
                "file": filename,
                "problem": "Use of eval() detected.",
                "why_it_matters": "eval() can execute dynamically supplied code and may create security vulnerabilities.",
                "suggested_fix": "Avoid eval() and use safer alternatives."
            })

        # 2. Hardcoded credentials
        if (
            "api_key =" in lower_patch
            or "password =" in lower_patch
            or "secret_key =" in lower_patch
            or "token =" in lower_patch
        ):
            issues.append({
                "severity": "high",
                "file": filename,
                "problem": "Possible hardcoded credential detected.",
                "why_it_matters": "Credentials committed to source code can be exposed through version control.",
                "suggested_fix": "Use environment variables or a secure secret manager."
            })

        # 3. Debug print statements
        if "print(" in patch:
            issues.append({
                "severity": "low",
                "file": filename,
                "problem": "Debug print statement detected.",
                "why_it_matters": "Debug output may expose information or create noisy production logs.",
                "suggested_fix": "Use proper application logging instead of print()."
            })

        # 4. TODO comments
        if "todo" in lower_patch:
            issues.append({
                "severity": "low",
                "file": filename,
                "problem": "TODO comment detected.",
                "why_it_matters": "The change may contain unfinished work.",
                "suggested_fix": "Review and complete the TODO before merging."
            })

        # 5. SQL query construction
        if (
            "select * from" in lower_patch
            or "insert into" in lower_patch
            or "delete from" in lower_patch
        ):
            if "+" in patch or "f\"" in lower_patch or "format(" in lower_patch:
                issues.append({
                    "severity": "high",
                    "file": filename,
                    "problem": "Possible dynamically constructed SQL query detected.",
                    "why_it_matters": "Building SQL queries from user-controlled values can lead to SQL injection.",
                    "suggested_fix": "Use parameterized queries or prepared statements."
                })

        # 6. Shell command execution
        if (
            "os.system(" in patch
            or "subprocess.call(" in patch
            or "subprocess.popen(" in patch
        ):
            issues.append({
                "severity": "high",
                "file": filename,
                "problem": "Shell command execution detected.",
                "why_it_matters": "Unsanitized input passed to shell commands can create command-injection vulnerabilities.",
                "suggested_fix": "Validate input and prefer safe subprocess APIs without shell execution."
            })

        # 7. HTTP instead of HTTPS
        if "http://" in lower_patch:
            issues.append({
                "severity": "medium",
                "file": filename,
                "problem": "Unencrypted HTTP URL detected.",
                "why_it_matters": "HTTP traffic can be intercepted or modified in transit.",
                "suggested_fix": "Use HTTPS where the service supports it."
            })

        # 8. Broad exception handling
        if "except exception:" in lower_patch:
            issues.append({
                "severity": "low",
                "file": filename,
                "problem": "Broad exception handling detected.",
                "why_it_matters": "Catching every exception can hide unexpected programming errors.",
                "suggested_fix": "Catch specific exceptions and handle them appropriately."
            })

        # 9. Dangerous file operations
        if (
            "open(" in patch
            and ("write" in lower_patch or "'w'" in lower_patch)
        ):
            issues.append({
                "severity": "medium",
                "file": filename,
                "problem": "File write operation detected.",
                "why_it_matters": "Writing files using unvalidated paths can create security or data-integrity problems.",
                "suggested_fix": "Validate file paths and restrict writes to approved directories."
            })

        # 10. Debugger
        if "breakpoint()" in patch or "pdb.set_trace()" in patch:
            issues.append({
                "severity": "medium",
                "file": filename,
                "problem": "Debugger statement detected.",
                "why_it_matters": "Debugger code should generally not be committed to production code.",
                "suggested_fix": "Remove debugger statements before merging."
            })

    if not issues:
        issues.append({
            "severity": "info",
            "file": "N/A",
            "problem": "No obvious issues detected by the local reviewer.",
            "why_it_matters": "The rule-based checks did not find any of the currently supported patterns.",
            "suggested_fix": "Perform a full manual code review before merging."
        })

    return {
        "repository": pr_data["repository"],
        "pull_request_number": pr_data["pull_request_number"],
        "title": pr_data["title"],
        "review_engine": "Local rule-based reviewer",
        "issues_found": len(issues),
        "review": issues
    }
@app.post("/webhook/github")
async def github_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")

    if not WEBHOOK_SECRET:
        raise HTTPException(
            status_code=500,
            detail="WEBHOOK_SECRET is not configured"
        )

    if not signature:
        raise HTTPException(
            status_code=401,
            detail="Missing webhook signature"
        )

    expected_signature = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(
            status_code=401,
            detail="Invalid webhook signature"
        )

    payload = json.loads(body)

    action = payload.get("action")
    pull_request = payload.get("pull_request")
    repository = payload.get("repository")

    if not pull_request or not repository:
        return {
            "status": "ignored",
            "message": "Not a pull request event"
        }

    repo_name = repository.get("full_name")
    pr_number = pull_request.get("number")

    # Only review relevant pull request events
    if action not in ["opened", "reopened", "synchronize"]:
        return {
            "status": "received",
            "message": "Event received but no review was triggered",
            "action": action,
            "repository": repo_name,
            "pull_request_number": pr_number
        }

    # Run our existing local reviewer
    review_result = review_pr(
        repo_name,
        pr_number
    )

    issues = review_result["review"]

    # Build a GitHub comment
    comment = "## 🤖 Automated Code Review\n\n"

    comment += f"**Repository:** `{repo_name}`  \n"
    comment += f"**Pull Request:** #{pr_number}  \n"
    comment += f"**Issues found:** {review_result['issues_found']}\n\n"

    for issue in issues:

        comment += "---\n\n"

        comment += f"### {issue['severity'].upper()}\n\n"

        comment += f"**File:** `{issue['file']}`\n\n"

        comment += f"**Problem:** {issue['problem']}\n\n"

        comment += f"**Why it matters:** {issue['why_it_matters']}\n\n"

        comment += f"**Suggested fix:** {issue['suggested_fix']}\n\n"

    # Connect to GitHub
    if not GITHUB_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="GITHUB_TOKEN is not configured"
        )

    github = Github(GITHUB_TOKEN)

    repo = github.get_repo(repo_name)

    pr = repo.get_pull(pr_number)

    # Post the review as a PR comment
    pr.create_issue_comment(comment)

    return {
        "status": "review_completed_and_commented",
        "repository": repo_name,
        "pull_request_number": pr_number,
        "issues_found": review_result["issues_found"]
    }