\# AI Code Review Platform



An automated code review platform that analyzes GitHub Pull Requests and posts review findings back to the Pull Request.



\## Overview



This project connects GitHub Pull Requests to an automated code review pipeline.



When a Pull Request is created or updated:



1\. GitHub sends a webhook event.

2\. The FastAPI backend receives the event.

3\. The changed Python code is analyzed.

4\. Multiple review tools identify potential issues.

5\. The results are combined into a review report.

6\. The review can be posted back to the GitHub Pull Request.



\## Features



\- GitHub Pull Request webhook integration

\- Automated Python code analysis

\- Rule-based security and code-quality checks

\- Ruff static analysis

\- Bandit security analysis

\- Optional OpenAI-powered code review

\- Automated review reports

\- GitHub Pull Request integration

\- FastAPI backend

\- Web-based review interface



\## Review Checks



The platform currently detects issues such as:



\- Unsafe use of `eval()`

\- Debug `print()` statements

\- Hardcoded credentials

\- Dynamic SQL

\- Shell command execution

\- Insecure HTTP connections

\- Broad exception handling

\- File-writing operations

\- Debugger statements

\- TODO items



The platform also uses:



\- \*\*Ruff\*\* for Python linting

\- \*\*Bandit\*\* for Python security analysis

\- \*\*OpenAI\*\* for optional AI-assisted review



\## Architecture



```text

GitHub Pull Request

&#x20;       |

&#x20;       v

GitHub Webhook

&#x20;       |

&#x20;       v

FastAPI Backend

&#x20;       |

&#x20;       +-------------------+

&#x20;       |                   |

&#x20;       v                   v

&#x20;Rule-based Review     Static Analysis

&#x20;       |              Ruff + Bandit

&#x20;       |                   |

&#x20;       +---------+---------+

&#x20;                 |

&#x20;                 v

&#x20;         Optional AI Review

&#x20;             OpenAI

&#x20;                 |

&#x20;                 v

&#x20;         Combined Findings

&#x20;                 |

&#x20;                 v

&#x20;      GitHub Pull Request


## Evaluation

The review system was evaluated using 7 real GitHub Pull Requests with intentionally introduced security and code-quality issues.

The evaluation measured whether the intended issue in each Pull Request was detected by the review pipeline.

| Pull Request | Target issue | Result |
|---|---|---|
| #8 | Shell command execution with `shell=True` | Detected |
| #9 | Hardcoded credential | Detected |
| #10 | Unsafe use of `eval()` | Detected |
| #11 | Dynamic SQL / SQL injection risk | Detected |
| #12 | Debug `print()` statement | Detected |
| #13 | Broad exception handling | Detected |
| #14 | Insecure HTTP connection | Detected |

**Result: 7/7 target issues detected.**

This was a controlled evaluation using intentionally introduced issues. It is not a benchmark dataset and does not measure precision, recall, or false-positive rate.

## Non-Python Review Test
