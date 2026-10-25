\# Evaluation Results



The review system was evaluated using 7 real GitHub Pull Requests with intentionally introduced security and code-quality issues.



| Pull Request | Target issue | Detected | Detection source |

|---|---|---|---|

| #8 | Shell command execution with `shell=True` | Yes | Bandit |

| #9 | Hardcoded credential | Yes | Rule-based |

| #10 | Unsafe use of `eval()` | Yes | Rule-based + Bandit |

| #11 | Dynamic SQL / SQL injection risk | Yes | Rule-based + Bandit |

| #12 | Debug `print()` statement | Yes | Rule-based |

| #13 | Broad exception handling | Yes | Rule-based + Ruff |

| #14 | Insecure HTTP connection | Yes | Rule-based |



\## Result



\*\*7/7 target issues detected.\*\*



This was a controlled evaluation using intentionally introduced issues in real GitHub Pull Requests. It is not a benchmark dataset and does not measure precision, recall, or false-positive rate.



The evaluation records whether the intended issue in each Pull Request was detected; the review pipeline may have also reported additional findings.

