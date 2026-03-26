#!/usr/bin/env python3
"""
Google Bug Hunters OSS VRP 대상 레포지토리 목록을 가져와서
targets_oss.json 형식으로 변환하는 스크립트.

소스: https://github.com/google/bughunters/blob/main/oss-repository-tier/external_repositories.txtpb
"""
import json
import os
import re
import sys
import urllib.request

TXTPB_URL = "https://raw.githubusercontent.com/google/bughunters/main/oss-repository-tier/external_repositories.txtpb"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
TARGETS_FILE = os.path.join(BASE_DIR, "data", "targets_oss.json")


def fetch_txtpb(url: str) -> str:
    """txtpb 파일 다운로드"""
    req = urllib.request.Request(url, headers={"User-Agent": "autoBounty/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def parse_txtpb(content):
    """
    text protobuf 형식에서 repository 항목 파싱.
    
    repository {
      url: "https://github.com/angular/angular"
      tier: TIER_OT0
      product_vuln_scope: SCOPE_OSS_VRP
    }
    """
    repos = []
    blocks = re.findall(
        r'repository\s*\{(.*?)\}',
        content,
        re.DOTALL
    )

    for block in blocks:
        url_match = re.search(r'url:\s*"([^"]+)"', block)
        tier_match = re.search(r'tier:\s*(\S+)', block)
        scope_match = re.search(r'product_vuln_scope:\s*(\S+)', block)

        if not url_match:
            continue

        url = url_match.group(1)
        tier = tier_match.group(1) if tier_match else "UNKNOWN"
        scope = scope_match.group(1) if scope_match else "UNKNOWN"

        # GitHub URL에서 이름 추출
        # https://github.com/org/repo → org_repo
        gh_match = re.match(r'https://github\.com/([^/]+)/([^/]+)/?$', url)
        if gh_match:
            org, repo = gh_match.group(1), gh_match.group(2)
            name = f"{org}_{repo}"
        else:
            # non-GitHub (e.g., fuchsia.googlesource.com)
            name = url.rstrip('/').split('/')[-1]

        # 주요 언어 추정
        language = guess_language(name, url)

        repos.append({
            "name": name,
            "repo_url": url,
            "tier": tier,
            "scope": scope,
            "language": language
        })

    return repos


def guess_language(name: str, url: str) -> str:
    """레포 이름으로 주요 언어 추정"""
    lang_map = {
        "angular": "typescript",
        "flutter": "dart",
        "bazel": "java",
        "golang": "go",
        "tink-go": "go",
        "tink-java": "java",
        "tink-cc": "cpp",
        "tensorflow": "python",
        "jax": "python",
        "dart": "dart",
        "protobuf": "cpp",
        "gson": "java",
        "guava": "java",
        "gvisor": "go",
        "puppeteer": "javascript",
        "polymer": "javascript",
        "shaka-player": "javascript",
        "closure-compiler": "java",
        "re2": "cpp",
        "flatbuffers": "cpp",
        "filament": "cpp",
        "brotli": "cpp",
        "XNNPACK": "cpp",
        "site-kit-wp": "php",
        "libphonenumber": "java",
        "clusterfuzz": "python",
        "osv-scanner": "go",
        "go-github": "go",
        "go-cloud": "go",
        "agones": "go",
        "zerocopy": "rust",
        "adk-python": "python",
        "gemini-cli": "typescript",
        "cdap": "java",
    }

    name_lower = name.lower()
    for key, lang in lang_map.items():
        if key.lower() in name_lower:
            return lang

    return "unknown"


def main():
    print(f"[fetch_oss_repos] {TXTPB_URL} 에서 레포 목록 가져오는 중...")

    try:
        content = fetch_txtpb(TXTPB_URL)
    except Exception as e:
        print(f"[fetch_oss_repos] ERROR: 다운로드 실패 — {e}")
        sys.exit(1)

    repos = parse_txtpb(content)
    print(f"[fetch_oss_repos] {len(repos)}개 레포지토리 파싱 완료")

    # 티어별 통계
    tier_counts = {}
    for r in repos:
        tier_counts[r["tier"]] = tier_counts.get(r["tier"], 0) + 1
    for tier, count in sorted(tier_counts.items()):
        print(f"  {tier}: {count}개")

    # GitHub 레포만 필터 (fuchsia.googlesource.com 등은 clone 방식이 다름)
    github_repos = [r for r in repos if "github.com" in r["repo_url"]]
    non_github = [r for r in repos if "github.com" not in r["repo_url"]]

    if non_github:
        print(f"[fetch_oss_repos] 비-GitHub 레포 {len(non_github)}개 제외:")
        for r in non_github:
            print(f"  - {r['repo_url']}")

    # 저장
    os.makedirs(os.path.dirname(TARGETS_FILE), exist_ok=True)
    with open(TARGETS_FILE, "w") as f:
        json.dump(github_repos, f, indent=2, ensure_ascii=False)

    print(f"[fetch_oss_repos] {len(github_repos)}개 GitHub 레포 → {TARGETS_FILE} 저장 완료")
    return github_repos


if __name__ == "__main__":
    main()
