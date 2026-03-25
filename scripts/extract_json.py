#!/usr/bin/env python3
"""
Claude -p 출력에서 JSON 블록만 안전하게 추출.
Claude가 JSON 앞뒤에 설명 텍스트를 붙여도 정상 동작.

사용법:
  claude -p "..." | python3 extract_json.py > output.json
  echo '{"ok":true}' | python3 extract_json.py > output.json
"""
import sys, json, re

raw = sys.stdin.read().strip()

# 1) 코드 펜스 안의 JSON 우선 시도 (```json ... ```)
fence_match = re.search(r'```(?:json)?\s*\n?([\s\S]*?)```', raw)
if fence_match:
    raw_candidate = fence_match.group(1).strip()
else:
    raw_candidate = raw

# 2) 가장 바깥쪽 { ... } 또는 [ ... ] 추출
def find_json_block(text):
    for start_char, end_char in [('{', '}'), ('[', ']')]:
        start = text.find(start_char)
        if start == -1:
            continue
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            c = text[i]
            if escape:
                escape = False
                continue
            if c == '\\' and in_string:
                escape = True
                continue
            if c == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == start_char:
                depth += 1
            elif c == end_char:
                depth -= 1
                if depth == 0:
                    return text[start:i+1]
    return None

candidate = find_json_block(raw_candidate)

if candidate:
    try:
        data = json.loads(candidate)
        json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write('\n')
        sys.exit(0)
    except json.JSONDecodeError:
        pass

# 3) 전체 텍스트에서 재시도
if fence_match:
    candidate = find_json_block(raw)
    if candidate:
        try:
            data = json.loads(candidate)
            json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
            sys.stdout.write('\n')
            sys.exit(0)
        except json.JSONDecodeError:
            pass

# 4) 실패 시 에러 JSON 출력
json.dump({
    "error": "json_extraction_failed",
    "raw_length": len(raw),
    "raw_preview": raw[:500]
}, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write('\n')
sys.exit(1)
