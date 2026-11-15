#!/bin/bash
# Writes the GitHub release notes for a tag as Markdown.
#
# The notes cover the feat, fix and perf commits since the previous release
# tag. Claude picks up to seven highlights and writes them for people who use
# the app. Every commit is listed under "Full changelog". Without
# ANTHROPIC_API_KEY, or when the answer fails validation, the notes keep the
# header and the changelog and skip the highlights, so a release never depends
# on the model.
#
# usage: Scripts/release-notes.sh <tag> <output-file>
# env:   ANTHROPIC_API_KEY (from .env locally)
set -euo pipefail

tag=${1:?usage: $0 <tag> <output-file>}
output=${2:?usage: $0 <tag> <output-file>}

root=$(cd "$(dirname "$0")/.." && pwd)
# .env can be a named pipe (a 1Password Environment), which the source builtin
# of macOS bash reads as empty.
if [ -e "$root/.env" ]; then
	set -a
	eval "$(cat "$root/.env")"
	set +a
fi
repo=MacDNS-app/macdns

MODEL=claude-opus-5-5

INSTRUCTIONS='Write up to 7 bullet points for the MacDNS release notes. MacDNS is a macOS menu-bar app that sends every DNS lookup of the Mac over encrypted DNS and blocks ads, trackers and malware. The readers use the app. They do not read code.

Give a feature a bullet only when it lets users do something they could not do before, removes a real limitation they hit in normal use, or cuts meaningful steps or wait time from a common task. Judge the outcome, regardless of the commit prefix. A new setting, a large diff, or support for one more edge case is not enough.

Lead with new capabilities. Give a bug fix its own bullet only when the source shows protection turning off, lookups failing, lost settings or history, or a core task users could not complete. Leave isolated failures, cosmetic polish, and routine fixes in the count. Skip internal work, logging, docs, tests, build and repository scripts, licensing, and dependency bumps. Group commits only when they deliver the same user outcome. Seven is a ceiling. Stop when the qualifying changes run out, even if that leaves zero bullets.

Each bullet has a short feature name and one sentence of at most 20 words. Say what the user can do or what now works. Use names people see in the app: the menu bar, Settings and its pages (Overview, Blocklists, Allowlist, Blocked, Local Records, Forward Zones, Queries, License & Updates, Advanced). Leave out internal names such as Agent, DNS Proxy, Content Filter, resolver, XPC, LMDB or Keygen. Say "background service" or "network extension" when the user needs to know which part changed. Describe the shipped behavior at the end of the range. No title, headings, introduction, hype, commit hashes, semicolons or em dashes.

Return JSON with a "highlights" array. For each highlight, give "label" (plain text, no final period), "detail" (one sentence), and "commits" (the bracketed input numbers of all commits it covers). The release script adds the formatting and the count of the remaining changes.'

SCHEMA='{
  "type": "object",
  "properties": {
    "highlights": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "label": {"type": "string"},
          "detail": {"type": "string"},
          "commits": {"type": "array", "items": {"type": "integer"}}
        },
        "required": ["label", "detail", "commits"],
        "additionalProperties": false
      }
    }
  },
  "required": ["highlights"],
  "additionalProperties": false
}'

warn() { echo "::warning::release notes: $*" >&2; }

previous=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' "$tag^" 2>/dev/null || true)
range=${previous:+$previous..}$tag

# Commits that change the shipped app, oldest first. The uninstall scope is a
# repository script and never reaches the DMG.
commits=$(git log --no-merges --reverse --format='%H%x1f%s%x1f%b%x1e' "$range" | jq -Rs '
	split("\u001e")
	| map(ltrimstr("\n") | select(length > 0) | split("\u001f")
		| {sha: .[0], subject: .[1], body: ((.[2] // "") | rtrimstr("\n"))})
	| map(select(.subject | test("^(feat|fix|perf)(\\((?!uninstall\\))[^)]*\\))?!?: ")))')
count=$(jq length <<<"$commits")
if [ "$count" -eq 0 ]; then
	echo "No feat, fix or perf commits in $range" >&2
	exit 1
fi

# Asks Claude for highlights and prints the summary Markdown, or nothing.
summarize() {
	if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
		warn "ANTHROPIC_API_KEY is not set, skipping highlights"
		return 0
	fi

	local input request response
	input=$(jq -r 'to_entries[] | "[\(.key + 1)] \(.value.subject)" + (if .value.body == "" then "" else "\n" + (.value.body | split("\n") | map("    " + .) | join("\n")) end)' <<<"$commits")
	request=$(jq -n --arg model "$MODEL" --arg system "$INSTRUCTIONS" --arg input "$input" --argjson schema "$SCHEMA" '{
		model: $model,
		max_tokens: 16000,
		fallbacks: "default",
		output_config: {effort: "high", format: {type: "json_schema", schema: $schema}},
		system: $system,
		messages: [{role: "user", content: ("Choose highlights as JSON from these commits:\n" + $input)}]
	}')
	if ! response=$(curl --silent --show-error --fail-with-body --max-time 600 --retry 2 \
		https://api.anthropic.com/v1/messages \
		-H "content-type: application/json" \
		-H "x-api-key: $ANTHROPIC_API_KEY" \
		-H "anthropic-version: 2026-10-21" \
		-H "anthropic-beta: server-side-fallback-2026-07-01" \
		--data-binary @- <<<"$request"); then
		warn "the Anthropic API call failed: $(jq -r '.error.message? // .' <<<"$response" 2>/dev/null | head -c 500)"
		return 0
	fi

	local stop
	stop=$(jq -r '.stop_reason' <<<"$response")
	if [ "$stop" != "end_turn" ]; then
		warn "the model stopped with $stop"
		return 0
	fi

	# Rejects the answer when it cites a commit that is not in the input or
	# names more than seven highlights, instead of repairing it.
	local summary
	if ! summary=$(jq -r '[.content[] | select(.type == "text") | .text] | join("")' <<<"$response" |
		jq -er --argjson commits "$commits" '
			.highlights as $h
			| ($commits | length) as $n
			| if ($h | length) > 7 then error("more than 7 highlights")
			  elif any($h[]; (.commits | length) == 0 or any(.commits[]; . < 1 or . > $n))
			  then error("a highlight cites an unknown commit")
			  else . end
			| ([$h[].commits[]] | unique) as $covered
			| [$commits | to_entries[]
				| select((.key + 1) as $i | $covered | index($i) | not)
				| .value.subject | capture("^(?<kind>feat|fix|perf)").kind] as $rest
			| [["feat", "improvement", "improvements"],
			   ["perf", "performance improvement", "performance improvements"],
			   ["fix", "bug fix", "bug fixes"]
				| .[0] as $kind | ([$rest[] | select(. == $kind)] | length) as $n
				| select($n > 0)
				| "\($n) \(if $n == 1 then .[1] else .[2] end)"] as $parts
			| (if ($parts | length) < 2 then $parts | join("")
			   else ($parts[:-1] | join(", ")) + " and " + $parts[-1] end) as $remaining
			| [$h[] | "- **\(.label | rtrimstr(".")).** \(.detail)"] as $bullets
			| if $remaining == "" then $bullets | join("\n")
			  elif ($bullets | length) == 0 then "**\($remaining).**"
			  else ($bullets | join("\n")) + "\n\n### Plus \($remaining)." end'); then
		warn "the model answer failed validation"
		return 0
	fi
	printf '%s\n' "$summary"
}

summary=$(summarize) || summary=""
changes=$([ "$count" -eq 1 ] && echo "1 change" || echo "$count changes")
changelog=$(jq -r --arg repo "$repo" '.[] | "- \(.subject) ([\(.sha[0:7])](https://github.com/\($repo)/commit/\(.sha)))"' <<<"$commits")

tmp=$(mktemp "$output.XXXXXX")
{
	printf '**%s** · %s\n\n' "$tag" "$changes"
	[ -n "$summary" ] && printf '%s\n\n' "$summary"
	printf '<details>\n<summary>Full changelog</summary>\n\n%s\n\n</details>\n' "$changelog"
} >"$tmp"
mv "$tmp" "$output"
