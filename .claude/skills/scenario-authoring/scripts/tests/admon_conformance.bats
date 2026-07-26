#!/usr/bin/env bats

load helpers

setup() {
  scenario_authoring_setup
  export CONFORMANCE="$FIXTURES/admon-conformance.json"
}

@test "shared admon conformance: format detection" {
  while IFS= read -r fixture; do
    name="$(jq -r '.name' <<< "$fixture")"
    input="$(jq -r '.input' <<< "$fixture")"
    leading_spaces="$(jq -r '.leading_spaces // 0' <<< "$fixture")"
    key="$(jq -r '.key' <<< "$fixture")"
    expected_extract="$(jq -r '.extract_format' <<< "$fixture")"
    expected_fidelity="$(jq -r '.fidelity_format' <<< "$fixture")"
    file="$BATS_TEST_TMPDIR/input.log"
    printf '%*s%s' "$leading_spaces" "" "$input" > "$file"

    run extract_events --dataset "$file" --key "$key" --mode summary
    [ "$status" -eq 0 ] || { echo "$name: $output"; false; }
    [ "$(jq -r '.format' <<< "$output")" = "$expected_extract" ] || { echo "$name: $output"; false; }

    run "$SCRIPTS_DIR/compare-fidelity.sh" \
      --master "$file" --generated "$file" --load-bearing ""
    [ "$status" -eq 0 ] || { echo "$name: $output"; false; }
  done < <(jq -c '.format_cases[]' "$CONFORMANCE")
}

@test "shared admon conformance: first-record fidelity" {
  while IFS= read -r fixture; do
    name="$(jq -r '.name' <<< "$fixture")"
    input="$(jq -r '.input' <<< "$fixture")"
    generated="$(jq -r '.generated' <<< "$fixture")"
    load_bearing="$(jq -r '.load_bearing' <<< "$fixture")"
    expected_count="$(jq -r '.master_field_count' <<< "$fixture")"
    master="$BATS_TEST_TMPDIR/master.log"
    rendered="$BATS_TEST_TMPDIR/generated.log"
    printf '%s' "$input" > "$master"
    printf '%s' "$generated" > "$rendered"

    run "$SCRIPTS_DIR/compare-fidelity.sh" \
      --master "$master" --generated "$rendered" --load-bearing "$load_bearing"
    [ "$status" -eq 0 ] || { echo "$name: $output"; false; }
    jq -e --argjson count "$expected_count" \
      '.verdict == "pass" and .master_field_count == $count' <<< "$output" \
      || { echo "$name: $output"; false; }
  done < <(jq -c '.first_record_cases[]' "$CONFORMANCE")
}

@test "shared admon conformance: wrapped records remain extractable" {
  while IFS= read -r fixture; do
    name="$(jq -r '.name' <<< "$fixture")"
    input="$(jq -r '.input' <<< "$fixture")"
    key="$(jq -r '.key' <<< "$fixture")"
    value="$(jq -r '.value' <<< "$fixture")"
    expected_total="$(jq -r '.total' <<< "$fixture")"
    file="$BATS_TEST_TMPDIR/input.log"
    sample="$BATS_TEST_TMPDIR/sample.log"
    printf '%s' "$input" > "$file"

    run extract_events --dataset "$file" --key "$key" --mode summary
    [ "$status" -eq 0 ] || { echo "$name: $output"; false; }
    jq -e --arg value "$value" --argjson total "$expected_total" \
      '.format == "admon" and .total == $total
       and .groups == [{key: $value, count: 1}]' <<< "$output" \
      || { echo "$name: $output"; false; }

    run extract_events --dataset "$file" --key "$key" --mode extract \
      --value "$value" --out "$sample"
    [ "$status" -eq 0 ] || { echo "$name: $output"; false; }
    [ "$(cat "$sample")" = "${input%$'\n'}" ] || { echo "$name: extracted sample differs"; false; }
  done < <(jq -c '.extraction_cases[]' "$CONFORMANCE")
}

@test "shared admon conformance: invalid records" {
  while IFS= read -r fixture; do
    name="$(jq -r '.name' <<< "$fixture")"
    input="$(jq -r '.input' <<< "$fixture")"
    contains="$(jq -r '.contains' <<< "$fixture")"
    file="$BATS_TEST_TMPDIR/input.log"
    printf '%s' "$input" > "$file"

    run "$SCRIPTS_DIR/compare-fidelity.sh" \
      --master "$file" --generated "$file" --format admon --load-bearing ""
    [ "$status" -eq 1 ] || { echo "$name: $output"; false; }
    [[ "$output" == *"$contains"* ]] || { echo "$name: $output"; false; }
  done < <(jq -c '.invalid_record_cases[]' "$CONFORMANCE")
}

@test "shared admon conformance: escaped load-bearing values" {
  while IFS= read -r fixture; do
    name="$(jq -r '.name' <<< "$fixture")"
    input="$(jq -r '.input' <<< "$fixture")"
    token="$(jq -r '.token' <<< "$fixture")"
    expected_globs="$(jq -c '.globs' <<< "$fixture")"
    file="$BATS_TEST_TMPDIR/input.log"
    printf '%s' "$input" > "$file"

    run "$SCRIPTS_DIR/compare-fidelity.sh" \
      --master "$file" --generated "$file" --format admon --load-bearing "$token"
    [ "$status" -eq 0 ] || { echo "$name: $output"; false; }
    jq -e --argjson globs "$expected_globs" \
      '.verdict == "pass" and .load_bearing_aggregate[0].globs == $globs' <<< "$output" \
      || { echo "$name: $output"; false; }
  done < <(jq -c '.load_bearing_cases[]' "$CONFORMANCE")
}

@test "shared admon conformance: actionable mismatch diagnostics" {
  while IFS= read -r fixture; do
    name="$(jq -r '.name' <<< "$fixture")"
    master_input="$(jq -r '.master' <<< "$fixture")"
    generated_input="$(jq -r '.generated' <<< "$fixture")"
    contains="$(jq -r '.contains' <<< "$fixture")"
    excludes="$(jq -r '.excludes' <<< "$fixture")"
    master="$BATS_TEST_TMPDIR/master.log"
    generated="$BATS_TEST_TMPDIR/generated.xml"
    printf '%s' "$master_input" > "$master"
    printf '%s' "$generated_input" > "$generated"

    run "$SCRIPTS_DIR/compare-fidelity.sh" \
      --master "$master" --generated "$generated" --load-bearing ""
    [ "$status" -eq 2 ] || { echo "$name: $output"; false; }
    [[ "$output" == *"$contains"* ]] || { echo "$name: $output"; false; }
    [[ "$output" != *"$excludes"* ]] || { echo "$name: $output"; false; }

    run "$SCRIPTS_DIR/diff-against-master.sh" \
      --master "$master" --generated "$generated"
    [ "$status" -eq 2 ] || { echo "$name: $output"; false; }
    [[ "$output" == *"$contains"* ]] || { echo "$name: $output"; false; }
    [[ "$output" != *"$excludes"* ]] || { echo "$name: $output"; false; }
  done < <(jq -c '.diagnostic_cases[]' "$CONFORMANCE")
}
