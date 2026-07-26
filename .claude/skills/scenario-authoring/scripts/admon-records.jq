def empty_record:
  {values: {}, payload: "", started: false, continuable: false, last_key: null};

def canonical_fields:
  .values
  | with_entries(
      .value |= map(select(. != ""))
    )
  | with_entries(select(.value | length > 0))
  | with_entries(
      .value = (
        if (.value | length) == 1 then .value[0]
        else (.value | tojson)
        end
      )
    );

def flush_record:
  if .current.started then
    .records += [{fields: (.current | canonical_fields), payload: .current.payload}]
    | .current = empty_record
  else
    .
  end;

def add_field($key; $value):
  .current.values[$key] = ((.current.values[$key] // []) + [$value])
  | .current.last_key = $key;

def is_admon_timestamp:
  test("^[0-9]{1,2}/[0-9]{1,2}/(?:[0-9]{2}|[0-9]{4})$")
  or test("^[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]+)?(?:[[:space:]]+(?:AM|PM))?$"; "i")
  or test("^[0-9]{1,2}/[0-9]{1,2}/(?:[0-9]{2}|[0-9]{4})[[:space:]]+[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]+)?(?:[[:space:]]+(?:AM|PM))?$"; "i");

reduce inputs as $raw (
  {records: [], current: empty_record, line: 0};
  .line += 1
  | . as $state
  | (
      $raw
      | if ($state.current.started | not) then sub("^\uFEFF+"; "") else . end
    ) as $source
  | ($source | sub("\r$"; "")) as $line
  | ($line | sub("[\t ]+$"; "")) as $structural
  | ($structural | sub("^[\t ]+"; "")) as $unindented
  | if ($line | contains("\r")) then
      error("admon line \(.line): unexpected carriage return")
    elif ($line | test("^[\t ]*$")) then
      if .current.started then
        .current.payload += ($source + "\n")
        | .current.continuable = false
      else
        .
      end
    elif $structural == "---splunk-admon-end-of-event---"
         or ($structural | is_admon_timestamp) then
      flush_record
    elif ($unindented | test("^[^=:\t\r\n][^=:\t\r\n]*:$")) then
      if .current.started then
        .current.payload += ($source + "\n")
        | .current.continuable = false
      else
        error("admon line \(.line): section header before record-start dcName")
      end
    else
      ($line | sub("^[\t ]+"; "")) as $field_line
      | if (($line | test("^\t "))
            and .current.started
            and .current.continuable) then
          .current.payload += ($source + "\n")
          | .current.values[.current.last_key][-1] += $line[2:]
        elif (($line | test("^[\t ]"))
            and .current.started
            and .current.continuable
            and ($line | contains("=") | not)) then
          .current.payload += ($source + "\n")
        elif ($field_line | test("^[A-Za-z0-9_-]+=") | not) then
          error("admon line \(.line): unrecognized line")
        else
          ($field_line | capture("^(?<key>[A-Za-z0-9_-]+)=(?<value>.*)$")) as $field
          | if $field.key == "dcName" and ($line | test("^[\t ]") | not) then
              if $field.value == "" then
                error("admon line \(.line): dcName must not be empty")
              else
                (if .current.started then flush_record else . end)
                | .current.started = true
                | .current.payload += ($source + "\n")
                | add_field($field.key; $field.value)
                | .current.continuable = true
              end
            elif (.current.started | not) then
              error("admon line \(.line): field \($field.key) before record-start dcName")
            else
              .current.payload += ($source + "\n")
              | add_field($field.key; $field.value)
              | .current.continuable = true
            end
        end
    end
)
| flush_record
| if (.records | length) == 0 then
    error("no ActiveDirectory admon records found")
  else
    .records
  end
