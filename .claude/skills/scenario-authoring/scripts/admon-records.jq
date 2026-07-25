def empty_record:
  {fields: {}, seen: {}, started: false};

def flush_record:
  if .current.started then
    .records += [.current.fields]
    | .current = empty_record
  else
    .
  end;

def add_field($key; $value):
  if $value == "" then
    .
  elif .current.seen[$key] then
    error("admon line \(.line): duplicate non-empty field \($key)")
  else
    .current.seen[$key] = true
    | .current.fields[$key] = $value
  end;

def is_admon_timestamp:
  test("^[0-9]{1,2}/[0-9]{1,2}/(?:[0-9]{2}|[0-9]{4})$")
  or test("^[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]+)?[[:space:]]+(?:AM|PM)$"; "i")
  or test("^[0-9]{1,2}/[0-9]{1,2}/(?:[0-9]{2}|[0-9]{4})[[:space:]]+[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]+)?(?:[[:space:]]+(?:AM|PM))?$"; "i");

reduce inputs as $raw (
  {records: [], current: empty_record, line: 0};
  .line += 1
  | . as $state
  | (
      $raw
      | if $state.line == 1 then sub("^\uFEFF"; "") else . end
      | sub("\r$"; "")
    ) as $line
  | if ($line | contains("\r")) then
      error("admon line \(.line): unexpected carriage return")
    elif ($line | test("^[\t ]*$")) then
      .
    elif $line == "---splunk-admon-end-of-event---"
         or ($line | is_admon_timestamp) then
      flush_record
    elif ($line | test("^[^=:\t\r\n][^=\t\r\n]*:$")) then
      if .current.started then
        .
      else
        error("admon line \(.line): section header before dcName")
      end
    else
      ($line | sub("^[\t ]+"; "")) as $field_line
      | if ($field_line | test("^[A-Za-z0-9_-]+=") | not) then
          error("admon line \(.line): unrecognized line")
        else
          ($field_line | capture("^(?<key>[A-Za-z0-9_-]+)=(?<value>.*)$")) as $field
          | if $field.key == "dcName" then
              if $field.value == "" then
                error("admon line \(.line): dcName must not be empty")
              else
                (if .current.started then flush_record else . end)
                | .current.started = true
                | add_field($field.key; $field.value)
              end
            elif (.current.started | not) then
              error("admon line \(.line): field \($field.key) before dcName")
            else
              add_field($field.key; $field.value)
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
