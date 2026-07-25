def empty_record:
  {fields: {}, seen: {}, started: false};

def flush_record:
  if .current.started then
    if (.current.fields | length) == 0 then
      error("kv line \(.line): admon record did not yield a non-empty event object")
    else
      .records += [.current.fields]
      | .current = empty_record
    end
  else
    .
  end;

def add_field($key; $value):
  if $value == "" then
    .
  elif .current.seen[$key] then
    error("kv line \(.line): duplicate field \($key)")
  else
    .current.seen[$key] = true
    | .current.fields[$key] = $value
  end;

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
      error("kv line \(.line): unexpected carriage return")
    elif $line == "" then
      .
    elif $line == "---splunk-admon-end-of-event---"
         or ($line | test("^[0-9]{1,2}/[0-9]{1,2}/[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?$")) then
      flush_record
    elif ($line | test("^[^=:\t\r\n][^=\t\r\n]*:$")) then
      if .current.started then
        .
      else
        error("kv line \(.line): section header before dcName")
      end
    else
      ($line | sub("^\t+"; "")) as $field_line
      | if ($field_line | test("^[A-Za-z0-9_-]+=") | not) then
          error("kv line \(.line): unrecognized admon line")
        else
          ($field_line | capture("^(?<key>[A-Za-z0-9_-]+)=(?<value>.*)$")) as $field
          | if $field.key == "dcName" then
              if $field.value == "" then
                error("kv line \(.line): dcName must not be empty")
              else
                (if .current.started then flush_record else . end)
                | .current.started = true
                | add_field($field.key; $field.value)
              end
            elif (.current.started | not) then
              error("kv line \(.line): field \($field.key) before dcName")
            else
              add_field($field.key; $field.value)
            end
        end
    end
)
| flush_record
| if (.records | length) == 0 then
    error("no admon records found")
  else
    .records
  end
