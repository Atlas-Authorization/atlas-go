package atlas

import "encoding/json"

// marshalWithExtra JSON-encodes v (a struct, encoded with its normal tags) and
// then overlays extra on top of the resulting object. An extra value of nil is
// sent as JSON null — the way PATCH routes clear a stored setting — so typed
// params can still express "clear this" and fields this SDK does not model yet.
func marshalWithExtra(v interface{}, extra map[string]interface{}) ([]byte, error) {
	base, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return base, nil
	}
	merged := map[string]json.RawMessage{}
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for k, val := range extra {
		raw, err := json.Marshal(val)
		if err != nil {
			return nil, err
		}
		merged[k] = raw
	}
	return json.Marshal(merged)
}

// unknownKeys returns the members of a JSON object whose keys are not in known,
// for decoding a typed struct while keeping the rest in an Extra map.
func unknownKeys(data []byte, known ...string) (map[string]interface{}, error) {
	all := map[string]interface{}{}
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, err
	}
	for _, k := range known {
		delete(all, k)
	}
	if len(all) == 0 {
		return nil, nil
	}
	return all, nil
}
