package cbor

import (
	"reflect"
	"testing"
)

// compareValues compares two values, handling type conversions that happen during CBOR round-trip
func compareValues(actual, expected interface{}) bool {
	// Handle nil cases
	if actual == nil && expected == nil {
		return true
	}
	if actual == nil || expected == nil {
		return false
	}

	// For numbers, CBOR might change the specific type (int vs int64, etc.)
	actualVal := reflect.ValueOf(actual)
	expectedVal := reflect.ValueOf(expected)

	// If both are numeric, compare their values
	if isNumeric(actualVal) && isNumeric(expectedVal) {
		return actualVal.Convert(reflect.TypeOf(float64(0))).Float() == expectedVal.Convert(reflect.TypeOf(float64(0))).Float()
	}

	// For maps, compare recursively
	if actualVal.Kind() == reflect.Map && expectedVal.Kind() == reflect.Map {
		if actualVal.Len() != expectedVal.Len() {
			return false
		}
		for _, expectedKey := range expectedVal.MapKeys() {
			// Try to find the key in actualVal - may need to handle type conversions
			var actualMapVal reflect.Value
			found := false

			// Try exact match first
			actualMapVal = actualVal.MapIndex(expectedKey)
			if actualMapVal.IsValid() {
				found = true
			} else {
				// Try finding by comparing keys with type conversion
				for _, actualKey := range actualVal.MapKeys() {
					if compareValues(actualKey.Interface(), expectedKey.Interface()) {
						actualMapVal = actualVal.MapIndex(actualKey)
						found = true
						break
					}
				}
			}

			if !found {
				return false
			}

			expectedMapVal := expectedVal.MapIndex(expectedKey)
			if !compareValues(actualMapVal.Interface(), expectedMapVal.Interface()) {
				return false
			}
		}
		return true
	}

	// For slices, compare recursively
	if actualVal.Kind() == reflect.Slice && expectedVal.Kind() == reflect.Slice {
		if actualVal.Len() != expectedVal.Len() {
			return false
		}
		for i := 0; i < actualVal.Len(); i++ {
			if !compareValues(actualVal.Index(i).Interface(), expectedVal.Index(i).Interface()) {
				return false
			}
		}
		return true
	}

	// For other types, use reflect.DeepEqual
	return reflect.DeepEqual(actual, expected)
}

// isNumeric checks if a reflect.Value represents a numeric type
func isNumeric(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

func TestEncodeUnknownFields(t *testing.T) {
	type TestStruct struct {
		Name    string                 `cbor:"name"`
		Age     int                    `cbor:"age"`
		Unknown map[string]interface{} `cbor:",unknown"`
	}

	testCases := []struct {
		name         string
		obj          TestStruct
		wantCborData []byte
	}{
		{
			name: "struct with unknown fields",
			obj: TestStruct{
				Name: "John",
				Age:  30,
				Unknown: map[string]interface{}{
					"extra1": "value1",
					"extra2": 42,
				},
			},
			wantCborData: mustHexDecode("a4646e616d65644a6f686e63616765181e666578747261316676616c756531666578747261321a"),
		},
		{
			name: "struct with empty unknown fields",
			obj: TestStruct{
				Name:    "Jane",
				Age:     25,
				Unknown: map[string]interface{}{},
			},
			wantCborData: mustHexDecode("a2646e616d65644a616e6563616765181a"),
		},
		{
			name: "struct with nil unknown fields",
			obj: TestStruct{
				Name:    "Bob",
				Age:     35,
				Unknown: nil,
			},
			wantCborData: mustHexDecode("a2646e616d6563426f6263616765181e"),
		},
		{
			name: "struct with complex unknown fields",
			obj: TestStruct{
				Name: "Alice",
				Age:  28,
				Unknown: map[string]interface{}{
					"nested": map[string]interface{}{
						"inner": "value",
					},
					"array": []interface{}{1, 2, 3},
					"bool":  true,
				},
			},
			wantCborData: mustHexDecode("a5646e616d6565416c69636563616765181c666e6573746564a165696e6e657265766176616c756565617272617983010203646b6f6f6cf5"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test encoding
			b, err := Marshal(tc.obj)
			if err != nil {
				t.Errorf("Marshal(%+v) returned error %v", tc.obj, err)
			}

			// For debugging: print the actual encoded data
			t.Logf("Encoded data: %x", b)

			// Test decoding back to verify roundtrip
			var decoded TestStruct
			err = Unmarshal(b, &decoded)
			if err != nil {
				t.Errorf("Unmarshal(0x%x) returned error %v", b, err)
			}

			// Verify the decoded struct matches the original
			if decoded.Name != tc.obj.Name {
				t.Errorf("Name mismatch: got %q, want %q", decoded.Name, tc.obj.Name)
			}
			if decoded.Age != tc.obj.Age {
				t.Errorf("Age mismatch: got %d, want %d", decoded.Age, tc.obj.Age)
			}

			// For unknown fields, we need to compare more carefully since map iteration order is not guaranteed
			// and types might be slightly different after round-trip
			if len(decoded.Unknown) != len(tc.obj.Unknown) {
				t.Errorf("Unknown fields length mismatch: got %d, want %d", len(decoded.Unknown), len(tc.obj.Unknown))
			} else {
				for key, expectedValue := range tc.obj.Unknown {
					if actualValue, exists := decoded.Unknown[key]; !exists {
						t.Errorf("Missing unknown field %q", key)
					} else if !compareValues(actualValue, expectedValue) {
						t.Errorf("Unknown field %q mismatch: got %+v (%T), want %+v (%T)", key, actualValue, actualValue, expectedValue, expectedValue)
					}
				}
			}
		})
	}
}

func TestEncodeUnknownFieldsSorting(t *testing.T) {
	type TestStruct struct {
		B       string                 `cbor:"b"`
		A       string                 `cbor:"a"`
		Unknown map[string]interface{} `cbor:",unknown"`
	}

	obj := TestStruct{
		B: "second",
		A: "first",
		Unknown: map[string]interface{}{
			"z": "last",
			"c": "middle",
		},
	}

	// Test with canonical sorting
	em, err := EncOptions{Sort: SortCanonical}.EncMode()
	if err != nil {
		t.Fatalf("EncMode() returned error %v", err)
	}

	b, err := em.Marshal(obj)
	if err != nil {
		t.Errorf("Marshal(%+v) returned error %v", obj, err)
	}

	t.Logf("Canonically sorted data: %x", b)

	// Test roundtrip
	var decoded TestStruct
	err = Unmarshal(b, &decoded)
	if err != nil {
		t.Errorf("Unmarshal(0x%x) returned error %v", b, err)
	}

	if !reflect.DeepEqual(decoded, obj) {
		t.Errorf("Roundtrip failed: got %+v, want %+v", decoded, obj)
	}
}

func TestEncodeUnknownFieldsWithOmitEmpty(t *testing.T) {
	type TestStruct struct {
		Name    string                 `cbor:"name,omitempty"`
		Age     int                    `cbor:"age,omitempty"`
		Unknown map[string]interface{} `cbor:",unknown"`
	}

	testCases := []struct {
		name string
		obj  TestStruct
	}{
		{
			name: "with omitempty and unknown fields",
			obj: TestStruct{
				Name: "John",
				Age:  0, // should be omitted
				Unknown: map[string]interface{}{
					"extra": "value",
				},
			},
		},
		{
			name: "empty struct with unknown fields only",
			obj: TestStruct{
				Unknown: map[string]interface{}{
					"only": "unknown",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Marshal(tc.obj)
			if err != nil {
				t.Errorf("Marshal(%+v) returned error %v", tc.obj, err)
			}

			t.Logf("Encoded data: %x", b)

			// Test roundtrip
			var decoded TestStruct
			err = Unmarshal(b, &decoded)
			if err != nil {
				t.Errorf("Unmarshal(0x%x) returned error %v", b, err)
			}

			// Verify the decoded struct matches the original (accounting for omitempty)
			if decoded.Name != tc.obj.Name {
				t.Errorf("Name mismatch: got %q, want %q", decoded.Name, tc.obj.Name)
			}
			if decoded.Age != tc.obj.Age {
				t.Errorf("Age mismatch: got %d, want %d", decoded.Age, tc.obj.Age)
			}
			if !reflect.DeepEqual(decoded.Unknown, tc.obj.Unknown) {
				t.Errorf("Unknown fields mismatch: got %+v, want %+v", decoded.Unknown, tc.obj.Unknown)
			}
		})
	}
}

func TestEncodeUnknownFieldsMultipleStructs(t *testing.T) {
	type Inner struct {
		Value   string                 `cbor:"value"`
		Unknown map[string]interface{} `cbor:",unknown"`
	}

	type Outer struct {
		Name    string                 `cbor:"name"`
		Inner   Inner                  `cbor:"inner"`
		Unknown map[string]interface{} `cbor:",unknown"`
	}

	obj := Outer{
		Name: "outer",
		Inner: Inner{
			Value: "inner_value",
			Unknown: map[string]interface{}{
				"inner_extra": "inner_unknown",
			},
		},
		Unknown: map[string]interface{}{
			"outer_extra": "outer_unknown",
		},
	}

	b, err := Marshal(obj)
	if err != nil {
		t.Errorf("Marshal(%+v) returned error %v", obj, err)
	}

	t.Logf("Encoded nested data: %x", b)

	// Test roundtrip
	var decoded Outer
	err = Unmarshal(b, &decoded)
	if err != nil {
		t.Errorf("Unmarshal(0x%x) returned error %v", b, err)
	}

	if !reflect.DeepEqual(decoded, obj) {
		t.Errorf("Roundtrip failed: got %+v, want %+v", decoded, obj)
	}
}

func TestEncodeUnknownFieldsNonStringKeys(t *testing.T) {
	t.Run("float64 keys", func(t *testing.T) {
		type TestStruct struct {
			Name    string          `cbor:"name"`
			Age     int             `cbor:"age"`
			Unknown map[float64]any `cbor:",unknown"`
		}

		obj := TestStruct{
			Name: "John",
			Age:  30,
			Unknown: map[float64]any{
				1.5: "value1",
				2.3: 42,
			},
		}

		testUnknownFieldRoundtrip(t, obj)
	})

	t.Run("disparate types with map[any]any", func(t *testing.T) {
		type TestStruct struct {
			Name    string      `cbor:"name"`
			Age     int         `cbor:"age"`
			Unknown map[any]any `cbor:",unknown"`
		}

		obj := TestStruct{
			Name: "Alice",
			Age:  25,
			Unknown: map[any]any{
				"string_key": "string_value",
				42:           "int_key_value",
				3.14:         "float_key_value",
				true:         "bool_key_value",
			},
		}

		testUnknownFieldRoundtrip(t, obj)
	})
}

// testUnknownFieldRoundtrip is a generic helper that tests encoding and decoding roundtrip
func testUnknownFieldRoundtrip[T any](t *testing.T, obj T) {
	t.Helper()

	// Test encoding
	b, err := Marshal(obj)
	if err != nil {
		t.Errorf("Marshal(%+v) returned error %v", obj, err)
		return
	}

	// For debugging: print the actual encoded data
	t.Logf("Encoded data: %x", b)

	// Test decoding back to verify roundtrip
	var decoded T
	err = Unmarshal(b, &decoded)
	if err != nil {
		t.Errorf("Unmarshal(0x%x) returned error %v", b, err)
		return
	}

	// Verify the decoded struct matches the original
	// For structs, we need to compare field by field since reflect.DeepEqual
	// can fail on map comparisons with different internal representations
	decodedVal := reflect.ValueOf(decoded)
	objVal := reflect.ValueOf(obj)

	for i := 0; i < decodedVal.NumField(); i++ {
		decodedField := decodedVal.Field(i)
		objField := objVal.Field(i)
		fieldName := decodedVal.Type().Field(i).Name

		if !compareValues(decodedField.Interface(), objField.Interface()) {
			t.Errorf("Field %s mismatch: got %+v (%T), want %+v (%T)",
				fieldName, decodedField.Interface(), decodedField.Interface(),
				objField.Interface(), objField.Interface())
		}
	}
}
