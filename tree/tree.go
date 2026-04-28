package tree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"strconv"

	sdktypes "github.com/lighthouse-web3/baas-go-sdk/types"
)

// CanonicalStringify serializes any value to canonical JSON.
func CanonicalStringify(v interface{}) string {
	var buf bytes.Buffer
	writeCanonical(&buf, reflect.ValueOf(v))
	return buf.String()
}

func writeCanonical(buf *bytes.Buffer, rv reflect.Value) {
	if !rv.IsValid() {
		buf.WriteString("null")
		return
	}
	for rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			buf.WriteString("null")
			return
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Bool:
		if rv.Bool() {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		buf.WriteString(strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		buf.WriteString(strconv.FormatUint(rv.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		f := rv.Float()
		if math.IsInf(f, 0) || math.IsNaN(f) {
			buf.WriteString("null")
			return
		}
		if f == math.Trunc(f) && !math.IsInf(f, 0) && math.Abs(f) < 1e15 {
			buf.WriteString(strconv.FormatInt(int64(f), 10))
		} else {
			buf.WriteString(strconv.FormatFloat(f, 'f', -1, 64))
		}
	case reflect.String:
		writeCanonicalString(buf, rv.String())
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			buf.WriteString("null")
			return
		}
		buf.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonical(buf, rv.Index(i))
		}
		buf.WriteByte(']')
	case reflect.Map:
		if rv.IsNil() {
			buf.WriteString("null")
			return
		}
		keys := make([]string, 0, rv.Len())
		for _, k := range rv.MapKeys() {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		first := true
		for _, k := range keys {
			val := rv.MapIndex(reflect.ValueOf(k))
			if !val.IsValid() {
				continue
			}
			if !first {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			writeCanonical(buf, val)
			first = false
		}
		buf.WriteByte('}')
	case reflect.Struct:
		writeCanonicalStruct(buf, rv)
	default:
		buf.WriteString("null")
	}
}

type kvPair struct {
	key string
	val reflect.Value
}

func writeCanonicalStruct(buf *bytes.Buffer, rv reflect.Value) {
	t := rv.Type()
	var pairs []kvPair
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		fv := rv.Field(i)
		tag := field.Tag.Get("json")
		name := field.Name
		omitempty := false
		if tag != "" {
			parts := splitTag(tag)
			if parts[0] == "-" {
				continue
			}
			if parts[0] != "" {
				name = parts[0]
			}
			for _, opt := range parts[1:] {
				if opt == "omitempty" {
					omitempty = true
				}
			}
		}
		if omitempty && isZeroValue(fv) {
			continue
		}
		pairs = append(pairs, kvPair{key: name, val: fv})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].key < pairs[j].key })
	buf.WriteByte('{')
	first := true
	for _, p := range pairs {
		if !first {
			buf.WriteByte(',')
		}
		writeCanonicalString(buf, p.key)
		buf.WriteByte(':')
		writeCanonical(buf, p.val)
		first = false
	}
	buf.WriteByte('}')
}

func splitTag(tag string) []string {
	var parts []string
	for tag != "" {
		idx := 0
		for idx < len(tag) && tag[idx] != ',' {
			idx++
		}
		parts = append(parts, tag[:idx])
		if idx < len(tag) {
			tag = tag[idx+1:]
		} else {
			break
		}
	}
	return parts
}

func isZeroValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		return v.IsNil()
	case reflect.Slice, reflect.Map:
		return v.IsNil() || v.Len() == 0
	case reflect.String:
		return v.String() == ""
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	}
	return false
}

var escMap = map[byte]string{
	'"':  `\"`,
	'\\': `\\`,
	'\b': `\b`,
	'\f': `\f`,
	'\n': `\n`,
	'\r': `\r`,
	'\t': `\t`,
}

func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if esc, ok := escMap[ch]; ok {
			buf.WriteString(esc)
		} else if ch < 0x20 {
			buf.WriteString(`\u00`)
			buf.WriteByte("0123456789abcdef"[ch>>4])
			buf.WriteByte("0123456789abcdef"[ch&0x0f])
		} else {
			buf.WriteByte(ch)
		}
	}
	buf.WriteByte('"')
}

// EncodeTree serializes tree nodes to canonical JSON bytes.
func EncodeTree(nodes []sdktypes.TreeNode) []byte {
	blob := sdktypes.TreeBlob{Nodes: nodes}
	return []byte(CanonicalStringify(blob))
}

// DecodeTree deserializes a tree blob from JSON bytes.
func DecodeTree(data []byte) (sdktypes.TreeBlob, error) {
	var blob sdktypes.TreeBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return blob, err
	}
	return blob, nil
}

// HashTree serializes tree nodes and returns the SHA-256 hash and raw bytes.
func HashTree(nodes []sdktypes.TreeNode) (hash string, data []byte) {
	data = EncodeTree(nodes)
	h := sha256.Sum256(data)
	hash = hex.EncodeToString(h[:])
	return
}
