// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package utils

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type NamespacedNameWithGroupKind struct {
	types.NamespacedName
	schema.GroupKind
}

// GetNamespacedNameWithGroupKind creates and returns object's NamespacedNameWithGroupKind.
func GetNamespacedNameWithGroupKind(obj client.Object) NamespacedNameWithGroupKind {
	return NamespacedNameWithGroupKind{
		NamespacedName: types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.GetName(),
		},
		GroupKind: schema.GroupKind{
			Group: obj.GetObjectKind().GroupVersionKind().GroupKind().Group,
			Kind:  obj.GetObjectKind().GroupVersionKind().GroupKind().Kind,
		},
	}
}

// NamespacedName creates and returns object's NamespacedName.
func NamespacedName(obj client.Object) types.NamespacedName {
	return types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}
}

// GetHashedName returns a partially hashed name for the string including up to the given length of the original name characters before the hash.
// Input `nsName` should be formatted as `{Namespace}/{ResourceName}`.
func GetHashedName(nsName string, length int) string {
	hashedName := Digest256(nsName)
	// replace `/` with `-` to create a valid K8s resource name
	resourceName := strings.ReplaceAll(nsName, "/", "-")
	if length > 0 && len(resourceName) > length {
		// resource name needs to be trimmed, as container port name must not contain consecutive hyphens
		trimmedName := strings.TrimSuffix(resourceName[0:length], "-")
		return fmt.Sprintf("%s-%s", trimmedName, hashedName[0:8])
	}
	// Ideally we should use 32-bit hash instead of 64-bit hash and return the first 8 characters of the hash.
	// However, we are using 64-bit hash to maintain backward compatibility.
	return fmt.Sprintf("%s-%s", resourceName, hashedName[0:8])
}

// Digest256 returns a sha256 hash of the input string.
// The hash is represented as a hexadecimal string of length 64.
func Digest256(str string) string {
	h := sha256.New() // Using sha256 instead of sha1 due to Blocklisted import crypto/sha1: weak cryptographic primitive (gosec)
	h.Write([]byte(str))
	return strings.ToLower(fmt.Sprintf("%x", h.Sum(nil)))
}

// DigestObject returns a short digest of a JSON representation of obj.
// It is intended for diagnostics where logging the object itself may be noisy
// or sensitive.
func DigestObject(obj any) string {
	b, err := json.Marshal(obj)
	if err != nil {
		return fmt.Sprintf("marshal-error:%T", obj)
	}
	return Digest256(string(b))[:12]
}

// Digest32 returns a 32-bit hash of the input string.
// The hash is represented as a hexadecimal string of length 8.
func Digest32(str string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(str))
	return fmt.Sprintf("%x", h.Sum32())
}
