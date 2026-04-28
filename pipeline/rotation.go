package pipeline

import (
	"fmt"

	"github.com/lighthouse-web3/baas-go-sdk/api"
	"github.com/lighthouse-web3/baas-go-sdk/encrypt"
	sdktypes "github.com/lighthouse-web3/baas-go-sdk/types"
)

// RotateSnapshotTMK rewraps a snapshot DEK from oldTMK to newTMK.
func RotateSnapshotTMK(http *api.HttpClient, snapshotID string, oldTMK, newTMK []byte) (sdktypes.Snapshot, bool, error) {
	snap, err := http.GetSnapshot(snapshotID)
	if err != nil {
		return sdktypes.Snapshot{}, false, fmt.Errorf("get snapshot %s: %w", snapshotID, err)
	}
	if snap.WrappedDEK == "" {
		return snap, false, fmt.Errorf("snapshot %s has no wrappedDek (unencrypted?)", snapshotID)
	}

	newWrapped, changed, err := encrypt.RewrapDEKIdempotent(oldTMK, newTMK, snap.WrappedDEK)
	if err != nil {
		return sdktypes.Snapshot{}, false, fmt.Errorf("rewrap snapshot %s: %w", snapshotID, err)
	}
	if !changed {
		return snap, false, nil
	}
	updated, err := http.UpdateSnapshotEncryption(snapshotID, sdktypes.SnapshotEncryptionUpdate{
		WrappedDEK: newWrapped,
		Encryption: snap.Encryption,
	})
	if err != nil {
		return sdktypes.Snapshot{}, false, fmt.Errorf("update snapshot %s: %w", snapshotID, err)
	}
	return updated, true, nil
}
