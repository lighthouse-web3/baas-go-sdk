package backup

import "fmt"

func RotateSnapshotTMK(http *HttpClient, snapshotID string, oldTMK, newTMK []byte) (Snapshot, bool, error) {
	snap, err := http.GetSnapshot(snapshotID)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("get snapshot %s: %w", snapshotID, err)
	}
	if snap.WrappedDEK == "" {
		return snap, false, fmt.Errorf("snapshot %s has no wrappedDek (unencrypted?)", snapshotID)
	}

	newWrapped, changed, err := RewrapDEKIdempotent(oldTMK, newTMK, snap.WrappedDEK)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("rewrap snapshot %s: %w", snapshotID, err)
	}
	if !changed {
		return snap, false, nil
	}

	updated, err := http.UpdateSnapshotEncryption(snapshotID, SnapshotEncryptionUpdate{
		WrappedDEK: newWrapped,
		Encryption: snap.Encryption,
	})
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("update snapshot %s: %w", snapshotID, err)
	}
	return updated, true, nil
}
