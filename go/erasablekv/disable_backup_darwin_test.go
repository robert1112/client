// +build darwin

package erasablekv

import (
	"context"
	"testing"

	"github.com/keybase/client/go/kbtest"
	"github.com/keybase/client/go/libkb"
	"github.com/pkg/xattr"
	"github.com/stretchr/testify/require"
)

func TestSetDisableBackup(t *testing.T) {
	tc := libkb.SetupTest(t, "erasable kv store disable backup", 1)
	defer tc.Cleanup()

	_, err := kbtest.CreateAndSignupFakeUser("t", tc.G)
	require.NoError(t, err)

	s := NewFileErasableKVStore(tc.G)
	key := "test-key"
	value := "value"

	err = s.Put(context.Background(), key, value)
	require.NoError(t, err)

	// This will break if we change the storagePath on storage..
	storagePath := tc.G.Env.GetDataDir()
	// Check that we set noBackup on the key
	metadata, err := xattr.Get(storagePath, key)
	require.NoError(t, err)
	require.Equal(t, []byte(noBackup), metadata)

	// Check that we set noBackup on the noise
	metadata, err = xattr.Get(storagePath, key+noiseSuffix)
	require.NoError(t, err)
	require.Equal(t, []byte(noBackup), metadata)
}
