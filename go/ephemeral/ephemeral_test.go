package libkb

import (
	"context"
	"testing"

	"github.com/keybase/client/go/kbtest"
	"github.com/keybase/client/go/libkb"
	"github.com/stretchr/testify/require"
)

func TestNewDeviceEK(t *testing.T) {
	tc := libkb.SetupTest(t, "ephemeral", 2)
	defer tc.Cleanup()

	_, err := kbtest.CreateAndSignupFakeUser("t", tc.G)
	require.NoError(t, err)

	publishedMetadata, err := PublishNewDeviceEK(context.Background(), tc.G)
	require.NoError(t, err)

	fetchedDevices, err := GetOwnDeviceEKs(context.Background(), tc.G)
	require.NoError(t, err)

	require.Equal(t, 1, len(fetchedDevices))
	for _, fetchedDevice := range fetchedDevices {
		require.Equal(t, publishedMetadata, fetchedDevice)
	}
	require.Equal(t, 1, publishedMetadata.Generation)
}

func TestNewUserEK(t *testing.T) {
	tc := libkb.SetupTest(t, "ephemeral", 2)
	defer tc.Cleanup()

	fakeUser, err := kbtest.CreateAndSignupFakeUser("t", tc.G)
	require.NoError(t, err)

	// The test user has a PUK, but it's not automatically loaded. We have to
	// explicitly sync it.
	keyring, err := tc.G.GetPerUserKeyring()
	require.NoError(t, err)
	err = keyring.Sync(context.Background())
	require.NoError(t, err)

	_, err = PublishNewDeviceEK(context.Background(), tc.G)
	require.NoError(t, err)

	publishedMetadata, err := PublishNewUserEK(context.Background(), tc.G)
	require.NoError(t, err)

	activeUserEK, err := GetActiveUserEK(context.Background(), tc.G, fakeUser.GetUID())
	require.NoError(t, err)
	require.NotNil(t, activeUserEK)
	require.Equal(t, *activeUserEK, publishedMetadata)
	require.Equal(t, 1, activeUserEK.Generation)
}

// TODO: test cases chat verify we can detect invalid signatures and bad metadata
