package libkb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
)

const KeyLifetimeSecs = 60 * 60 * 24 * 7 // one week

const EKSeedSize = 32

func makeNewRandomSeed() (seed [EKSeedSize]byte, err error) {
	bs, err := libkb.RandBytes(32)
	if err != nil {
		return seed, err
	}
	return libkb.MakeByte32(bs), nil
}

// =================
// === DeviceEKs ===
// =================

type DeviceEKSeed [EKSeedSize]byte

func newDeviceEphemeralSeed() (seed DeviceEKSeed, err error) {
	randomSeed, err := makeNewRandomSeed()
	if err != nil {
		return seed, err
	}
	return DeviceEKSeed(randomSeed), nil
}

func (s *DeviceEKSeed) DeriveDHKey() (key *libkb.NaclDHKeyPair, err error) {
	derived, err := libkb.DeriveFromSecret(*s, libkb.DeriveReasonDeviceEKEncryption)
	if err != nil {
		return nil, err
	}
	keypair, err := libkb.MakeNaclDHKeyPairFromSecret(derived)
	return &keypair, err
}

func postNewDeviceEK(ctx context.Context, g *libkb.GlobalContext, sig string) error {
	apiArg := libkb.APIArg{
		Endpoint:    "user/device_ek",
		SessionType: libkb.APISessionTypeREQUIRED,
		NetContext:  ctx,
		Args: libkb.HTTPArgs{
			"sig":       libkb.S{Val: sig},
			"device_id": libkb.S{Val: string(g.Env.GetDeviceID())},
		},
	}
	_, err := g.GetAPI().Post(apiArg)
	return err
}

func PublishNewDeviceEK(ctx context.Context, g *libkb.GlobalContext) (data keybase1.DeviceEkMetadata, err error) {
	currentMerkleRoot, err := g.GetMerkleClient().FetchRootFromServer(ctx, libkb.EphemeralKeyMerkleFreshness)
	if err != nil {
		return data, err
	}

	// TODO: Read the actual generation from the deviceEK store.
	generation := 1

	seed, err := newDeviceEphemeralSeed()
	if err != nil {
		return data, err
	}

	// TODO: Store the key.

	dhKeypair, err := seed.DeriveDHKey()
	if err != nil {
		return data, err
	}
	metadata := keybase1.DeviceEkMetadata{
		Kid:        dhKeypair.GetKID(),
		Generation: generation,
		HashMeta:   currentMerkleRoot.HashMeta(),
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return data, err
	}

	// Sign the metadata blob with the device's long term signing key.
	signingKey, err := g.ActiveDevice.SigningKey()
	if err != nil {
		return data, err
	}
	signedPacket, _, err := signingKey.SignToString(metadataJSON)

	err = postNewDeviceEK(ctx, g, signedPacket)
	if err != nil {
		return data, err
	}

	return metadata, nil
}

type DeviceEKsResponse struct {
	Results []struct {
		MerklePayload string `json:"merkle_payload"`
		Sig           string `json:"sig"`
	} `json:"results"`
}

func GetOwnDeviceEKs(ctx context.Context, g *libkb.GlobalContext) (map[keybase1.DeviceID]keybase1.DeviceEkMetadata, error) {
	apiArg := libkb.APIArg{
		Endpoint:    "user/device_eks",
		SessionType: libkb.APISessionTypeREQUIRED,
		NetContext:  ctx,
		Args:        libkb.HTTPArgs{},
	}
	res, err := g.GetAPI().Get(apiArg)
	if err != nil {
		return nil, err
	}

	parsedResponse := DeviceEKsResponse{}
	err = res.Body.UnmarshalAgain(&parsedResponse)
	if err != nil {
		return nil, err
	}

	// The client now needs to verify several things about these blobs its
	// received:
	// 1) Each is validly signed.
	// 2) The signing key belongs to one of the current user's devices.
	// 3) The merkle payload supplied by the server matches the hash that's
	//    been signed over.
	// 4) The key hasn't expired. That is, the Merkle root it was delegated
	//    with is within one week of the current root. The server deliberately
	//    avoids doing this filtering for us, and finding expired keys in the
	//    results here is expected. We silently drop them.
	currentDeviceEKs := map[keybase1.DeviceID]keybase1.DeviceEkMetadata{}
	currentMerkleRoot, err := g.GetMerkleClient().FetchRootFromServer(ctx, libkb.EphemeralKeyMerkleFreshness)
	for _, element := range parsedResponse.Results {
		// Verify the sig.
		signerKey, payload, _, err := libkb.NaclVerifyAndExtract(element.Sig)
		if err != nil {
			return nil, err
		}

		// Verify the signing key corresponds to a device.
		var matchingDevice *keybase1.PublicKey
		self, _, err := g.GetUPAKLoader().Load(libkb.NewLoadUserByUIDArg(ctx, g, g.Env.GetUID()))
		if err != nil {
			return nil, err
		}
		for _, device := range self.Base.DeviceKeys {
			if !device.KID.Equal(signerKey.GetKID()) {
				continue
			}
			if device.IsRevoked {
				return nil, fmt.Errorf("deviceEK returned for revoked device KID %s", signerKey.GetKID())
			}
			deviceDummyVar := device
			matchingDevice = &deviceDummyVar
			break
		}
		if matchingDevice == nil {
			return nil, fmt.Errorf("deviceEK returned for unknown device KID %s", signerKey.GetKID())
		}

		// Decode the signed JSON.
		var verifiedMetadata keybase1.DeviceEkMetadata
		err = json.Unmarshal(payload, &verifiedMetadata)
		if err != nil {
			return nil, err
		}

		// Check the hash of the Merkle payload, confirm it matches what was signed, and parse it.
		computedHash := sha256.Sum256([]byte(element.MerklePayload))
		if !bytes.Equal(verifiedMetadata.HashMeta, computedHash[:]) {
			return nil, fmt.Errorf("supplied merkle root doesn't match signed hash meta")
		}
		var signedMerkleRoot libkb.MerkleRootPayloadUnpacked
		err = json.Unmarshal([]byte(element.MerklePayload), &signedMerkleRoot)
		if err != nil {
			return nil, err
		}

		// Check whether the key is expired. This isn't considered an error,
		// since the server doesn't do this check for us. We log these cases
		// and skip them.
		ageSecs := currentMerkleRoot.Ctime() - signedMerkleRoot.Ctime
		if ageSecs > KeyLifetimeSecs {
			g.Log.Debug("skipping stale deviceEK %s for device KID %s", verifiedMetadata.Kid, matchingDevice.KID)
			continue
		}

		// This key is valid and current. Add it to the list we're about to return.
		currentDeviceEKs[matchingDevice.DeviceID] = verifiedMetadata
	}

	return currentDeviceEKs, nil
}

// ===============
// === UserEKs ===
// ===============

type UserEKSeed [EKSeedSize]byte

func newUserEphemeralSeed() (seed UserEKSeed, err error) {
	randomSeed, err := makeNewRandomSeed()
	if err != nil {
		return seed, err
	}
	return UserEKSeed(randomSeed), nil
}

func (s *UserEKSeed) DeriveDHKey() (key *libkb.NaclDHKeyPair, err error) {
	derived, err := libkb.DeriveFromSecret(*s, libkb.DeriveReasonUserEKEncryption)
	if err != nil {
		return nil, err
	}
	keypair, err := libkb.MakeNaclDHKeyPairFromSecret(derived)
	return &keypair, err
}

type UserEKBoxMetadata struct {
	RecipientDeviceID   keybase1.DeviceID `json:"recipient_device_id"`
	RecipientGeneration int               `json:"recipient_generation"`
	Box                 string            `json:"box"`
}

func postNewUserEK(ctx context.Context, g *libkb.GlobalContext, sig string, boxes []UserEKBoxMetadata) error {
	boxesJSON, err := json.Marshal(boxes)
	if err != nil {
		return err
	}
	apiArg := libkb.APIArg{
		Endpoint:    "user/user_ek",
		SessionType: libkb.APISessionTypeREQUIRED,
		NetContext:  ctx,
		Args: libkb.HTTPArgs{
			"sig":   libkb.S{Val: sig},
			"boxes": libkb.S{Val: string(boxesJSON)},
		},
	}
	_, err = g.GetAPI().Post(apiArg)
	return err
}

func PublishNewUserEK(ctx context.Context, g *libkb.GlobalContext) (data keybase1.UserEkMetadata, err error) {
	currentMerkleRoot, err := g.GetMerkleClient().FetchRootFromServer(ctx, libkb.EphemeralKeyMerkleFreshness)
	if err != nil {
		return data, err
	}

	// TODO: Read the actual generation from the userEK store.
	generation := 1

	seed, err := newUserEphemeralSeed()
	if err != nil {
		return data, err
	}

	// TODO: Store the key.

	dhKeypair, err := seed.DeriveDHKey()
	if err != nil {
		return data, err
	}
	metadata := keybase1.UserEkMetadata{
		Kid:        dhKeypair.GetKID(),
		Generation: generation,
		HashMeta:   currentMerkleRoot.HashMeta(),
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return data, err
	}

	// Sign the metadata blob with the latest PUK.
	pukKeyring, err := g.GetPerUserKeyring()
	if err != nil {
		return data, err
	}
	signingKey, err := pukKeyring.GetLatestSigningKey(ctx)
	if err != nil {
		return data, err
	}
	signedPacket, _, err := signingKey.SignToString(metadataJSON)

	// Box the seed up for each valid deviceEK.
	ownDeviceEKs, err := GetOwnDeviceEKs(ctx, g)
	if err != nil {
		return data, err
	}
	boxes := []UserEKBoxMetadata{}
	for deviceID, deviceEK := range ownDeviceEKs {
		recipientKey, err := libkb.ImportKeypairFromKID(deviceEK.Kid)
		if err != nil {
			return data, err
		}
		// Encrypting with a nil sender means we'll generate a random sender private key.
		box, err := recipientKey.EncryptToString(seed[:], nil)
		if err != nil {
			return data, err
		}
		boxMetadata := UserEKBoxMetadata{
			RecipientDeviceID:   deviceID,
			RecipientGeneration: deviceEK.Generation,
			Box:                 box,
		}
		boxes = append(boxes, boxMetadata)
	}

	err = postNewUserEK(ctx, g, signedPacket, boxes)
	if err != nil {
		return data, err
	}

	return metadata, nil
}

type UserEKResponse struct {
	Result struct {
		MerklePayload string `json:"merkle_payload"`
		Sig           string `json:"sig"`
	} `json:"result"`
}

// Returns nil if there is no active userEK, either because none has ever been
// created or because the user has gone stale.
func GetActiveUserEK(ctx context.Context, g *libkb.GlobalContext, uid keybase1.UID) (*keybase1.UserEkMetadata, error) {
	apiArg := libkb.APIArg{
		Endpoint:    "user/user_ek",
		SessionType: libkb.APISessionTypeREQUIRED,
		NetContext:  ctx,
		Args:        libkb.HTTPArgs{},
	}
	res, err := g.GetAPI().Get(apiArg)
	if err != nil {
		return nil, err
	}

	parsedResponse := UserEKResponse{}
	err = res.Body.UnmarshalAgain(&parsedResponse)
	if err != nil {
		return nil, err
	}

	// The client now needs to verify several things about the blob its
	// received:
	// 1) Each is validly signed.
	// 2) The signing key is the user's latest PUK.
	// 3) The merkle payload supplied by the server matches the hash that's
	//    been signed over.
	// 4) The key hasn't expired. That is, the Merkle root it was delegated
	//    with is within one week of the current root. The server deliberately
	//    avoids doing this filtering for us, and finding expired keys in the
	//    results here is expected. We silently drop them.

	// Verify the sig.
	signerKey, payload, _, err := libkb.NaclVerifyAndExtract(parsedResponse.Result.Sig)
	if err != nil {
		return nil, err
	}

	// Verify the signing key corresponds to the latest PUK. We load the user's
	// UPAK from cache, but if the KID doesn't match, we try a forced reload to
	// see if the cache might've been stale. Only if the KID still doesn't
	// match after the reload do we complain.
	upak, _, err := g.GetUPAKLoader().LoadV2(libkb.NewLoadUserByUIDArg(ctx, g, uid))
	if err != nil {
		return nil, err
	}
	latestPUK := upak.Current.GetLatestPerUserKey()
	if latestPUK == nil || !latestPUK.SigKID.Equal(signerKey.GetKID()) {
		// The latest PUK might be stale. Force a reload, then check this over again.
		upak, _, err = g.GetUPAKLoader().LoadV2(libkb.NewLoadUserByUIDForceArg(g, uid))
		if err != nil {
			return nil, err
		}
		latestPUK = upak.Current.GetLatestPerUserKey()
		if latestPUK == nil || !latestPUK.SigKID.Equal(signerKey.GetKID()) {
			// It still looks stale after a fresh poll. Bail out.
			latestPUKSigningKIDString := "<nil>"
			if latestPUK != nil {
				latestPUKSigningKIDString = fmt.Sprint(latestPUK.SigKID)
			}
			return nil, fmt.Errorf("userEK returned for UID %s PUK signing KID %s, but latest is %s",
				uid, signerKey.GetKID(), latestPUKSigningKIDString)
		}
	}

	// Decode the signed JSON.
	var verifiedMetadata keybase1.UserEkMetadata
	err = json.Unmarshal(payload, &verifiedMetadata)
	if err != nil {
		return nil, err
	}

	// Check the hash of the Merkle payload, confirm it matches what was signed, and parse it.
	computedHash := sha256.Sum256([]byte(parsedResponse.Result.MerklePayload))
	if !bytes.Equal(verifiedMetadata.HashMeta, computedHash[:]) {
		return nil, fmt.Errorf("supplied merkle root doesn't match signed hash meta")
	}
	var signedMerkleRoot libkb.MerkleRootPayloadUnpacked
	err = json.Unmarshal([]byte(parsedResponse.Result.MerklePayload), &signedMerkleRoot)
	if err != nil {
		return nil, err
	}

	// Check whether the key is expired. This isn't considered an error,
	// since the server doesn't do this check for us. We log these cases
	// and return nil.
	currentMerkleRoot, err := g.GetMerkleClient().FetchRootFromServer(ctx, libkb.EphemeralKeyMerkleFreshness)
	ageSecs := currentMerkleRoot.Ctime() - signedMerkleRoot.Ctime
	if ageSecs > KeyLifetimeSecs {
		g.Log.Debug("found stale userEK %s for UID %s", verifiedMetadata.Kid, uid)
		return nil, nil
	}

	// This key is valid and current. Return it.
	return &verifiedMetadata, nil
}
