// Auto-generated by avdl-compiler v1.3.22 (https://github.com/keybase/node-avdl-compiler)
//   Input file: avdl/keybase1/ephemeral.avdl

package keybase1

import (
	"github.com/keybase/go-framed-msgpack-rpc/rpc"
)

type DeviceEkMetadata struct {
	Kid        KID      `codec:"kid" json:"device_ephemeral_dh_public"`
	Generation int      `codec:"generation" json:"generation"`
	HashMeta   HashMeta `codec:"hashMeta" json:"hash_meta"`
}

func (o DeviceEkMetadata) DeepCopy() DeviceEkMetadata {
	return DeviceEkMetadata{
		Kid:        o.Kid.DeepCopy(),
		Generation: o.Generation,
		HashMeta:   o.HashMeta.DeepCopy(),
	}
}

type UserEkMetadata struct {
	Kid        KID      `codec:"kid" json:"user_ephemeral_dh_public"`
	Generation int      `codec:"generation" json:"generation"`
	HashMeta   HashMeta `codec:"hashMeta" json:"hash_meta"`
}

func (o UserEkMetadata) DeepCopy() UserEkMetadata {
	return UserEkMetadata{
		Kid:        o.Kid.DeepCopy(),
		Generation: o.Generation,
		HashMeta:   o.HashMeta.DeepCopy(),
	}
}

type TeamEkMetadata struct {
	Kid        KID      `codec:"kid" json:"team_ephemeral_dh_public"`
	Generation int      `codec:"generation" json:"generation"`
	HashMeta   HashMeta `codec:"hashMeta" json:"hash_meta"`
}

func (o TeamEkMetadata) DeepCopy() TeamEkMetadata {
	return TeamEkMetadata{
		Kid:        o.Kid.DeepCopy(),
		Generation: o.Generation,
		HashMeta:   o.HashMeta.DeepCopy(),
	}
}

type EphemeralInterface interface {
}

func EphemeralProtocol(i EphemeralInterface) rpc.Protocol {
	return rpc.Protocol{
		Name:    "keybase.1.ephemeral",
		Methods: map[string]rpc.ServeHandlerDescription{},
	}
}

type EphemeralClient struct {
	Cli rpc.GenericClient
}
