package p3pserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

const challengeHMACKeyPrefix = "p3p-challenge-v1:"

func deriveChallengeHMACKey(secret string) string { return challengeHMACKeyPrefix + secret }
func computeChallengeID(key, realm, intent, requestBase64, expires string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(realm + "|" + intent + "|" + requestBase64 + "|" + expires))
	return "ch_" + hex.EncodeToString(mac.Sum(nil))
}
