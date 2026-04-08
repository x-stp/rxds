// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 x-stp

package asn1

type Tag uint8

const (
	BOOLEAN           Tag = 1
	INTEGER           Tag = 2
	BIT_STRING        Tag = 3
	OCTET_STRING      Tag = 4
	NULL              Tag = 5
	OBJECT_IDENTIFIER Tag = 6
	ENUM              Tag = 10
	SEQUENCE          Tag = 16
	SET               Tag = 17
	PrintableString   Tag = 19
	T61String         Tag = 20
	IA5String         Tag = 22
	UTCTime           Tag = 23
	GeneralizedTime   Tag = 24
	GeneralString     Tag = 27
)
