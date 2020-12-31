/* SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */
// 00000000000000000000000000000000

package vplogic

var principalNamesMap map[string]principalEnum = map[string]principalEnum{
	"Attacker": 0,
}

var principalNamesMapCounter principalEnum = 1

func principalNamesMapAdd(name string) principalEnum {
	id, exists := principalNamesMap[name]
	if !exists {
		id = principalNamesMapCounter
		principalNamesMap[name] = id
		principalNamesMapCounter++
	}
	return id
}

func principalGetNameFromID(id principalEnum) string {
	for k, v := range principalNamesMap {
		if v == id {
			return k
		}
	}
	return ""
}
