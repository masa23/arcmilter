//go:build race

package main

// go test -raceでは結合テスト用の別プロセスにも競合検出を適用する。
const testRaceEnabled = true
