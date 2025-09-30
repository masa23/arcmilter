# Changelog

## [v0.0.21](https://github.com/masa23/arcmilter/compare/v0.0.20...v0.0.21) - 2025-09-30
- mmauth v1.0.3 update by @masa23 in https://github.com/masa23/arcmilter/pull/37
- tagprに対応 by @masa23 in https://github.com/masa23/arcmilter/pull/38
- テストに使うgoのバージョン間違いを修正 by @masa23 in https://github.com/masa23/arcmilter/pull/39
- update by @masa23 in https://github.com/masa23/arcmilter/pull/40

## [v0.0.20](https://github.com/masa23/arcmilter/compare/v0.0.19...v0.0.20) - 2025-09-06
- delete pr-agent by @masa23 in https://github.com/masa23/arcmilter/pull/35

## [v0.0.19](https://github.com/masa23/arcmilter/compare/v0.0.18...v0.0.19) - 2025-05-01
- golangを1.24にアップデート by @masa23 in https://github.com/masa23/arcmilter/pull/34

## [v0.0.18](https://github.com/masa23/arcmilter/compare/v0.0.17...v0.0.18) - 2025-05-01
- mmauthを分離 by @masa23 in https://github.com/masa23/arcmilter/pull/33

## [v0.0.17](https://github.com/masa23/arcmilter/compare/v0.0.16...v0.0.17) - 2025-01-29
- ARC署名が不完全な場合にnilのパターンで落ちる不具合を修正 by @masa23 in https://github.com/masa23/arcmilter/pull/29
- DKIMのheader.goのテストを追加 by @masa23 in https://github.com/masa23/arcmilter/pull/30
- mmauthに含まれるdkim,arc固有のヘッダ処理をarc,dkimパッケージに移動 by @masa23 in https://github.com/masa23/arcmilter/pull/28

## [v0.0.16](https://github.com/masa23/arcmilter/compare/v0.0.15...v0.0.16) - 2024-12-30
- Bump golang.org/x/crypto from 0.16.0 to 0.31.0 in the go_modules group across 1 directory by @dependabot[bot] in https://github.com/masa23/arcmilter/pull/26
- update golang.org/x/net by @masa23 in https://github.com/masa23/arcmilter/pull/27

## [v0.0.15](https://github.com/masa23/arcmilter/compare/v0.0.14...v0.0.15) - 2024-11-29
- mmauth.NewMMAuth()のタイミングを修正・子プロセス異常終了時に自動起動を追加 by @masa23 in https://github.com/masa23/arcmilter/pull/25

## [v0.0.14](https://github.com/masa23/arcmilter/compare/v0.0.13...v0.0.14) - 2024-11-25
- Verifyでpanicする不具合を修正 by @masa23 in https://github.com/masa23/arcmilter/pull/24

## [v0.0.13](https://github.com/masa23/arcmilter/compare/v0.0.12...v0.0.13) - 2024-10-30
- parseMailでエラーが発生するとWriteがブロックする問題の修正 by @masa23 in https://github.com/masa23/arcmilter/pull/23

## [v0.0.12](https://github.com/masa23/arcmilter/compare/v0.0.11...v0.0.12) - 2024-10-30
- test:mmauthのheaderテストを追加 by @masa23 in https://github.com/masa23/arcmilter/pull/21
- ParseError周りのエラーハンドリングを修正 by @masa23 in https://github.com/masa23/arcmilter/pull/22

## [v0.0.11](https://github.com/masa23/arcmilter/compare/v0.0.10...v0.0.11) - 2024-10-29
- pipeがcloseされないケースがあるのを修正 by @masa23 in https://github.com/masa23/arcmilter/pull/20

## [v0.0.10](https://github.com/masa23/arcmilter/compare/v0.0.9...v0.0.10) - 2024-10-16
- ARC-Authcation-ResultのSPFのmessageがtypoしているのを修正 by @masa23 in https://github.com/masa23/arcmilter/pull/19

## [v0.0.9](https://github.com/masa23/arcmilter/compare/v0.0.8...v0.0.9) - 2024-10-12
- fix ARCSign Selector hard code by @masa23 in https://github.com/masa23/arcmilter/pull/18

## [v0.0.8](https://github.com/masa23/arcmilter/compare/v0.0.7...v0.0.8) - 2024-10-08
- Fix ed25519 by @masa23 in https://github.com/masa23/arcmilter/pull/16

## [v0.0.7](https://github.com/masa23/arcmilter/compare/v0.0.6...v0.0.7) - 2024-09-30
- DKIMのLimitがある場合のBodyHashへの指定漏れを修正 by @masa23 in https://github.com/masa23/arcmilter/pull/14
- config_test.goを追加 by @masa23 in https://github.com/masa23/arcmilter/pull/15

## [v0.0.6](https://github.com/masa23/arcmilter/compare/v0.0.5...v0.0.6) - 2024-09-18
- MilterListenのOwnerとGroup指定ができるように変更 by @masa23 in https://github.com/masa23/arcmilter/pull/13

## [v0.0.5](https://github.com/masa23/arcmilter/compare/v0.0.4...v0.0.5) - 2024-08-27
- Milterとしての応答をチェックするテストと不具合修正 by @masa23 in https://github.com/masa23/arcmilter/pull/8
- README update by @masa23 in https://github.com/masa23/arcmilter/pull/9

## [v0.0.4](https://github.com/masa23/arcmilter/compare/v0.0.3...v0.0.4) - 2024-08-21
- test:checkPidFileをテストしやすく修正し、testを追加 by @masa23 in https://github.com/masa23/arcmilter/pull/3
- test:実行テストを追加 by @masa23 in https://github.com/masa23/arcmilter/pull/5
- feat:localから送信の際にARC署名を付与しないよう変更 by @masa23 in https://github.com/masa23/arcmilter/pull/6
- logrotateを追加 by @masa23 in https://github.com/masa23/arcmilter/pull/7

## [v0.0.3](https://github.com/masa23/arcmilter/compare/v0.0.2...v0.0.3) - 2024-08-18
- fix:DKIM署名が正常に行われない不具合を修正 by @masa23 in https://github.com/masa23/arcmilter/pull/2

## [v0.0.2](https://github.com/masa23/arcmilter/compare/v0.0.1...v0.0.2) - 2024-08-17
- ci:CREDITSを配布に含むよう修正 by @masa23 in https://github.com/masa23/arcmilter/pull/1

## [v0.0.1](https://github.com/masa23/arcmilter/commits/v0.0.1) - 2024-08-17
