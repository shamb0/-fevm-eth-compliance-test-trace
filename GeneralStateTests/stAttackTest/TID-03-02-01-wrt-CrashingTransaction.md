> Status

| Status | Context |
| --- | --- |
| SKIP | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stAttackTest/CrashingTransaction.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json \
	cargo run \
	-- \
	statetest
```

> For Review

* `pre::code` is empty | Execution skipped

```
"pre" : {
	"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b" : {
		"balance" : "0x0de0b6b3a7640000",
		"code" : "0x",
		"nonce" : "0x0cc6",
		"storage" : {
		}
	}
},
```

> Execution Trace

```
2023-01-20T14:48:05.241979Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json", Total Files :: 1
2023-01-20T14:48:05.242428Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
2023-01-20T14:48:05.358544Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T14:48:17.368075Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T14:48:17.368259Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:48:17.369517Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T14:48:17.369579Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CrashingTransaction"::Istanbul::0
2023-01-20T14:48:17.369588Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
2023-01-20T14:48:17.369596Z  WARN evm_eth_compliance::statetest::runner: TX len : 119
2023-01-20T14:48:17.369602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T14:48:17.369627Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CrashingTransaction"::Berlin::0
2023-01-20T14:48:17.369633Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
2023-01-20T14:48:17.369640Z  WARN evm_eth_compliance::statetest::runner: TX len : 119
2023-01-20T14:48:17.369646Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T14:48:17.369668Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CrashingTransaction"::London::0
2023-01-20T14:48:17.369674Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
2023-01-20T14:48:17.369682Z  WARN evm_eth_compliance::statetest::runner: TX len : 119
2023-01-20T14:48:17.369688Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T14:48:17.369709Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CrashingTransaction"::Merge::0
2023-01-20T14:48:17.369716Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
2023-01-20T14:48:17.369722Z  WARN evm_eth_compliance::statetest::runner: TX len : 119
2023-01-20T14:48:17.371649Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stAttackTest/CrashingTransaction.json"
2023-01-20T14:48:17.372026Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.011211969s
```
