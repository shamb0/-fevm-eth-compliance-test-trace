> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEIP3860/creationTxInitCodeSizeLimit.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/creationTxInitCodeSizeLimit.json \
	cargo run \
	-- \
	statetest
```

> For Review

* `transaction::to` address is empty | Execution Skipped

```
"transaction" : {
	...
	"gasLimit" : [
                "0xe4e1c0"
            ],
    "gasPrice" : "0x0a",
    "nonce" : "0x00",
    "secretKey" : "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
    "sender" : "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
    "to" : "",
    "value" : [
                "0x00"
            ]
}
```
> Execution Trace

```
2023-01-20T06:55:25.877765Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/creationTxInitCodeSizeLimit.json", Total Files :: 1
2023-01-20T06:55:25.878202Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/creationTxInitCodeSizeLimit.json"
2023-01-20T06:55:26.095990Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T06:55:37.965993Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T06:55:37.966240Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:55:37.967796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T06:55:37.967887Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "creationTxInitCodeSizeLimit"::Merge::0
2023-01-20T06:55:37.967908Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/creationTxInitCodeSizeLimit.json"
2023-01-20T06:55:37.967927Z  WARN evm_eth_compliance::statetest::runner: TX len : 49152
2023-01-20T06:55:37.967942Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T06:55:37.967983Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "creationTxInitCodeSizeLimit"::Merge::1
2023-01-20T06:55:37.967994Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/creationTxInitCodeSizeLimit.json"
2023-01-20T06:55:37.968005Z  WARN evm_eth_compliance::statetest::runner: TX len : 49153
2023-01-20T06:55:37.968023Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T06:55:37.968067Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "creationTxInitCodeSizeLimit"::Shanghai::0
2023-01-20T06:55:37.968087Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/creationTxInitCodeSizeLimit.json"
2023-01-20T06:55:37.968104Z  WARN evm_eth_compliance::statetest::runner: TX len : 49152
2023-01-20T06:55:37.968120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T06:55:37.968161Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "creationTxInitCodeSizeLimit"::Shanghai::1
2023-01-20T06:55:37.968178Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/creationTxInitCodeSizeLimit.json"
2023-01-20T06:55:37.968200Z  WARN evm_eth_compliance::statetest::runner: TX len : 49153
2023-01-20T06:55:37.970667Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/creationTxInitCodeSizeLimit.json"
2023-01-20T06:55:37.971201Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:11.872250999s

```