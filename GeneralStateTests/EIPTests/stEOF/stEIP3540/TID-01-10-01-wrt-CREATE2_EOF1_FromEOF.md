> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

EIP-3541: Contract code starting with the 0xEF byte is disallowed

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T09:44:06.250788Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json", Total Files :: 1
2023-01-20T09:44:06.251255Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json"
2023-01-20T09:44:06.367422Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T09:44:19.758676Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T09:44:19.758858Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:44:19.758935Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-20T09:44:19.758961Z  WARN evm_eth_compliance::statetest::runner: Skipping Test EIP-3541: Contract code starting with the 0xEF byte is disallowed.
2023-01-20T09:44:19.760114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T09:44:19.760167Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CREATE2_EOF1_FromEOF"::Shanghai::0
2023-01-20T09:44:19.760177Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json"
2023-01-20T09:44:19.760185Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:44:19.760191Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T09:44:19.760214Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CREATE2_EOF1_FromEOF"::Shanghai::1
2023-01-20T09:44:19.760220Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json"
2023-01-20T09:44:19.760227Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:44:19.760233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T09:44:19.760255Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CREATE2_EOF1_FromEOF"::Shanghai::2
2023-01-20T09:44:19.760261Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json"
2023-01-20T09:44:19.760268Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:44:19.760274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T09:44:19.760296Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CREATE2_EOF1_FromEOF"::Shanghai::3
2023-01-20T09:44:19.760302Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json"
2023-01-20T09:44:19.760309Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:44:19.760315Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T09:44:19.760337Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CREATE2_EOF1_FromEOF"::Shanghai::4
2023-01-20T09:44:19.760343Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json"
2023-01-20T09:44:19.760350Z  WARN evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:44:19.760355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T09:44:19.760377Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CREATE2_EOF1_FromEOF"::Shanghai::5
2023-01-20T09:44:19.760383Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json"
2023-01-20T09:44:19.760390Z  WARN evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:44:19.760396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T09:44:19.760418Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CREATE2_EOF1_FromEOF"::Shanghai::6
2023-01-20T09:44:19.760424Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json"
2023-01-20T09:44:19.760431Z  WARN evm_eth_compliance::statetest::runner: TX len : 64
2023-01-20T09:44:19.760436Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T09:44:19.760458Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CREATE2_EOF1_FromEOF"::Shanghai::7
2023-01-20T09:44:19.760464Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json"
2023-01-20T09:44:19.760471Z  WARN evm_eth_compliance::statetest::runner: TX len : 62
2023-01-20T09:44:19.762074Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1_FromEOF.json"
2023-01-20T09:44:19.762405Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:13.393082445s
```