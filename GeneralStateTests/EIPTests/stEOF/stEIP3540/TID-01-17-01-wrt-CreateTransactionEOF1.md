> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

EIP-3541: Contract code starting with the 0xEF byte is disallowed

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json \
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
		"0x011170"
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
2023-01-20T10:52:51.037568Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json", Total Files :: 1
2023-01-20T10:52:51.038038Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:52:51.151990Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T10:53:03.111771Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T10:53:03.111953Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T10:53:03.113181Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T10:53:03.113239Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Berlin::0
2023-01-20T10:53:03.113248Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113257Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-20T10:53:03.113285Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Berlin::1
2023-01-20T10:53:03.113291Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113298Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-20T10:53:03.113326Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Berlin::2
2023-01-20T10:53:03.113335Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113341Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113347Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-20T10:53:03.113368Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Berlin::3
2023-01-20T10:53:03.113374Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113383Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113389Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T10:53:03.113410Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::London::0
2023-01-20T10:53:03.113416Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113423Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-20T10:53:03.113451Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::London::1
2023-01-20T10:53:03.113457Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113464Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-20T10:53:03.113491Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::London::2
2023-01-20T10:53:03.113497Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113504Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-20T10:53:03.113531Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::London::3
2023-01-20T10:53:03.113538Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113545Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113551Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T10:53:03.113573Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Merge::0
2023-01-20T10:53:03.113579Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113586Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113591Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T10:53:03.113612Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Merge::1
2023-01-20T10:53:03.113619Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113627Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113632Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-20T10:53:03.113654Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Merge::2
2023-01-20T10:53:03.113660Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113667Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113672Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-20T10:53:03.113695Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Merge::3
2023-01-20T10:53:03.113701Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113708Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113713Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-20T10:53:03.113735Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Merge::4
2023-01-20T10:53:03.113741Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113748Z  WARN evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:53:03.113754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-20T10:53:03.113776Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Merge::5
2023-01-20T10:53:03.113782Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113788Z  WARN evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:53:03.113794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-20T10:53:03.113816Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Merge::6
2023-01-20T10:53:03.113822Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113829Z  WARN evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:53:03.113834Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-20T10:53:03.113856Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Merge::7
2023-01-20T10:53:03.113862Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113870Z  WARN evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:53:03.113875Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-20T10:53:03.113897Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Merge::8
2023-01-20T10:53:03.113903Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113909Z  WARN evm_eth_compliance::statetest::runner: TX len : 64
2023-01-20T10:53:03.113915Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-20T10:53:03.113938Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Merge::9
2023-01-20T10:53:03.113944Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113950Z  WARN evm_eth_compliance::statetest::runner: TX len : 62
2023-01-20T10:53:03.113956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T10:53:03.113978Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Shanghai::0
2023-01-20T10:53:03.113984Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.113991Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.113997Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T10:53:03.114019Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Shanghai::1
2023-01-20T10:53:03.114025Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.114032Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.114037Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T10:53:03.114059Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Shanghai::2
2023-01-20T10:53:03.114065Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.114072Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.114078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T10:53:03.114104Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Shanghai::3
2023-01-20T10:53:03.114114Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.114124Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:53:03.114132Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T10:53:03.114164Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Shanghai::4
2023-01-20T10:53:03.114174Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.114184Z  WARN evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:53:03.114191Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T10:53:03.114221Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Shanghai::5
2023-01-20T10:53:03.114231Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.114242Z  WARN evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:53:03.114250Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T10:53:03.114280Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Shanghai::6
2023-01-20T10:53:03.114291Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.114301Z  WARN evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:53:03.114311Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T10:53:03.114342Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Shanghai::7
2023-01-20T10:53:03.114356Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.114365Z  WARN evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:53:03.114374Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 8
2023-01-20T10:53:03.114408Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Shanghai::8
2023-01-20T10:53:03.114419Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.114429Z  WARN evm_eth_compliance::statetest::runner: TX len : 64
2023-01-20T10:53:03.114438Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 9
2023-01-20T10:53:03.114470Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "CreateTransactionEOF1"::Shanghai::9
2023-01-20T10:53:03.114480Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.114490Z  WARN evm_eth_compliance::statetest::runner: TX len : 62
2023-01-20T10:53:03.116818Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CreateTransactionEOF1.json"
2023-01-20T10:53:03.117234Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:11.962537261s
```