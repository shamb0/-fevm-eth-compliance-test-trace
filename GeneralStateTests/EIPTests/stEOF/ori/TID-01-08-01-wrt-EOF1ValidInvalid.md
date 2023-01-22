> Status

| Status | Context |
| --- | --- |
| SKIP | under WASM RT context |
| SKIP | under native RT context |

EIP-3541: Contract code starting with the 0xEF byte is disallowed

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json \
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
		"0x04c4b400"
	],
	"gasPrice" : "0x0a",
	"nonce" : "0x01",
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
2023-01-20T09:27:46.666165Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json", Total Files :: 1
2023-01-20T09:27:46.666629Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:46.791540Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T09:27:59.134251Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T09:27:59.134430Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:27:59.135696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 48
2023-01-20T09:27:59.135757Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::48
2023-01-20T09:27:59.135772Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.135780Z  WARN evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:27:59.135786Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 49
2023-01-20T09:27:59.135810Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::49
2023-01-20T09:27:59.135816Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.135822Z  WARN evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:27:59.135828Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 50
2023-01-20T09:27:59.135851Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::50
2023-01-20T09:27:59.135858Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.135864Z  WARN evm_eth_compliance::statetest::runner: TX len : 63
2023-01-20T09:27:59.135870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 51
2023-01-20T09:27:59.135893Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::51
2023-01-20T09:27:59.135899Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.135906Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T09:27:59.135911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 52
2023-01-20T09:27:59.135934Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::52
2023-01-20T09:27:59.135940Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.135947Z  WARN evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T09:27:59.135952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 53
2023-01-20T09:27:59.135975Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::53
2023-01-20T09:27:59.135982Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.135988Z  WARN evm_eth_compliance::statetest::runner: TX len : 141
2023-01-20T09:27:59.135994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 54
2023-01-20T09:27:59.136017Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::54
2023-01-20T09:27:59.136023Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136029Z  WARN evm_eth_compliance::statetest::runner: TX len : 46
2023-01-20T09:27:59.136035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 55
2023-01-20T09:27:59.136058Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::55
2023-01-20T09:27:59.136064Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136070Z  WARN evm_eth_compliance::statetest::runner: TX len : 46
2023-01-20T09:27:59.136076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 56
2023-01-20T09:27:59.136099Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::56
2023-01-20T09:27:59.136105Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136112Z  WARN evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T09:27:59.136117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 57
2023-01-20T09:27:59.136140Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::57
2023-01-20T09:27:59.136146Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136153Z  WARN evm_eth_compliance::statetest::runner: TX len : 39
2023-01-20T09:27:59.136158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 58
2023-01-20T09:27:59.136181Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::58
2023-01-20T09:27:59.136187Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136194Z  WARN evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:27:59.136199Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 59
2023-01-20T09:27:59.136222Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::59
2023-01-20T09:27:59.136228Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136235Z  WARN evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T09:27:59.136240Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 60
2023-01-20T09:27:59.136263Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::60
2023-01-20T09:27:59.136269Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136276Z  WARN evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:27:59.136281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 61
2023-01-20T09:27:59.136304Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::61
2023-01-20T09:27:59.136310Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136317Z  WARN evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:27:59.136322Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 62
2023-01-20T09:27:59.136345Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::62
2023-01-20T09:27:59.136351Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136358Z  WARN evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:27:59.136363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 63
2023-01-20T09:27:59.136386Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::63
2023-01-20T09:27:59.136392Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136399Z  WARN evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:27:59.136404Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 64
2023-01-20T09:27:59.136427Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::64
2023-01-20T09:27:59.136433Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136440Z  WARN evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:27:59.136445Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 65
2023-01-20T09:27:59.136468Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::65
2023-01-20T09:27:59.136474Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136481Z  WARN evm_eth_compliance::statetest::runner: TX len : 49
2023-01-20T09:27:59.136486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 66
2023-01-20T09:27:59.136509Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::66
2023-01-20T09:27:59.136515Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136522Z  WARN evm_eth_compliance::statetest::runner: TX len : 49
2023-01-20T09:27:59.136527Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 67
2023-01-20T09:27:59.136553Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::67
2023-01-20T09:27:59.136559Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136565Z  WARN evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:27:59.136571Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 68
2023-01-20T09:27:59.136594Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::68
2023-01-20T09:27:59.136600Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136606Z  WARN evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T09:27:59.136612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 69
2023-01-20T09:27:59.136634Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::69
2023-01-20T09:27:59.136641Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136647Z  WARN evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:27:59.136653Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 70
2023-01-20T09:27:59.136675Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::70
2023-01-20T09:27:59.136681Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136688Z  WARN evm_eth_compliance::statetest::runner: TX len : 37
2023-01-20T09:27:59.136693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 71
2023-01-20T09:27:59.136716Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::71
2023-01-20T09:27:59.136722Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136729Z  WARN evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:27:59.136734Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 72
2023-01-20T09:27:59.136757Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::72
2023-01-20T09:27:59.136763Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136769Z  WARN evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T09:27:59.136775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 73
2023-01-20T09:27:59.136798Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::73
2023-01-20T09:27:59.136804Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136810Z  WARN evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T09:27:59.136816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 74
2023-01-20T09:27:59.136838Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::74
2023-01-20T09:27:59.136845Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136851Z  WARN evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:27:59.136857Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 75
2023-01-20T09:27:59.136879Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::75
2023-01-20T09:27:59.136886Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136892Z  WARN evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:27:59.136898Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 76
2023-01-20T09:27:59.136920Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::76
2023-01-20T09:27:59.136926Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136933Z  WARN evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:27:59.136938Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 77
2023-01-20T09:27:59.136969Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::77
2023-01-20T09:27:59.136975Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.136982Z  WARN evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:27:59.136988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 78
2023-01-20T09:27:59.137010Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::78
2023-01-20T09:27:59.137017Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137023Z  WARN evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:27:59.137029Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T09:27:59.137051Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::0
2023-01-20T09:27:59.137057Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137064Z  WARN evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:27:59.137069Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T09:27:59.137092Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::1
2023-01-20T09:27:59.137098Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137104Z  WARN evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:27:59.137110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T09:27:59.137132Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::2
2023-01-20T09:27:59.137138Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137144Z  WARN evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:27:59.137150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T09:27:59.137172Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::3
2023-01-20T09:27:59.137178Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137184Z  WARN evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:27:59.137190Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T09:27:59.137213Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::4
2023-01-20T09:27:59.137219Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137226Z  WARN evm_eth_compliance::statetest::runner: TX len : 31
2023-01-20T09:27:59.137232Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T09:27:59.137254Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::5
2023-01-20T09:27:59.137261Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137267Z  WARN evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T09:27:59.137273Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T09:27:59.137295Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::6
2023-01-20T09:27:59.137302Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137308Z  WARN evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:27:59.137314Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T09:27:59.137336Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::7
2023-01-20T09:27:59.137342Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137349Z  WARN evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:27:59.137354Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 8
2023-01-20T09:27:59.137377Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::8
2023-01-20T09:27:59.137383Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137389Z  WARN evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T09:27:59.137395Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 9
2023-01-20T09:27:59.137417Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::9
2023-01-20T09:27:59.137424Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137430Z  WARN evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:27:59.137436Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 10
2023-01-20T09:27:59.137458Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::10
2023-01-20T09:27:59.137464Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137471Z  WARN evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:27:59.137476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 11
2023-01-20T09:27:59.137499Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::11
2023-01-20T09:27:59.137505Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137512Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T09:27:59.137517Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 12
2023-01-20T09:27:59.137540Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::12
2023-01-20T09:27:59.137546Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137552Z  WARN evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T09:27:59.137558Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 13
2023-01-20T09:27:59.137580Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::13
2023-01-20T09:27:59.137587Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137595Z  WARN evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T09:27:59.137601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 14
2023-01-20T09:27:59.137626Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::14
2023-01-20T09:27:59.137634Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137641Z  WARN evm_eth_compliance::statetest::runner: TX len : 37
2023-01-20T09:27:59.137647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 15
2023-01-20T09:27:59.137670Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::15
2023-01-20T09:27:59.137676Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137682Z  WARN evm_eth_compliance::statetest::runner: TX len : 142
2023-01-20T09:27:59.137688Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 16
2023-01-20T09:27:59.137711Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::16
2023-01-20T09:27:59.137717Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137723Z  WARN evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:27:59.137729Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 17
2023-01-20T09:27:59.137751Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::17
2023-01-20T09:27:59.137758Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137764Z  WARN evm_eth_compliance::statetest::runner: TX len : 46
2023-01-20T09:27:59.137770Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 18
2023-01-20T09:27:59.137792Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::18
2023-01-20T09:27:59.137798Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137805Z  WARN evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:27:59.137811Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 19
2023-01-20T09:27:59.137833Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::19
2023-01-20T09:27:59.137839Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137846Z  WARN evm_eth_compliance::statetest::runner: TX len : 37
2023-01-20T09:27:59.137851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 20
2023-01-20T09:27:59.137874Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::20
2023-01-20T09:27:59.137880Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137887Z  WARN evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:27:59.137892Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 21
2023-01-20T09:27:59.137915Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::21
2023-01-20T09:27:59.137921Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137928Z  WARN evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T09:27:59.137934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 22
2023-01-20T09:27:59.137956Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::22
2023-01-20T09:27:59.137962Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.137969Z  WARN evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:27:59.137975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 23
2023-01-20T09:27:59.137997Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::23
2023-01-20T09:27:59.138003Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138010Z  WARN evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:27:59.138015Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 24
2023-01-20T09:27:59.138038Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::24
2023-01-20T09:27:59.138044Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138051Z  WARN evm_eth_compliance::statetest::runner: TX len : 46
2023-01-20T09:27:59.138056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 25
2023-01-20T09:27:59.138079Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::25
2023-01-20T09:27:59.138085Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138092Z  WARN evm_eth_compliance::statetest::runner: TX len : 39
2023-01-20T09:27:59.138097Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 26
2023-01-20T09:27:59.138120Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::26
2023-01-20T09:27:59.138126Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138133Z  WARN evm_eth_compliance::statetest::runner: TX len : 49
2023-01-20T09:27:59.138138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 27
2023-01-20T09:27:59.138161Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::27
2023-01-20T09:27:59.138167Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138173Z  WARN evm_eth_compliance::statetest::runner: TX len : 43
2023-01-20T09:27:59.138179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 28
2023-01-20T09:27:59.138202Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::28
2023-01-20T09:27:59.138208Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138214Z  WARN evm_eth_compliance::statetest::runner: TX len : 43
2023-01-20T09:27:59.138220Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 29
2023-01-20T09:27:59.138243Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::29
2023-01-20T09:27:59.138249Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138256Z  WARN evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T09:27:59.138261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 30
2023-01-20T09:27:59.138284Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::30
2023-01-20T09:27:59.138290Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138297Z  WARN evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T09:27:59.138302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 31
2023-01-20T09:27:59.138325Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::31
2023-01-20T09:27:59.138331Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138338Z  WARN evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:27:59.138343Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 32
2023-01-20T09:27:59.138366Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::32
2023-01-20T09:27:59.138372Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138378Z  WARN evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T09:27:59.138384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 33
2023-01-20T09:27:59.138406Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::33
2023-01-20T09:27:59.138412Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138419Z  WARN evm_eth_compliance::statetest::runner: TX len : 49
2023-01-20T09:27:59.138425Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 34
2023-01-20T09:27:59.138447Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::34
2023-01-20T09:27:59.138453Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138460Z  WARN evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T09:27:59.138465Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 35
2023-01-20T09:27:59.138488Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::35
2023-01-20T09:27:59.138494Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138501Z  WARN evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T09:27:59.138506Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 36
2023-01-20T09:27:59.138529Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::36
2023-01-20T09:27:59.138535Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138542Z  WARN evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T09:27:59.138547Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 37
2023-01-20T09:27:59.138570Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::37
2023-01-20T09:27:59.138576Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138582Z  WARN evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:27:59.138588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 38
2023-01-20T09:27:59.138611Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::38
2023-01-20T09:27:59.138617Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138623Z  WARN evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T09:27:59.138629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 39
2023-01-20T09:27:59.138651Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::39
2023-01-20T09:27:59.138658Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138664Z  WARN evm_eth_compliance::statetest::runner: TX len : 43
2023-01-20T09:27:59.138670Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 40
2023-01-20T09:27:59.138692Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::40
2023-01-20T09:27:59.138698Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138705Z  WARN evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T09:27:59.138711Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 41
2023-01-20T09:27:59.138733Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::41
2023-01-20T09:27:59.138739Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138746Z  WARN evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:27:59.138751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 42
2023-01-20T09:27:59.138774Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::42
2023-01-20T09:27:59.138780Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138786Z  WARN evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:27:59.138792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 43
2023-01-20T09:27:59.138815Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::43
2023-01-20T09:27:59.138821Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138827Z  WARN evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:27:59.138833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 44
2023-01-20T09:27:59.138855Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::44
2023-01-20T09:27:59.138862Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138868Z  WARN evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:27:59.138874Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 45
2023-01-20T09:27:59.138896Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::45
2023-01-20T09:27:59.138903Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138909Z  WARN evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:27:59.138914Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 46
2023-01-20T09:27:59.138937Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::46
2023-01-20T09:27:59.138943Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138950Z  WARN evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:27:59.138955Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 47
2023-01-20T09:27:59.138978Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "EOF1ValidInvalid"::Shanghai::47
2023-01-20T09:27:59.138984Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.138990Z  WARN evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:27:59.141135Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/EOF1ValidInvalid.json"
2023-01-20T09:27:59.141489Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.347484678s
```