> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

EIP-3541: Contract code starting with the 0xEF byte is disallowed

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json#L20

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T11:05:15.758562Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json", Total Files :: 1
2023-01-20T11:05:15.758954Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:15.869151Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [2, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.048309Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T11:05:28.048499Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.048575Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [80, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzaceav6tskfi7jtpscyzuejwztxsbcbcp5uovun7uv54di5jm3lwyceo
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.051479Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T11:05:28.051618Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.051663Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [81, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacebqdzubpf7r5xggtdrp55d3l2bxhs7euftrm7a7szuzsufdvc3v6u
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.054669Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-20T11:05:28.054816Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.054861Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [82, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzacea6wpospr7gis6l7rao3kbi6t4euegygctkffenbcqoidm5mkelxu
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.058007Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-20T11:05:28.058145Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.058199Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [96, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 145, 95, 210, 114, 99, 97, 196, 103, 113, 159, 135, 176, 147, 142, 56, 188, 98, 191, 170]) }
[DEBUG] getting cid: bafy2bzaced74c35javqwm5no3prwguqfjhl7z3rm47sjeay4nu43io2zwffte
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.061249Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-20T11:05:28.061391Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.061441Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [97, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([8, 220, 70, 60, 95, 134, 230, 77, 167, 148, 57, 129, 203, 169, 16, 22, 114, 213, 117, 83]) }
[DEBUG] getting cid: bafy2bzacedvozj7f3wobfk26sgddv6cedseukaete2aulzmajo6uei6xjmr5w
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.065128Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [205]
2023-01-20T11:05:28.065310Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.065380Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [98, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([110, 106, 165, 99, 30, 211, 65, 233, 221, 242, 20, 186, 213, 63, 121, 136, 142, 179, 54, 182]) }
[DEBUG] getting cid: bafy2bzacebvt4yhksrcl5xiqgc2fygscxggthccnkirirenxrda5r5jqxe3fc
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.068574Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [206]
2023-01-20T11:05:28.068742Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.068809Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [99, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 5, 158, 185, 170, 5, 126, 190, 213, 91, 244, 103, 65, 236, 58, 54, 23, 90, 163, 232]) }
[DEBUG] getting cid: bafy2bzacebiidqchp2hmytmh6gymydwreqnrjeishpreqr7lwgukn6tiaevmq
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.071863Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [207]
2023-01-20T11:05:28.072020Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.072095Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [100, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([60, 213, 27, 33, 255, 147, 208, 24, 221, 249, 192, 33, 170, 243, 120, 65, 173, 130, 62, 118]) }
[DEBUG] getting cid: bafy2bzacebz2xmz4a55v6fgsfz7kipa3ynlb4t3lbdvey5hqv5ycfgo6t64fg
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.075155Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [208]
2023-01-20T11:05:28.075296Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.075348Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [101, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([52, 236, 47, 243, 10, 24, 163, 193, 208, 154, 15, 84, 169, 37, 75, 149, 162, 169, 2, 106]) }
[DEBUG] getting cid: bafy2bzacedxm3truuan4ofp5qxz77tjh4yd7glxs2f4byfgsitabnxqdtehmw
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.078628Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [209]
2023-01-20T11:05:28.078799Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.078870Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [102, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([224, 96, 23, 27, 11, 254, 109, 105, 147, 242, 31, 205, 64, 122, 50, 192, 129, 171, 105, 157]) }
[DEBUG] getting cid: bafy2bzacedco5ej27oilx2jna2tch3mxtujq3jlqrmmbbb4dagkaraqduxyv2
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.082240Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [210]
2023-01-20T11:05:28.082398Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.082450Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [103, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([88, 7, 105, 134, 41, 171, 45, 202, 96, 54, 195, 118, 205, 182, 59, 37, 115, 79, 202, 185]) }
[DEBUG] getting cid: bafy2bzacecsyop5yxgisqoalype6fkpag7i5guwpdwmhandmzudijz7hyhjdy
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.085747Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [211]
2023-01-20T11:05:28.085903Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.085963Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([203, 29, 242, 111, 87, 242, 104, 10, 204, 78, 236, 229, 253, 230, 75, 112, 5, 23, 23, 46]) }
[DEBUG] getting cid: bafy2bzaceaoptmsoct3oorqcnsxtopyfwyxrmmzocws2yywep7pvfjlsjyrg2
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.088906Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [212]
2023-01-20T11:05:28.089058Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.089115Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([113, 222, 35, 242, 18, 65, 148, 67, 250, 227, 253, 187, 195, 0, 32, 28, 169, 223, 198, 105]) }
[DEBUG] getting cid: bafy2bzacec5nx5nlubtnudhnmbklpw55m6lym7ciggxxsc57tbmqecv4jwyla
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.092158Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [213]
2023-01-20T11:05:28.092304Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.092355Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [201, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([93, 225, 158, 165, 228, 0, 51, 61, 207, 237, 155, 116, 106, 16, 173, 65, 189, 187, 168, 53]) }
[DEBUG] getting cid: bafy2bzacec2ceqfkpgip3zqrqiprrgz33jn2c23ifwj6xh5ighjrla5p3eoye
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.095337Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [214]
2023-01-20T11:05:28.095477Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.095533Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [217, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([99, 108, 72, 87, 154, 195, 66, 152, 214, 99, 112, 230, 193, 27, 161, 159, 253, 145, 86, 192]) }
[DEBUG] getting cid: bafy2bzaceceo4xcwvevpnxqp5osuz2yk6kgk4kdmvw6phwliwnhnhbt6wn3xa
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.098519Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [215]
2023-01-20T11:05:28.098658Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:05:28.099797Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T11:05:28.099852Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::0
2023-01-20T11:05:28.099862Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.099873Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.099882Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.100971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2739164,
    events_root: None,
}
2023-01-20T11:05:28.101011Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T11:05:28.101041Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::1
2023-01-20T11:05:28.101048Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.101057Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.101065Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.101995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.102028Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-20T11:05:28.102058Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::2
2023-01-20T11:05:28.102066Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.102075Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.102082Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.102998Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.103031Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-20T11:05:28.103061Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::3
2023-01-20T11:05:28.103069Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.103078Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.103086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.104001Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.104033Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-20T11:05:28.104063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::4
2023-01-20T11:05:28.104071Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.104080Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.104087Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.104990Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.105023Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-20T11:05:28.105053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::5
2023-01-20T11:05:28.105061Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.105069Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.105077Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.106001Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.106034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-20T11:05:28.106063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::6
2023-01-20T11:05:28.106071Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.106079Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.106087Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.107006Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.107039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-20T11:05:28.107068Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::7
2023-01-20T11:05:28.107076Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.107085Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.107093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.108008Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.108041Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-20T11:05:28.108070Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::8
2023-01-20T11:05:28.108078Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.108087Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.108095Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.109033Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.109066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-20T11:05:28.109095Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::9
2023-01-20T11:05:28.109104Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.109112Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.109120Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.110031Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.110064Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-20T11:05:28.110093Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::10
2023-01-20T11:05:28.110101Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.110110Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.110117Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.111029Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.111061Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-20T11:05:28.111090Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::11
2023-01-20T11:05:28.111098Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.111107Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.111115Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.112049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.112082Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-20T11:05:28.112111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::12
2023-01-20T11:05:28.112119Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.112128Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.112136Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.113033Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.113065Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-20T11:05:28.113095Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Merge::13
2023-01-20T11:05:28.113103Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.113112Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.113119Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.114034Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.114067Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T11:05:28.114096Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::0
2023-01-20T11:05:28.114104Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.114113Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.114120Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.114844Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.114877Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T11:05:28.114906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::1
2023-01-20T11:05:28.114915Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.114923Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.114931Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.115647Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.115680Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T11:05:28.115709Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::2
2023-01-20T11:05:28.115718Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.115726Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.115734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.116457Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.116490Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T11:05:28.116519Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::3
2023-01-20T11:05:28.116526Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.116535Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.116543Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.117263Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.117296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T11:05:28.117326Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::4
2023-01-20T11:05:28.117334Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.117342Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.117350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.118062Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.118095Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T11:05:28.118124Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::5
2023-01-20T11:05:28.118132Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.118141Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.118148Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.118860Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.118892Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T11:05:28.118921Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::6
2023-01-20T11:05:28.118929Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.118938Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.118945Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.119663Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.119695Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T11:05:28.119725Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::7
2023-01-20T11:05:28.119733Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.119741Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.119749Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.120462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.120495Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 8
2023-01-20T11:05:28.120524Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::8
2023-01-20T11:05:28.120532Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.120541Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.120550Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.121271Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.121304Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 9
2023-01-20T11:05:28.121333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::9
2023-01-20T11:05:28.121341Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.121350Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.121358Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.122072Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.122105Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 10
2023-01-20T11:05:28.122134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::10
2023-01-20T11:05:28.122142Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.122151Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.122158Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.122878Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.122911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 11
2023-01-20T11:05:28.122940Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::11
2023-01-20T11:05:28.122948Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.122957Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.122964Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.123682Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.123715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 12
2023-01-20T11:05:28.123744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::12
2023-01-20T11:05:28.123752Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.123761Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.123768Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.124482Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.124515Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 13
2023-01-20T11:05:28.124544Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Execution"::Shanghai::13
2023-01-20T11:05:28.124553Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.124561Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:05:28.124569Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:05:28.125293Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1840814,
    events_root: None,
}
2023-01-20T11:05:28.127378Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Execution.json"
2023-01-20T11:05:28.127626Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.256202384s
```