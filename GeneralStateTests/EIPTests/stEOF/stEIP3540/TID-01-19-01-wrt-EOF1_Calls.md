> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

EIP-3541: Contract code starting with the 0xEF byte is disallowed

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T11:01:11.037960Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json", Total Files :: 1
2023-01-20T11:01:11.038380Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:11.150625Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.632145Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T11:01:23.632338Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.632417Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [18, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzaceagfzk4nypdtyrvnvpp2yh3q6cmukxqae5chcvgqiiv6yteupzdxq
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.635545Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T11:01:23.635688Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.635734Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzaceccsjtwn2lipcwcpf37zbmmao6pb3mhw5ynsegeeus462b42sbksm
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.639109Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-20T11:01:23.639257Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.639308Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [20, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaceasthexjb42ze6og7zcjwoxqpnt4jhvfxn4lar3gt2vudijyc6xno
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.642193Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-20T11:01:23.642331Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.642378Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [32, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 145, 95, 210, 114, 99, 97, 196, 103, 113, 159, 135, 176, 147, 142, 56, 188, 98, 191, 170]) }
[DEBUG] getting cid: bafy2bzacedswxngbflydujfbaowvszpr27x3dkdruwcvqaryninemufdvhake
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.645437Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-20T11:01:23.645574Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.645619Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [34, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([8, 220, 70, 60, 95, 134, 230, 77, 167, 148, 57, 129, 203, 169, 16, 22, 114, 213, 117, 83]) }
[DEBUG] getting cid: bafy2bzacedxadifeopdczejfzlvpredp67qygchuvrmtuomua67e435fh4v5a
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.648744Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [205]
2023-01-20T11:01:23.648880Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.648927Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [35, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([110, 106, 165, 99, 30, 211, 65, 233, 221, 242, 20, 186, 213, 63, 121, 136, 142, 179, 54, 182]) }
[DEBUG] getting cid: bafy2bzacecqmhzlpxrtpiyw4vykw5b7hyscpy4cx7ttirp7xbyxxwigj54z4k
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.652187Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [206]
2023-01-20T11:01:23.652327Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.652375Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [36, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 5, 158, 185, 170, 5, 126, 190, 213, 91, 244, 103, 65, 236, 58, 54, 23, 90, 163, 232]) }
[DEBUG] getting cid: bafy2bzaced6pmjx7236fljjitzdd525jixxd5l4kjiwal44xvke77eg4tv6pe
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.655689Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [207]
2023-01-20T11:01:23.655841Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.655900Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [48, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([60, 213, 27, 33, 255, 147, 208, 24, 221, 249, 192, 33, 170, 243, 120, 65, 173, 130, 62, 118]) }
[DEBUG] getting cid: bafy2bzacecb7qnxsnbontiry5wbe5qaktqc35u27lkiglmpvnttl2xkg5tck6
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.659037Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [208]
2023-01-20T11:01:23.659174Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.659220Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [50, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([52, 236, 47, 243, 10, 24, 163, 193, 208, 154, 15, 84, 169, 37, 75, 149, 162, 169, 2, 106]) }
[DEBUG] getting cid: bafy2bzacebki7dz2of4zbzkjqcmgcjds4fnlhatbhyhkp2av2ajzu6ajfonee
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.662312Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [209]
2023-01-20T11:01:23.662479Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.662524Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [51, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([224, 96, 23, 27, 11, 254, 109, 105, 147, 242, 31, 205, 64, 122, 50, 192, 129, 171, 105, 157]) }
[DEBUG] getting cid: bafy2bzaceashod7l2eaiazk2xuk3ukszayi5wscxtd7sswqbjkvif6jv534li
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.665846Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [210]
2023-01-20T11:01:23.665985Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.666032Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([88, 7, 105, 134, 41, 171, 45, 202, 96, 54, 195, 118, 205, 182, 59, 37, 115, 79, 202, 185]) }
[DEBUG] getting cid: bafy2bzacedxb7c5tozz2gxgnlf2smjokjobehiftwxgybpd3fp4wtr734dxdg
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.669110Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [211]
2023-01-20T11:01:23.669248Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.669297Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([203, 29, 242, 111, 87, 242, 104, 10, 204, 78, 236, 229, 253, 230, 75, 112, 5, 23, 23, 46]) }
[DEBUG] getting cid: bafy2bzacebukwwv3fednonf7hzioe5m2t22xpdbxc3awftoxfo2uxmtbb6sdo
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.672347Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [212]
2023-01-20T11:01:23.672502Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.672556Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([113, 222, 35, 242, 18, 65, 148, 67, 250, 227, 253, 187, 195, 0, 32, 28, 169, 223, 198, 105]) }
[DEBUG] getting cid: bafy2bzacedud3xrcfxgqexyoemsb7swui7wgwh3kkbp6jufzj7tbqim6zq474
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.675686Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [213]
2023-01-20T11:01:23.675828Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.675877Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [201, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([93, 225, 158, 165, 228, 0, 51, 61, 207, 237, 155, 116, 106, 16, 173, 65, 189, 187, 168, 53]) }
[DEBUG] getting cid: bafy2bzaceaeqi36eryrp5aelqekzoxotavhe5xipibg3mgfytdk43wx7u7xas
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.678975Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [214]
2023-01-20T11:01:23.679119Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.679175Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [217, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([99, 108, 72, 87, 154, 195, 66, 152, 214, 99, 112, 230, 193, 27, 161, 159, 253, 145, 86, 192]) }
[DEBUG] getting cid: bafy2bzacecyl3r2bfwlaaktoh3xrkavbngto3pq4bp5n7jn2i7wefsyfrsmze
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.682530Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [215]
2023-01-20T11:01:23.682686Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.682746Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [233, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([15, 35, 15, 230, 224, 213, 73, 156, 188, 219, 72, 185, 217, 129, 240, 2, 43, 120, 180, 38]) }
[DEBUG] getting cid: bafy2bzaceceermf5pme2kj4ppcosnotbo3aypomn3dbb34oto3kxqz2aupmcu
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.685956Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [216]
2023-01-20T11:01:23.686101Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.686154Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [249, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([247, 14, 230, 123, 234, 211, 48, 197, 177, 106, 144, 223, 79, 135, 102, 44, 190, 53, 196, 138]) }
[DEBUG] getting cid: bafy2bzacebfxgqnxt5ibpv5fjqsqntraqdqo35aeawp6wtbocviouj4z2rres
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.689589Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [217]
2023-01-20T11:01:23.689776Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:01:23.691003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T11:01:23.691061Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Merge::0
2023-01-20T11:01:23.691070Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.691079Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.691086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.692234Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2839164,
    events_root: None,
}
2023-01-20T11:01:23.692269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T11:01:23.692298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Merge::1
2023-01-20T11:01:23.692304Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.692312Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.692318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.693422Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.693451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-20T11:01:23.693481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Merge::2
2023-01-20T11:01:23.693488Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.693495Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.693501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.694477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.694506Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-20T11:01:23.694534Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Merge::3
2023-01-20T11:01:23.694541Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.694547Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.694553Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.695520Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.695552Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T11:01:23.695580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::0
2023-01-20T11:01:23.695587Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.695594Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.695600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.696396Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.696436Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T11:01:23.696471Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::1
2023-01-20T11:01:23.696479Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.696486Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.696492Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.697247Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.697278Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T11:01:23.697307Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::2
2023-01-20T11:01:23.697315Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.697322Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.697328Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.698097Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.698127Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T11:01:23.698156Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::3
2023-01-20T11:01:23.698163Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.698171Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.698177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.698916Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.698944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T11:01:23.698973Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::4
2023-01-20T11:01:23.698979Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.698986Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.698992Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.700127Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.700165Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T11:01:23.700203Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::5
2023-01-20T11:01:23.700213Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.700223Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.700231Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.701333Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.701362Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T11:01:23.701390Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::6
2023-01-20T11:01:23.701397Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.701405Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.701411Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.702371Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.702400Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T11:01:23.702427Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::7
2023-01-20T11:01:23.702434Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.702442Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.702447Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.703454Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.703495Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 8
2023-01-20T11:01:23.703541Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::8
2023-01-20T11:01:23.703566Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.703578Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.703587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.704827Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.704864Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 9
2023-01-20T11:01:23.704902Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::9
2023-01-20T11:01:23.704910Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.704919Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.704927Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.705936Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.705969Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 10
2023-01-20T11:01:23.705999Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::10
2023-01-20T11:01:23.706007Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.706016Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.706024Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.707015Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.707054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 11
2023-01-20T11:01:23.707091Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "EOF1_Calls"::Shanghai::11
2023-01-20T11:01:23.707102Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.707112Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T11:01:23.707121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:01:23.708139Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940814,
    events_root: None,
}
2023-01-20T11:01:23.709908Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/EOF1_Calls.json"
2023-01-20T11:01:23.710242Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.55756832s
```