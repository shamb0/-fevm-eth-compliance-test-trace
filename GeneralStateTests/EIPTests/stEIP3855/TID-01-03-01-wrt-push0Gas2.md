> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEIP3855/push0Gas2.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas2.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T06:34:34.938013Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas2.json", Total Files :: 1
2023-01-20T06:34:34.938475Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas2.json"
2023-01-20T06:34:35.085173Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T06:34:47.248833Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T06:34:47.249085Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:34:47.249171Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzaceakolkw3lbrubtfreszqhtnie34izgdksjuu77tsfape7abhsipqa
[DEBUG] fetching parameters block: 1
2023-01-20T06:34:47.252315Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T06:34:47.252464Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:34:47.252509Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec36lb7pzasfrw4z7i6wvwy235ozsnsawxumlomkaqoxrktzvinvu
[DEBUG] fetching parameters block: 1
2023-01-20T06:34:47.255998Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-20T06:34:47.256171Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:34:47.256230Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaceaebg6jvkihnuivjctbxuj25pj36twvttwtvfigikb2p7z5lxhbpc
[DEBUG] fetching parameters block: 1
2023-01-20T06:34:47.259461Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-20T06:34:47.259608Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:34:47.260832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T06:34:47.260893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0Gas2"::Merge::0
2023-01-20T06:34:47.260911Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas2.json"
2023-01-20T06:34:47.260921Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:34:47.260930Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:34:47.262084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2742670,
    events_root: None,
}
2023-01-20T06:34:47.262124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T06:34:47.262158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0Gas2"::Merge::1
2023-01-20T06:34:47.262167Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas2.json"
2023-01-20T06:34:47.262176Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:34:47.262184Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:34:47.263163Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:34:47.263199Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => MergePush0 0
2023-01-20T06:34:47.263232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0Gas2"::MergePush0::0
2023-01-20T06:34:47.263240Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas2.json"
2023-01-20T06:34:47.263249Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:34:47.263257Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:34:47.264057Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:34:47.264091Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => MergePush0 1
2023-01-20T06:34:47.264124Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0Gas2"::MergePush0::1
2023-01-20T06:34:47.264133Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas2.json"
2023-01-20T06:34:47.264142Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T06:34:47.264150Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:34:47.264928Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1845243,
    events_root: None,
}
2023-01-20T06:34:47.267761Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas2.json"
2023-01-20T06:34:47.268161Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.179818786s
```