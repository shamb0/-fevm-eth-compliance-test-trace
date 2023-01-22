> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

* KO :: [FEVM | Eth Compliance Test | Hit with stack overflow error · Issue #1437 · filecoin-project/ref-fvm](https://github.com/filecoin-project/ref-fvm/issues/1437)

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json \
	cargo run \
	-- \
	statetest
```

> For Review

* No Stack overflow, but opcode is with `DELEGATECALL` of three stackframe, all the internal calls needs to be confirmed with traces.

* opcode needs to be reviewed.

> Opcodes

```
0000 PUSH1 0x40
0002 PUSH1 0x00
0004 PUSH1 0x40
0006 PUSH1 0x00
0008 PUSH20 0x1000000000000000000000000000000000000001
001d PUSH4 0x017d7840
0022 DELEGATECALL
0023 PUSH1 0x00
0025 SSTORE
0026 STOP
```

> Execution Trace

```
2023-01-21T12:16:35.626307Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-21T12:16:35.626751Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T12:16:35.741184Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-21T12:16:47.630771Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-21T12:16:47.630954Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T12:16:47.631030Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacebnl4qs36lv6yeufvqp2v2ulyxw7fg4lsy74npykx6rbqt7tu7you
[DEBUG] fetching parameters block: 1
2023-01-21T12:16:47.634047Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-21T12:16:47.634180Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T12:16:47.634225Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec4vpktydmelpwnsx5wnk7ddcfjbcy4p32woetpf5pywtrugromus
[DEBUG] fetching parameters block: 1
2023-01-21T12:16:47.637369Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-21T12:16:47.637505Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T12:16:47.637549Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaced2l3n2nphc2xwbukvf2fiooxrsdsoj7hd2rymybae7bd7owbz76m
[DEBUG] fetching parameters block: 1
2023-01-21T12:16:47.640348Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-21T12:16:47.640481Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T12:16:47.641629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-21T12:16:47.641680Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-21T12:16:47.641689Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T12:16:47.641698Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T12:16:47.641705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-21T12:16:47.644744Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7107509,
    events_root: None,
}
2023-01-21T12:16:47.644799Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-21T12:16:47.644826Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-21T12:16:47.644833Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T12:16:47.644841Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T12:16:47.644847Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-21T12:16:47.647276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6222695,
    events_root: None,
}
2023-01-21T12:16:47.647325Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-21T12:16:47.647352Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::London::0
2023-01-21T12:16:47.647359Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T12:16:47.647367Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T12:16:47.647373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-21T12:16:47.649801Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6222695,
    events_root: None,
}
2023-01-21T12:16:47.649850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-21T12:16:47.649877Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Merge::0
2023-01-21T12:16:47.649884Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T12:16:47.649891Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T12:16:47.649897Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-21T12:16:47.652323Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6222695,
    events_root: None,
}
2023-01-21T12:16:47.653861Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T12:16:47.654208Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:11.911211663s
```
