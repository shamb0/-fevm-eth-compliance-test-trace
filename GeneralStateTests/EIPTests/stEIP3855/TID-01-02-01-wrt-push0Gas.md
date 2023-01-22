> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEIP3855/push0Gas.json#L50

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas.json \
	cargo run \
	-- \
	statetest
```

> For Review

* Contract gets invoked, for transaction data length of 0 bytes, is it requirement ?

> Opcodes

@0x0000000000000000000000000000000000000100

```
0000 GAS
0001 PUSH1 0x00
0003 SSTORE
0004 INVALID
0005 GAS
0006 PUSH1 0x00
0008 SLOAD
0009 SUB
000a PUSH1 0x01
000c SSTORE
000d STOP
```

> Execution Trace


```
2023-01-20T06:17:44.827624Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas.json", Total Files :: 1
2023-01-20T06:17:44.828040Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas.json"
2023-01-20T06:17:44.937452Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T06:17:57.417280Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T06:17:57.417466Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:17:57.417539Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzaceakolkw3lbrubtfreszqhtnie34izgdksjuu77tsfape7abhsipqa
[DEBUG] fetching parameters block: 1
2023-01-20T06:17:57.420529Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T06:17:57.420664Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:17:57.421841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T06:17:57.421896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0Gas"::Merge::0
2023-01-20T06:17:57.421905Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas.json"
2023-01-20T06:17:57.421913Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T06:17:57.421920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:17:57.422492Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1577405,
    events_root: None,
}
2023-01-20T06:17:57.422511Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 200,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: UndefinedInstruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T06:17:57.422541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => MergePush0 0
2023-01-20T06:17:57.422570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "push0Gas"::MergePush0::0
2023-01-20T06:17:57.422577Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas.json"
2023-01-20T06:17:57.422584Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T06:17:57.422590Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T06:17:57.423125Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1577405,
    events_root: None,
}
2023-01-20T06:17:57.423140Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 200,
                    method: 3844450837,
                    code: ExitCode {
                        value: 23,
                    },
                    message: "EVM execution error: UndefinedInstruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-20T06:17:57.424818Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3855/push0Gas.json"
2023-01-20T06:17:57.425156Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.485739571s
```
