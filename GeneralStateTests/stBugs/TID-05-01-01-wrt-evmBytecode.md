> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stBugs/evmBytecode.json#L1


> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json \
	cargo run \
	-- \
	statetest
```

> opcodes

```
0000 PUSH8 0xffffffffffffffff
0009 PUSH1 0x01
000b PUSH1 0x00
000d PUSH1 0x00
000f INVALID
```

> Execution Trace

```
2023-01-20T15:00:00.984110Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json", Total Files :: 1
2023-01-20T15:00:00.984563Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json"
2023-01-20T15:00:01.098513Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T15:00:13.479808Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T15:00:13.479990Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:00:13.480072Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T15:00:13.483274Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T15:00:13.483427Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:00:13.484605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T15:00:13.484661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "evmBytecode"::Istanbul::0
2023-01-20T15:00:13.484676Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json"
2023-01-20T15:00:13.484684Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T15:00:13.484691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:00:13.485277Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1552088,
    events_root: None,
}
2023-01-20T15:00:13.485297Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
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
2023-01-20T15:00:13.485343Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T15:00:13.485371Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "evmBytecode"::Berlin::0
2023-01-20T15:00:13.485378Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json"
2023-01-20T15:00:13.485385Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T15:00:13.485391Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:00:13.485925Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1552088,
    events_root: None,
}
2023-01-20T15:00:13.485940Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
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
2023-01-20T15:00:13.485967Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T15:00:13.485995Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "evmBytecode"::London::0
2023-01-20T15:00:13.486002Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json"
2023-01-20T15:00:13.486009Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T15:00:13.486014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:00:13.486549Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1552088,
    events_root: None,
}
2023-01-20T15:00:13.486564Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
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
2023-01-20T15:00:13.486590Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T15:00:13.486618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "evmBytecode"::Merge::0
2023-01-20T15:00:13.486625Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json"
2023-01-20T15:00:13.486632Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T15:00:13.486638Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:00:13.487168Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1552088,
    events_root: None,
}
2023-01-20T15:00:13.487183Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
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
2023-01-20T15:00:13.489610Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json"
2023-01-20T15:00:13.490126Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.388727066s
```
