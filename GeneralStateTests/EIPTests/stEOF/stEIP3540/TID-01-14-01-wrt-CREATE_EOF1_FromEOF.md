> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

EIP-3541: Contract code starting with the 0xEF byte is disallowed

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json \
	cargo run \
	-- \
	statetest
```

> Opcodes

```
0000 INVALID
0001 STOP
0002 ADD
0003 ADD
0004 STOP
0005 DIV
0006 MUL
0007 STOP
0008 ADD
0009 STOP
000a ISZERO
000b SUB
000c STOP
000d STOP
000e STOP
000f STOP
0010 STOP
0011 STOP
0012 SUB
0013 CALLDATASIZE
0014 PUSH1 0x00
0016 PUSH1 0x00
0018 CALLDATACOPY
0019 CALLDATASIZE
001a PUSH1 0x00
001c PUSH1 0x00
001e CREATE
001f PUSH1 0x00
0021 SSTORE
0022 PUSH1 0x01
0024 PUSH1 0x01
0026 SSTORE
0027 STOP
```

> Execution Trace

```
2023-01-20T10:23:15.176028Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json", Total Files :: 1
2023-01-20T10:23:15.176458Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json"
2023-01-20T10:23:15.291315Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T10:23:27.646113Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T10:23:27.646289Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T10:23:27.646367Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T10:23:27.649389Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T10:23:27.649523Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T10:23:27.650652Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T10:23:27.650705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1_FromEOF"::Shanghai::0
2023-01-20T10:23:27.650713Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json"
2023-01-20T10:23:27.650722Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:23:27.650728Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:23:27.651287Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557727,
    events_root: None,
}
2023-01-20T10:23:27.651306Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:23:27.651335Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T10:23:27.651362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1_FromEOF"::Shanghai::1
2023-01-20T10:23:27.651368Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json"
2023-01-20T10:23:27.651375Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:23:27.651381Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:23:27.651897Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557727,
    events_root: None,
}
2023-01-20T10:23:27.651912Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:23:27.651937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T10:23:27.651964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1_FromEOF"::Shanghai::2
2023-01-20T10:23:27.651970Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json"
2023-01-20T10:23:27.651978Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:23:27.651985Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:23:27.652502Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557727,
    events_root: None,
}
2023-01-20T10:23:27.652516Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:23:27.652541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T10:23:27.652568Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1_FromEOF"::Shanghai::3
2023-01-20T10:23:27.652575Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json"
2023-01-20T10:23:27.652582Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:23:27.652587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:23:27.653116Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557727,
    events_root: None,
}
2023-01-20T10:23:27.653131Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:23:27.653156Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T10:23:27.653182Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1_FromEOF"::Shanghai::4
2023-01-20T10:23:27.653189Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json"
2023-01-20T10:23:27.653196Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:23:27.653202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:23:27.653718Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558692,
    events_root: None,
}
2023-01-20T10:23:27.653732Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:23:27.653757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T10:23:27.653783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1_FromEOF"::Shanghai::5
2023-01-20T10:23:27.653790Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json"
2023-01-20T10:23:27.653797Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:23:27.653803Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:23:27.654318Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558692,
    events_root: None,
}
2023-01-20T10:23:27.654332Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:23:27.654357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T10:23:27.654384Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1_FromEOF"::Shanghai::6
2023-01-20T10:23:27.654390Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json"
2023-01-20T10:23:27.654397Z  INFO evm_eth_compliance::statetest::runner: TX len : 64
2023-01-20T10:23:27.654403Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:23:27.654917Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558697,
    events_root: None,
}
2023-01-20T10:23:27.654932Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:23:27.654956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T10:23:27.654984Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1_FromEOF"::Shanghai::7
2023-01-20T10:23:27.654990Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json"
2023-01-20T10:23:27.654997Z  INFO evm_eth_compliance::statetest::runner: TX len : 62
2023-01-20T10:23:27.655003Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:23:27.655517Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558694,
    events_root: None,
}
2023-01-20T10:23:27.655532Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:23:27.657427Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1_FromEOF.json"
2023-01-20T10:23:27.657753Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.364269993s
```