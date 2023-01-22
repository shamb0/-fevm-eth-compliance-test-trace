> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

EIP-3541: Contract code starting with the 0xEF byte is disallowed

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json \
	cargo run \
	-- \
	statetest
```

> Opcode

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
000a OR
000b SUB
000c STOP
000d STOP
000e STOP
000f STOP
0010 STOP
0011 STOP
0012 DIV
0013 CALLDATASIZE
0014 PUSH1 0x00
0016 PUSH1 0x00
0018 CALLDATACOPY
0019 PUSH1 0x00
001b CALLDATASIZE
001c PUSH1 0x00
001e PUSH1 0x00
0020 CREATE2
0021 PUSH1 0x00
0023 SSTORE
0024 PUSH1 0x01
0026 PUSH1 0x01
0028 SSTORE
0029 STOP
```

> Execution Trace

```
2023-01-20T10:05:27.399500Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json", Total Files :: 1
2023-01-20T10:05:27.399910Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:27.540433Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.571170Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T10:05:39.571352Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T10:05:39.571432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.574521Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T10:05:39.574659Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T10:05:39.575800Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T10:05:39.575860Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::0
2023-01-20T10:05:39.575875Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.575883Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-20T10:05:39.575890Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.576449Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557985,
    events_root: None,
}
2023-01-20T10:05:39.576469Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.576497Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T10:05:39.576525Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::1
2023-01-20T10:05:39.576531Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.576538Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:05:39.576544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.577072Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558961,
    events_root: None,
}
2023-01-20T10:05:39.577087Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.577113Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T10:05:39.577139Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::2
2023-01-20T10:05:39.577146Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.577153Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:05:39.577159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.577677Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558961,
    events_root: None,
}
2023-01-20T10:05:39.577692Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.577717Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T10:05:39.577744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::3
2023-01-20T10:05:39.577751Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.577758Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:05:39.577764Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.578285Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558961,
    events_root: None,
}
2023-01-20T10:05:39.578300Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.578325Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T10:05:39.578352Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::4
2023-01-20T10:05:39.578359Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.578366Z  INFO evm_eth_compliance::statetest::runner: TX len : 2
2023-01-20T10:05:39.578372Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.578889Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557987,
    events_root: None,
}
2023-01-20T10:05:39.578903Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.578928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T10:05:39.578955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::5
2023-01-20T10:05:39.578962Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.578969Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:05:39.578975Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.579492Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558961,
    events_root: None,
}
2023-01-20T10:05:39.579507Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.579532Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T10:05:39.579558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::6
2023-01-20T10:05:39.579565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.579572Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:05:39.579578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.580109Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558961,
    events_root: None,
}
2023-01-20T10:05:39.580125Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.580150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T10:05:39.580176Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::7
2023-01-20T10:05:39.580183Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.580190Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:05:39.580196Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.580773Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558961,
    events_root: None,
}
2023-01-20T10:05:39.580788Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.580813Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 8
2023-01-20T10:05:39.580840Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::8
2023-01-20T10:05:39.580846Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.580854Z  INFO evm_eth_compliance::statetest::runner: TX len : 3
2023-01-20T10:05:39.580859Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.581411Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557988,
    events_root: None,
}
2023-01-20T10:05:39.581426Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.581451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 9
2023-01-20T10:05:39.581482Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::9
2023-01-20T10:05:39.581490Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.581497Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T10:05:39.581503Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.582039Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557989,
    events_root: None,
}
2023-01-20T10:05:39.582054Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.582079Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 10
2023-01-20T10:05:39.582106Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::10
2023-01-20T10:05:39.582113Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.582120Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T10:05:39.582126Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.582651Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557989,
    events_root: None,
}
2023-01-20T10:05:39.582666Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.582691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 11
2023-01-20T10:05:39.582718Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::11
2023-01-20T10:05:39.582724Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.582732Z  INFO evm_eth_compliance::statetest::runner: TX len : 5
2023-01-20T10:05:39.582737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.583280Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557990,
    events_root: None,
}
2023-01-20T10:05:39.583295Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.583320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 12
2023-01-20T10:05:39.583348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::12
2023-01-20T10:05:39.583354Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.583361Z  INFO evm_eth_compliance::statetest::runner: TX len : 7
2023-01-20T10:05:39.583367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.583897Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557993,
    events_root: None,
}
2023-01-20T10:05:39.583913Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.583937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 13
2023-01-20T10:05:39.583964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::13
2023-01-20T10:05:39.583971Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.583978Z  INFO evm_eth_compliance::statetest::runner: TX len : 8
2023-01-20T10:05:39.583984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.584510Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557994,
    events_root: None,
}
2023-01-20T10:05:39.584525Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.584550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 14
2023-01-20T10:05:39.584577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::14
2023-01-20T10:05:39.584584Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.584592Z  INFO evm_eth_compliance::statetest::runner: TX len : 9
2023-01-20T10:05:39.584601Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.585145Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557995,
    events_root: None,
}
2023-01-20T10:05:39.585160Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.585185Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 15
2023-01-20T10:05:39.585212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::15
2023-01-20T10:05:39.585218Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.585226Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:05:39.585231Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.585754Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557996,
    events_root: None,
}
2023-01-20T10:05:39.585769Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.585794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 16
2023-01-20T10:05:39.585821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::16
2023-01-20T10:05:39.585828Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.585835Z  INFO evm_eth_compliance::statetest::runner: TX len : 11
2023-01-20T10:05:39.585841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.586362Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557997,
    events_root: None,
}
2023-01-20T10:05:39.586377Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.586402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 17
2023-01-20T10:05:39.586428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::17
2023-01-20T10:05:39.586435Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.586442Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T10:05:39.586448Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.586974Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558001,
    events_root: None,
}
2023-01-20T10:05:39.586989Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.587014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 18
2023-01-20T10:05:39.587041Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::18
2023-01-20T10:05:39.587048Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.587055Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:05:39.587061Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.587582Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558007,
    events_root: None,
}
2023-01-20T10:05:39.587597Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.587622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 19
2023-01-20T10:05:39.587649Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::19
2023-01-20T10:05:39.587655Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.587663Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:05:39.587669Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.588193Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558007,
    events_root: None,
}
2023-01-20T10:05:39.588208Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.588233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 20
2023-01-20T10:05:39.588260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::20
2023-01-20T10:05:39.588267Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.588274Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T10:05:39.588280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.588802Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558005,
    events_root: None,
}
2023-01-20T10:05:39.588817Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.588841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 21
2023-01-20T10:05:39.588868Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::21
2023-01-20T10:05:39.588875Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.588882Z  INFO evm_eth_compliance::statetest::runner: TX len : 15
2023-01-20T10:05:39.588888Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.589418Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558002,
    events_root: None,
}
2023-01-20T10:05:39.589433Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.589457Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 22
2023-01-20T10:05:39.589484Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::22
2023-01-20T10:05:39.589491Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.589498Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:05:39.589504Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.590032Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558000,
    events_root: None,
}
2023-01-20T10:05:39.590047Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.590071Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 23
2023-01-20T10:05:39.590099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::23
2023-01-20T10:05:39.590105Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.590113Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:05:39.590118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.590641Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558007,
    events_root: None,
}
2023-01-20T10:05:39.590656Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.590681Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 24
2023-01-20T10:05:39.590711Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::24
2023-01-20T10:05:39.590718Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.590725Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:05:39.590731Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.591262Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558364,
    events_root: None,
}
2023-01-20T10:05:39.591277Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.591302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 25
2023-01-20T10:05:39.591329Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::25
2023-01-20T10:05:39.591336Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.591343Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T10:05:39.591349Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.591876Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558461,
    events_root: None,
}
2023-01-20T10:05:39.591891Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.591916Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 26
2023-01-20T10:05:39.591943Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::26
2023-01-20T10:05:39.591950Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.591957Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:05:39.591963Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.592486Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558007,
    events_root: None,
}
2023-01-20T10:05:39.592501Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.592526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 27
2023-01-20T10:05:39.592552Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::27
2023-01-20T10:05:39.592559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.592566Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:05:39.592572Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.593110Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558007,
    events_root: None,
}
2023-01-20T10:05:39.593125Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.593150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 28
2023-01-20T10:05:39.593177Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::28
2023-01-20T10:05:39.593184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.593191Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:05:39.593197Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.593723Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558000,
    events_root: None,
}
2023-01-20T10:05:39.593739Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.593763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 29
2023-01-20T10:05:39.593790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::29
2023-01-20T10:05:39.593797Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.593808Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T10:05:39.593814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.594345Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558365,
    events_root: None,
}
2023-01-20T10:05:39.594360Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.594385Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 30
2023-01-20T10:05:39.594412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::30
2023-01-20T10:05:39.594419Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.594426Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:05:39.594432Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.594959Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558367,
    events_root: None,
}
2023-01-20T10:05:39.594974Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.594999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 31
2023-01-20T10:05:39.595026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::31
2023-01-20T10:05:39.595032Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.595039Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:05:39.595045Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.595568Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558367,
    events_root: None,
}
2023-01-20T10:05:39.595582Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.595607Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 32
2023-01-20T10:05:39.595634Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::32
2023-01-20T10:05:39.595641Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.595648Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:05:39.595654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.596186Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558367,
    events_root: None,
}
2023-01-20T10:05:39.596201Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.596225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 33
2023-01-20T10:05:39.596253Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::33
2023-01-20T10:05:39.596260Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.596267Z  INFO evm_eth_compliance::statetest::runner: TX len : 16
2023-01-20T10:05:39.596272Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.596798Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558003,
    events_root: None,
}
2023-01-20T10:05:39.596813Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.596838Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 34
2023-01-20T10:05:39.596865Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::34
2023-01-20T10:05:39.596872Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.596879Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T10:05:39.596885Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.597430Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558005,
    events_root: None,
}
2023-01-20T10:05:39.597445Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.597470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 35
2023-01-20T10:05:39.597497Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::35
2023-01-20T10:05:39.597504Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.597511Z  INFO evm_eth_compliance::statetest::runner: TX len : 12
2023-01-20T10:05:39.597517Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.598043Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557999,
    events_root: None,
}
2023-01-20T10:05:39.598058Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.598083Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 36
2023-01-20T10:05:39.598110Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::36
2023-01-20T10:05:39.598116Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.598123Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:05:39.598129Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.598655Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558000,
    events_root: None,
}
2023-01-20T10:05:39.598670Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.598695Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 37
2023-01-20T10:05:39.598722Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::37
2023-01-20T10:05:39.598729Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.598736Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T10:05:39.598742Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.599270Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558001,
    events_root: None,
}
2023-01-20T10:05:39.599285Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.599310Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 38
2023-01-20T10:05:39.599337Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::38
2023-01-20T10:05:39.599344Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.599351Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T10:05:39.599357Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.599882Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558365,
    events_root: None,
}
2023-01-20T10:05:39.599897Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.599922Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 39
2023-01-20T10:05:39.599949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::39
2023-01-20T10:05:39.599955Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.599962Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:05:39.599971Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.600503Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558364,
    events_root: None,
}
2023-01-20T10:05:39.600518Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.600543Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 40
2023-01-20T10:05:39.600570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::40
2023-01-20T10:05:39.600577Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.600584Z  INFO evm_eth_compliance::statetest::runner: TX len : 23
2023-01-20T10:05:39.600590Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.601124Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558368,
    events_root: None,
}
2023-01-20T10:05:39.601139Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.601163Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 41
2023-01-20T10:05:39.601190Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::41
2023-01-20T10:05:39.601197Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.601204Z  INFO evm_eth_compliance::statetest::runner: TX len : 25
2023-01-20T10:05:39.601210Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.601735Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558459,
    events_root: None,
}
2023-01-20T10:05:39.601750Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.601775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 42
2023-01-20T10:05:39.601802Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::42
2023-01-20T10:05:39.601809Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.601816Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T10:05:39.601822Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.602348Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558461,
    events_root: None,
}
2023-01-20T10:05:39.602363Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.602387Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 43
2023-01-20T10:05:39.602415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::43
2023-01-20T10:05:39.602421Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.602429Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T10:05:39.602434Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.602959Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558469,
    events_root: None,
}
2023-01-20T10:05:39.602974Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.602999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 44
2023-01-20T10:05:39.603026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::44
2023-01-20T10:05:39.603033Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.603040Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:05:39.603045Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.603578Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557996,
    events_root: None,
}
2023-01-20T10:05:39.603593Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.603618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 45
2023-01-20T10:05:39.603645Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::45
2023-01-20T10:05:39.603652Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.603659Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:05:39.603665Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.604196Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557996,
    events_root: None,
}
2023-01-20T10:05:39.604211Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.604236Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 46
2023-01-20T10:05:39.604263Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::46
2023-01-20T10:05:39.604270Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.604277Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:05:39.604283Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.604809Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557996,
    events_root: None,
}
2023-01-20T10:05:39.604824Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.604849Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 47
2023-01-20T10:05:39.604879Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::47
2023-01-20T10:05:39.604887Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.604895Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:05:39.604901Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.605432Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558364,
    events_root: None,
}
2023-01-20T10:05:39.605447Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.605472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 48
2023-01-20T10:05:39.605499Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::48
2023-01-20T10:05:39.605505Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.605512Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:05:39.605518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.606049Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558364,
    events_root: None,
}
2023-01-20T10:05:39.606064Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.606089Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 49
2023-01-20T10:05:39.606116Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::49
2023-01-20T10:05:39.606123Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.606130Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:05:39.606136Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.606669Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558364,
    events_root: None,
}
2023-01-20T10:05:39.606684Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.606709Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 50
2023-01-20T10:05:39.606736Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::50
2023-01-20T10:05:39.606743Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.606750Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:05:39.606756Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.607286Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558364,
    events_root: None,
}
2023-01-20T10:05:39.607301Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.607326Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 51
2023-01-20T10:05:39.607353Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::51
2023-01-20T10:05:39.607360Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.607367Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:05:39.607373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.607903Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558364,
    events_root: None,
}
2023-01-20T10:05:39.607918Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.607942Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 52
2023-01-20T10:05:39.607969Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::52
2023-01-20T10:05:39.607976Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.607983Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:05:39.607989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.608515Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558364,
    events_root: None,
}
2023-01-20T10:05:39.608529Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.608554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 53
2023-01-20T10:05:39.608582Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::53
2023-01-20T10:05:39.608588Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.608595Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:05:39.608601Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.609143Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558457,
    events_root: None,
}
2023-01-20T10:05:39.609158Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.609183Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 54
2023-01-20T10:05:39.609210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::54
2023-01-20T10:05:39.609217Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.609224Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:05:39.609230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.609760Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558457,
    events_root: None,
}
2023-01-20T10:05:39.609774Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.609799Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 55
2023-01-20T10:05:39.609827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::55
2023-01-20T10:05:39.609833Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.609841Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:05:39.609846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.610374Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558457,
    events_root: None,
}
2023-01-20T10:05:39.610389Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.610414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 56
2023-01-20T10:05:39.610441Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::56
2023-01-20T10:05:39.610448Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.610455Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:05:39.610461Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.610992Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557996,
    events_root: None,
}
2023-01-20T10:05:39.611008Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.611033Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 57
2023-01-20T10:05:39.611060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::57
2023-01-20T10:05:39.611067Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.611074Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.611080Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.611608Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.611622Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.611647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 58
2023-01-20T10:05:39.611674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::58
2023-01-20T10:05:39.611681Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.611689Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.611695Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.612225Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.612240Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.612266Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 59
2023-01-20T10:05:39.612293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::59
2023-01-20T10:05:39.612299Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.612307Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.612313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.612840Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.612856Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.612884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 60
2023-01-20T10:05:39.612912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::60
2023-01-20T10:05:39.612919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.612926Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.612932Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.613469Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.613484Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.613509Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 61
2023-01-20T10:05:39.613536Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::61
2023-01-20T10:05:39.613542Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.613549Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.613555Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.614088Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.614103Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.614128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 62
2023-01-20T10:05:39.614155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::62
2023-01-20T10:05:39.614162Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.614169Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.614175Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.614701Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.614716Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.614741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 63
2023-01-20T10:05:39.614768Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::63
2023-01-20T10:05:39.614775Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.614782Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.614788Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.615320Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.615335Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.615359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 64
2023-01-20T10:05:39.615386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::64
2023-01-20T10:05:39.615393Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.615400Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.615406Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.615937Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.615952Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.615977Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 65
2023-01-20T10:05:39.616007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::65
2023-01-20T10:05:39.616015Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.616022Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.616028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.616558Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.616573Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.616598Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 66
2023-01-20T10:05:39.616625Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::66
2023-01-20T10:05:39.616632Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.616639Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.616645Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.617179Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.617195Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.617219Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 67
2023-01-20T10:05:39.617246Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::67
2023-01-20T10:05:39.617253Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.617260Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.617266Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.617792Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.617808Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.617833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 68
2023-01-20T10:05:39.617859Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::68
2023-01-20T10:05:39.617866Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.617873Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.617879Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.618408Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.618423Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.618448Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 69
2023-01-20T10:05:39.618475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::69
2023-01-20T10:05:39.618482Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.618489Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.618495Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.619022Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.619037Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.619061Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 70
2023-01-20T10:05:39.619088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::70
2023-01-20T10:05:39.619095Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.619102Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.619110Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.619636Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.619651Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.619676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 71
2023-01-20T10:05:39.619703Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::71
2023-01-20T10:05:39.619709Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.619716Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.619722Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.620255Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.620270Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.620294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 72
2023-01-20T10:05:39.620322Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::72
2023-01-20T10:05:39.620328Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.620336Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.620341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.620870Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.620885Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.620910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 73
2023-01-20T10:05:39.620936Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::73
2023-01-20T10:05:39.620943Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.620963Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.620969Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.621494Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.621509Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.621534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 74
2023-01-20T10:05:39.621561Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::74
2023-01-20T10:05:39.621567Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.621575Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.621580Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.622113Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.622128Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.622153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 75
2023-01-20T10:05:39.622183Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::75
2023-01-20T10:05:39.622191Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.622198Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.622204Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.622734Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.622748Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.622773Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 76
2023-01-20T10:05:39.622800Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::76
2023-01-20T10:05:39.622806Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.622813Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.622819Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.623374Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.623389Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.623413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 77
2023-01-20T10:05:39.623440Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::77
2023-01-20T10:05:39.623447Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.623454Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.623460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.623989Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.624004Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.624029Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 78
2023-01-20T10:05:39.624055Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::78
2023-01-20T10:05:39.624062Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.624069Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.624075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.624598Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.624612Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.624637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 79
2023-01-20T10:05:39.624664Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::79
2023-01-20T10:05:39.624671Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.624678Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.624684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.625225Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.625240Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.625264Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 80
2023-01-20T10:05:39.625291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::80
2023-01-20T10:05:39.625308Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.625317Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.625323Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.625857Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.625873Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.625897Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 81
2023-01-20T10:05:39.625924Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::81
2023-01-20T10:05:39.625931Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.625938Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.625944Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.626471Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.626486Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.626511Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 82
2023-01-20T10:05:39.626538Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::82
2023-01-20T10:05:39.626544Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.626551Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.626557Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.627084Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.627099Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.627124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 83
2023-01-20T10:05:39.627150Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::83
2023-01-20T10:05:39.627157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.627164Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.627170Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.627693Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.627708Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.627732Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 84
2023-01-20T10:05:39.627759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::84
2023-01-20T10:05:39.627766Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.627773Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.627779Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.628311Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.628326Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.628351Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 85
2023-01-20T10:05:39.628378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::85
2023-01-20T10:05:39.628384Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.628392Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.628397Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.628932Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.628946Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.628978Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 86
2023-01-20T10:05:39.629005Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::86
2023-01-20T10:05:39.629012Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.629019Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.629025Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.629553Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.629568Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.629593Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 87
2023-01-20T10:05:39.629620Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::87
2023-01-20T10:05:39.629627Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.629634Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.629640Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.630167Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.630182Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.630206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 88
2023-01-20T10:05:39.630234Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::88
2023-01-20T10:05:39.630241Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.630248Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.630254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.630778Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.630794Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.630819Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 89
2023-01-20T10:05:39.630845Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::89
2023-01-20T10:05:39.630852Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.630859Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.630865Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.631393Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.631408Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.631433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 90
2023-01-20T10:05:39.631459Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::90
2023-01-20T10:05:39.631466Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.631473Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.631479Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.632016Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.632031Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.632056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 91
2023-01-20T10:05:39.632083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::91
2023-01-20T10:05:39.632090Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.632097Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.632102Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.632627Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.632642Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.632667Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 92
2023-01-20T10:05:39.632693Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::92
2023-01-20T10:05:39.632700Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.632707Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.632713Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.633245Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.633260Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.633284Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 93
2023-01-20T10:05:39.633311Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::93
2023-01-20T10:05:39.633317Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.633325Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.633330Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.633854Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.633869Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.633893Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 94
2023-01-20T10:05:39.633922Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::94
2023-01-20T10:05:39.633930Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.633939Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.633945Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.634473Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.634488Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.634513Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 95
2023-01-20T10:05:39.634540Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::95
2023-01-20T10:05:39.634546Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.634553Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.634559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.635115Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.635130Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.635155Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 96
2023-01-20T10:05:39.635182Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::96
2023-01-20T10:05:39.635188Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.635196Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.635201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.635730Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.635744Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.635769Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 97
2023-01-20T10:05:39.635796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::97
2023-01-20T10:05:39.635803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.635810Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.635816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.636343Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.636358Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.636383Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 98
2023-01-20T10:05:39.636410Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::98
2023-01-20T10:05:39.636416Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.636423Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.636429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.636980Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.636996Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.637021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 99
2023-01-20T10:05:39.637048Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::99
2023-01-20T10:05:39.637054Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.637062Z  INFO evm_eth_compliance::statetest::runner: TX len : 77
2023-01-20T10:05:39.637067Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.637596Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558981,
    events_root: None,
}
2023-01-20T10:05:39.637612Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.637637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 100
2023-01-20T10:05:39.637664Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::100
2023-01-20T10:05:39.637670Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.637677Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.637683Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.638217Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.638232Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.638257Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 101
2023-01-20T10:05:39.638283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::101
2023-01-20T10:05:39.638290Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.638297Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.638303Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.638830Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.638845Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.638870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 102
2023-01-20T10:05:39.638899Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::102
2023-01-20T10:05:39.638906Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.638913Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.638919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.639449Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.639464Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.639489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 103
2023-01-20T10:05:39.639516Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::103
2023-01-20T10:05:39.639523Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.639530Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.639536Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.640068Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.640083Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.640108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 104
2023-01-20T10:05:39.640135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::104
2023-01-20T10:05:39.640141Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.640149Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.640154Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.640681Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.640697Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.640722Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 105
2023-01-20T10:05:39.640749Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::105
2023-01-20T10:05:39.640755Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.640762Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.640768Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.641306Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.641321Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.641346Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 106
2023-01-20T10:05:39.641373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::106
2023-01-20T10:05:39.641379Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.641386Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.641392Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.641921Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.641936Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.641961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 107
2023-01-20T10:05:39.641988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::107
2023-01-20T10:05:39.641995Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.642002Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.642008Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.642530Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.642545Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.642570Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 108
2023-01-20T10:05:39.642597Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::108
2023-01-20T10:05:39.642604Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.642611Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.642617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.643146Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.643161Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.643186Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 109
2023-01-20T10:05:39.643213Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::109
2023-01-20T10:05:39.643220Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.643227Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.643233Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.643756Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.643771Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.643796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 110
2023-01-20T10:05:39.643822Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::110
2023-01-20T10:05:39.643829Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.643837Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.643843Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.644381Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.644396Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.644421Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 111
2023-01-20T10:05:39.644448Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::111
2023-01-20T10:05:39.644455Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.644462Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.644468Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.644998Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.645013Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.645038Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 112
2023-01-20T10:05:39.645065Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::112
2023-01-20T10:05:39.645072Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.645079Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T10:05:39.645085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.645610Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558467,
    events_root: None,
}
2023-01-20T10:05:39.645625Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.645650Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 113
2023-01-20T10:05:39.645677Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::113
2023-01-20T10:05:39.645684Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.645691Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:05:39.645697Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.646221Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558961,
    events_root: None,
}
2023-01-20T10:05:39.646236Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.646261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 114
2023-01-20T10:05:39.646288Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::114
2023-01-20T10:05:39.646295Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.646302Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:05:39.646308Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.646832Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558961,
    events_root: None,
}
2023-01-20T10:05:39.646847Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.646872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 115
2023-01-20T10:05:39.646899Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::115
2023-01-20T10:05:39.646905Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.646913Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:05:39.646918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.647453Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558961,
    events_root: None,
}
2023-01-20T10:05:39.647468Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.647493Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 116
2023-01-20T10:05:39.647520Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::116
2023-01-20T10:05:39.647528Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.647538Z  INFO evm_eth_compliance::statetest::runner: TX len : 33
2023-01-20T10:05:39.647544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.648079Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558468,
    events_root: None,
}
2023-01-20T10:05:39.648094Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.648119Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 117
2023-01-20T10:05:39.648146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::117
2023-01-20T10:05:39.648153Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.648160Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.648166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.648693Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.648708Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.648733Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 118
2023-01-20T10:05:39.648760Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::118
2023-01-20T10:05:39.648766Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.648774Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.648780Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.649315Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.649330Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.649355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 119
2023-01-20T10:05:39.649382Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::119
2023-01-20T10:05:39.649389Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.649396Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.649402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.649931Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.649946Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.649970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 120
2023-01-20T10:05:39.649997Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::120
2023-01-20T10:05:39.650004Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.650011Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T10:05:39.650017Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.650541Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558469,
    events_root: None,
}
2023-01-20T10:05:39.650556Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.650581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 121
2023-01-20T10:05:39.650607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::121
2023-01-20T10:05:39.650614Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.650622Z  INFO evm_eth_compliance::statetest::runner: TX len : 35
2023-01-20T10:05:39.650628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.651166Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558919,
    events_root: None,
}
2023-01-20T10:05:39.651181Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.651206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 122
2023-01-20T10:05:39.651233Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::122
2023-01-20T10:05:39.651240Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.651247Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T10:05:39.651253Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.651779Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558920,
    events_root: None,
}
2023-01-20T10:05:39.651794Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.651819Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 123
2023-01-20T10:05:39.651847Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::123
2023-01-20T10:05:39.651854Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.651861Z  INFO evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T10:05:39.651867Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.652392Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558922,
    events_root: None,
}
2023-01-20T10:05:39.652407Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.652432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 124
2023-01-20T10:05:39.652458Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::124
2023-01-20T10:05:39.652465Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.652472Z  INFO evm_eth_compliance::statetest::runner: TX len : 39
2023-01-20T10:05:39.652478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.653015Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558923,
    events_root: None,
}
2023-01-20T10:05:39.653030Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.653055Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 125
2023-01-20T10:05:39.653082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::125
2023-01-20T10:05:39.653089Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.653097Z  INFO evm_eth_compliance::statetest::runner: TX len : 40
2023-01-20T10:05:39.653103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.653629Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558925,
    events_root: None,
}
2023-01-20T10:05:39.653644Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.653669Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 126
2023-01-20T10:05:39.653697Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::126
2023-01-20T10:05:39.653703Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.653710Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.653716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.654247Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.654262Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.654287Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 127
2023-01-20T10:05:39.654314Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::127
2023-01-20T10:05:39.654321Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.654328Z  INFO evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T10:05:39.654334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.654861Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558927,
    events_root: None,
}
2023-01-20T10:05:39.654876Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.654901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 128
2023-01-20T10:05:39.654930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::128
2023-01-20T10:05:39.654937Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.654944Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T10:05:39.654950Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.655473Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558931,
    events_root: None,
}
2023-01-20T10:05:39.655488Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.655513Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 129
2023-01-20T10:05:39.655540Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::129
2023-01-20T10:05:39.655547Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.655554Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:05:39.655560Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.656091Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558937,
    events_root: None,
}
2023-01-20T10:05:39.656107Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.656131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 130
2023-01-20T10:05:39.656158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::130
2023-01-20T10:05:39.656165Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.656172Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:05:39.656178Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.656704Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558937,
    events_root: None,
}
2023-01-20T10:05:39.656719Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.656744Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 131
2023-01-20T10:05:39.656773Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::131
2023-01-20T10:05:39.656782Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.656789Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T10:05:39.656795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.657347Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558934,
    events_root: None,
}
2023-01-20T10:05:39.657362Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.657387Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 132
2023-01-20T10:05:39.657414Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::132
2023-01-20T10:05:39.657420Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.657428Z  INFO evm_eth_compliance::statetest::runner: TX len : 46
2023-01-20T10:05:39.657434Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.657964Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558932,
    events_root: None,
}
2023-01-20T10:05:39.657979Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.658003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 133
2023-01-20T10:05:39.658030Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::133
2023-01-20T10:05:39.658037Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.658044Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:05:39.658050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.658574Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558929,
    events_root: None,
}
2023-01-20T10:05:39.658590Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.658615Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 134
2023-01-20T10:05:39.658641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::134
2023-01-20T10:05:39.658648Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.658655Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T10:05:39.658661Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.659188Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558933,
    events_root: None,
}
2023-01-20T10:05:39.659204Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.659228Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 135
2023-01-20T10:05:39.659255Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::135
2023-01-20T10:05:39.659262Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.659269Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.659275Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.659800Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.659814Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.659839Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 136
2023-01-20T10:05:39.659866Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::136
2023-01-20T10:05:39.659873Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.659880Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T10:05:39.659886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.660416Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558958,
    events_root: None,
}
2023-01-20T10:05:39.660431Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.660456Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 137
2023-01-20T10:05:39.660482Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::137
2023-01-20T10:05:39.660489Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.660496Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:05:39.660502Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.661033Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558937,
    events_root: None,
}
2023-01-20T10:05:39.661048Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.661072Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 138
2023-01-20T10:05:39.661100Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::138
2023-01-20T10:05:39.661107Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.661114Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:05:39.661120Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.661646Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558937,
    events_root: None,
}
2023-01-20T10:05:39.661661Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.661685Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 139
2023-01-20T10:05:39.661712Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::139
2023-01-20T10:05:39.661720Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.661727Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:05:39.661733Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.662256Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558929,
    events_root: None,
}
2023-01-20T10:05:39.662271Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.662296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 140
2023-01-20T10:05:39.662323Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::140
2023-01-20T10:05:39.662330Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.662337Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T10:05:39.662343Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.662866Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558951,
    events_root: None,
}
2023-01-20T10:05:39.662881Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.662906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 141
2023-01-20T10:05:39.662932Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::141
2023-01-20T10:05:39.662939Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.662946Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:05:39.662952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.663480Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558952,
    events_root: None,
}
2023-01-20T10:05:39.663495Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.663520Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 142
2023-01-20T10:05:39.663546Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::142
2023-01-20T10:05:39.663553Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.663561Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:05:39.663567Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.664089Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558952,
    events_root: None,
}
2023-01-20T10:05:39.664104Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.664128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 143
2023-01-20T10:05:39.664155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::143
2023-01-20T10:05:39.664162Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.664169Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:05:39.664175Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.664699Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558952,
    events_root: None,
}
2023-01-20T10:05:39.664714Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.664739Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 144
2023-01-20T10:05:39.664766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::144
2023-01-20T10:05:39.664773Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.664780Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T10:05:39.664786Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.665308Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558933,
    events_root: None,
}
2023-01-20T10:05:39.665322Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.665347Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 145
2023-01-20T10:05:39.665374Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::145
2023-01-20T10:05:39.665380Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.665388Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T10:05:39.665393Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.665906Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558934,
    events_root: None,
}
2023-01-20T10:05:39.665921Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.665946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 146
2023-01-20T10:05:39.665973Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::146
2023-01-20T10:05:39.665986Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.665994Z  INFO evm_eth_compliance::statetest::runner: TX len : 43
2023-01-20T10:05:39.666001Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.666538Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558928,
    events_root: None,
}
2023-01-20T10:05:39.666552Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.666577Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 147
2023-01-20T10:05:39.666605Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::147
2023-01-20T10:05:39.666612Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.666619Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:05:39.666625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.667151Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558929,
    events_root: None,
}
2023-01-20T10:05:39.667166Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.667191Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 148
2023-01-20T10:05:39.667218Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::148
2023-01-20T10:05:39.667224Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.667232Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T10:05:39.667237Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.667764Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558931,
    events_root: None,
}
2023-01-20T10:05:39.667779Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.667804Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 149
2023-01-20T10:05:39.667831Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::149
2023-01-20T10:05:39.667838Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.667845Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T10:05:39.667851Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.668383Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558951,
    events_root: None,
}
2023-01-20T10:05:39.668398Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.668423Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 150
2023-01-20T10:05:39.668450Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::150
2023-01-20T10:05:39.668457Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.668464Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.668470Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.669005Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.669022Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.669047Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 151
2023-01-20T10:05:39.669074Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::151
2023-01-20T10:05:39.669081Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.669089Z  INFO evm_eth_compliance::statetest::runner: TX len : 54
2023-01-20T10:05:39.669095Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.669628Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558953,
    events_root: None,
}
2023-01-20T10:05:39.669643Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.669668Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 152
2023-01-20T10:05:39.669695Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::152
2023-01-20T10:05:39.669702Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.669709Z  INFO evm_eth_compliance::statetest::runner: TX len : 56
2023-01-20T10:05:39.669715Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.670249Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558956,
    events_root: None,
}
2023-01-20T10:05:39.670264Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.670289Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 153
2023-01-20T10:05:39.670316Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::153
2023-01-20T10:05:39.670323Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.670330Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T10:05:39.670336Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.670865Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558958,
    events_root: None,
}
2023-01-20T10:05:39.670881Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.670906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 154
2023-01-20T10:05:39.670933Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::154
2023-01-20T10:05:39.670940Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.670947Z  INFO evm_eth_compliance::statetest::runner: TX len : 65
2023-01-20T10:05:39.670954Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.671479Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558967,
    events_root: None,
}
2023-01-20T10:05:39.671494Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.671519Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 155
2023-01-20T10:05:39.671546Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::155
2023-01-20T10:05:39.671553Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.671560Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.671566Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.672091Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.672106Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.672130Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 156
2023-01-20T10:05:39.672158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::156
2023-01-20T10:05:39.672165Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.672172Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.672177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.672710Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.672725Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.672750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 157
2023-01-20T10:05:39.672777Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::157
2023-01-20T10:05:39.672784Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.672791Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.672797Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.673329Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.673344Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.673369Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 158
2023-01-20T10:05:39.673395Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::158
2023-01-20T10:05:39.673402Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.673410Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.673416Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.673940Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.673957Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.673984Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 159
2023-01-20T10:05:39.674011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::159
2023-01-20T10:05:39.674018Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.674025Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.674030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.674554Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.674569Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.674594Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 160
2023-01-20T10:05:39.674621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::160
2023-01-20T10:05:39.674628Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.674635Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.674641Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.675170Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.675184Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.675210Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 161
2023-01-20T10:05:39.675236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::161
2023-01-20T10:05:39.675243Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.675251Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.675257Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.675784Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.675800Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.675824Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 162
2023-01-20T10:05:39.675851Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::162
2023-01-20T10:05:39.675858Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.675865Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.675871Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.676400Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.676415Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.676440Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 163
2023-01-20T10:05:39.676467Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::163
2023-01-20T10:05:39.676473Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.676481Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:05:39.676486Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.677025Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558950,
    events_root: None,
}
2023-01-20T10:05:39.677040Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.677065Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 164
2023-01-20T10:05:39.677092Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::164
2023-01-20T10:05:39.677099Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.677106Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:05:39.677111Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.677636Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558955,
    events_root: None,
}
2023-01-20T10:05:39.677650Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.677675Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 165
2023-01-20T10:05:39.677702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::165
2023-01-20T10:05:39.677709Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.677716Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:05:39.677722Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.678247Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558955,
    events_root: None,
}
2023-01-20T10:05:39.678262Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.678286Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 166
2023-01-20T10:05:39.678313Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::166
2023-01-20T10:05:39.678320Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.678328Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:05:39.678334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.678863Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558955,
    events_root: None,
}
2023-01-20T10:05:39.678878Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.678903Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 167
2023-01-20T10:05:39.678930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::167
2023-01-20T10:05:39.678936Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.678943Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.678949Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.679472Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.679487Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.679512Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 168
2023-01-20T10:05:39.679539Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::168
2023-01-20T10:05:39.679546Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.679553Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:05:39.679559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.680087Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558926,
    events_root: None,
}
2023-01-20T10:05:39.680102Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.680126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 169
2023-01-20T10:05:39.680153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::169
2023-01-20T10:05:39.680160Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.680168Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:05:39.680173Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.680696Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558457,
    events_root: None,
}
2023-01-20T10:05:39.680711Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.680736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 170
2023-01-20T10:05:39.680763Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid_FromEOF"::Shanghai::170
2023-01-20T10:05:39.680769Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.680776Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T10:05:39.680782Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:05:39.681318Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558467,
    events_root: None,
}
2023-01-20T10:05:39.681333Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:05:39.682991Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json"
2023-01-20T10:05:39.683340Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.140950596s
```