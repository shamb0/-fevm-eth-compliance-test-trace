> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

EIP-3541: Contract code starting with the 0xEF byte is disallowed

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json#L1167-L1168

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T10:47:55.792726Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json", Total Files :: 1
2023-01-20T10:47:55.793456Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:47:55.925869Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.374385Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T10:48:08.374594Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T10:48:08.374677Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.378084Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T10:48:08.378240Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T10:48:08.379467Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T10:48:08.379524Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::0
2023-01-20T10:48:08.379540Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.379548Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-20T10:48:08.379555Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.380166Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557545,
    events_root: None,
}
2023-01-20T10:48:08.380187Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.380227Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T10:48:08.380256Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::1
2023-01-20T10:48:08.380263Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.380270Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:48:08.380276Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.380825Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558521,
    events_root: None,
}
2023-01-20T10:48:08.380840Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.380869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T10:48:08.380895Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::2
2023-01-20T10:48:08.380902Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.380909Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:48:08.380915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.381483Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558521,
    events_root: None,
}
2023-01-20T10:48:08.381502Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.381539Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T10:48:08.381576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::3
2023-01-20T10:48:08.381587Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.381598Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:48:08.381607Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.382277Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558521,
    events_root: None,
}
2023-01-20T10:48:08.382296Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.382333Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T10:48:08.382369Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::4
2023-01-20T10:48:08.382379Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.382389Z  INFO evm_eth_compliance::statetest::runner: TX len : 2
2023-01-20T10:48:08.382397Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.383047Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557547,
    events_root: None,
}
2023-01-20T10:48:08.383066Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.383103Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T10:48:08.383138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::5
2023-01-20T10:48:08.383149Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.383160Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:48:08.383168Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.383821Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558521,
    events_root: None,
}
2023-01-20T10:48:08.383841Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.383877Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T10:48:08.383913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::6
2023-01-20T10:48:08.383924Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.383934Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:48:08.383943Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.384531Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558521,
    events_root: None,
}
2023-01-20T10:48:08.384546Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.384573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T10:48:08.384601Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::7
2023-01-20T10:48:08.384607Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.384615Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:48:08.384620Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.385167Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558521,
    events_root: None,
}
2023-01-20T10:48:08.385183Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.385209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 8
2023-01-20T10:48:08.385236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::8
2023-01-20T10:48:08.385242Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.385250Z  INFO evm_eth_compliance::statetest::runner: TX len : 3
2023-01-20T10:48:08.385256Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.385802Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557548,
    events_root: None,
}
2023-01-20T10:48:08.385817Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.385842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 9
2023-01-20T10:48:08.385870Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::9
2023-01-20T10:48:08.385877Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.385884Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T10:48:08.385892Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.386432Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557549,
    events_root: None,
}
2023-01-20T10:48:08.386447Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.386472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 10
2023-01-20T10:48:08.386500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::10
2023-01-20T10:48:08.386507Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.386514Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T10:48:08.386520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.387116Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557549,
    events_root: None,
}
2023-01-20T10:48:08.387136Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.387163Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 11
2023-01-20T10:48:08.387190Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::11
2023-01-20T10:48:08.387197Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.387204Z  INFO evm_eth_compliance::statetest::runner: TX len : 5
2023-01-20T10:48:08.387211Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.387754Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557550,
    events_root: None,
}
2023-01-20T10:48:08.387770Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.387795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 12
2023-01-20T10:48:08.387822Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::12
2023-01-20T10:48:08.387829Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.387836Z  INFO evm_eth_compliance::statetest::runner: TX len : 7
2023-01-20T10:48:08.387842Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.388399Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557553,
    events_root: None,
}
2023-01-20T10:48:08.388414Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.388440Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 13
2023-01-20T10:48:08.388467Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::13
2023-01-20T10:48:08.388474Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.388481Z  INFO evm_eth_compliance::statetest::runner: TX len : 8
2023-01-20T10:48:08.388487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.389065Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557554,
    events_root: None,
}
2023-01-20T10:48:08.389082Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.389108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 14
2023-01-20T10:48:08.389135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::14
2023-01-20T10:48:08.389141Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.389148Z  INFO evm_eth_compliance::statetest::runner: TX len : 9
2023-01-20T10:48:08.389154Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.389697Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557555,
    events_root: None,
}
2023-01-20T10:48:08.389712Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.389737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 15
2023-01-20T10:48:08.389764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::15
2023-01-20T10:48:08.389771Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.389779Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:48:08.389785Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.390323Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557556,
    events_root: None,
}
2023-01-20T10:48:08.390338Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.390363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 16
2023-01-20T10:48:08.390390Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::16
2023-01-20T10:48:08.390399Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.390406Z  INFO evm_eth_compliance::statetest::runner: TX len : 11
2023-01-20T10:48:08.390412Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.390952Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557557,
    events_root: None,
}
2023-01-20T10:48:08.390967Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.390992Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 17
2023-01-20T10:48:08.391019Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::17
2023-01-20T10:48:08.391026Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.391033Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T10:48:08.391039Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.391627Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557561,
    events_root: None,
}
2023-01-20T10:48:08.391642Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.391668Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 18
2023-01-20T10:48:08.391695Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::18
2023-01-20T10:48:08.391702Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.391709Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:48:08.391715Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.392255Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557567,
    events_root: None,
}
2023-01-20T10:48:08.392270Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.392306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 19
2023-01-20T10:48:08.392335Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::19
2023-01-20T10:48:08.392342Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.392349Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:48:08.392355Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.392900Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557567,
    events_root: None,
}
2023-01-20T10:48:08.392915Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.392941Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 20
2023-01-20T10:48:08.392979Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::20
2023-01-20T10:48:08.392986Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.392994Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T10:48:08.392999Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.393540Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557565,
    events_root: None,
}
2023-01-20T10:48:08.393556Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.393583Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 21
2023-01-20T10:48:08.393610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::21
2023-01-20T10:48:08.393617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.393624Z  INFO evm_eth_compliance::statetest::runner: TX len : 15
2023-01-20T10:48:08.393630Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.394192Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557562,
    events_root: None,
}
2023-01-20T10:48:08.394207Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.394233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 22
2023-01-20T10:48:08.394260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::22
2023-01-20T10:48:08.394267Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.394274Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:48:08.394280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.394818Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557560,
    events_root: None,
}
2023-01-20T10:48:08.394833Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.394859Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 23
2023-01-20T10:48:08.394886Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::23
2023-01-20T10:48:08.394893Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.394902Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:48:08.394908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.395446Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557567,
    events_root: None,
}
2023-01-20T10:48:08.395461Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.395486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 24
2023-01-20T10:48:08.395514Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::24
2023-01-20T10:48:08.395521Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.395528Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:48:08.395534Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.396073Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557924,
    events_root: None,
}
2023-01-20T10:48:08.396087Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.396112Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 25
2023-01-20T10:48:08.396140Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::25
2023-01-20T10:48:08.396146Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.396154Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T10:48:08.396160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.396696Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558021,
    events_root: None,
}
2023-01-20T10:48:08.396711Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.396737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 26
2023-01-20T10:48:08.396765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::26
2023-01-20T10:48:08.396772Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.396779Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:48:08.396785Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.397330Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557567,
    events_root: None,
}
2023-01-20T10:48:08.397345Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.397371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 27
2023-01-20T10:48:08.397397Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::27
2023-01-20T10:48:08.397405Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.397412Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:48:08.397418Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.397962Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557567,
    events_root: None,
}
2023-01-20T10:48:08.397977Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.398003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 28
2023-01-20T10:48:08.398031Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::28
2023-01-20T10:48:08.398037Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.398045Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:48:08.398050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.398591Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557560,
    events_root: None,
}
2023-01-20T10:48:08.398605Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.398633Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 29
2023-01-20T10:48:08.398660Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::29
2023-01-20T10:48:08.398667Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.398674Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T10:48:08.398680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.399221Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557925,
    events_root: None,
}
2023-01-20T10:48:08.399236Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.399262Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 30
2023-01-20T10:48:08.399289Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::30
2023-01-20T10:48:08.399297Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.399304Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:48:08.399310Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.399850Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557927,
    events_root: None,
}
2023-01-20T10:48:08.399865Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.399891Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 31
2023-01-20T10:48:08.399919Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::31
2023-01-20T10:48:08.399926Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.399934Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:48:08.399940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.400481Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557927,
    events_root: None,
}
2023-01-20T10:48:08.400497Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.400522Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 32
2023-01-20T10:48:08.400549Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::32
2023-01-20T10:48:08.400556Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.400563Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:48:08.400569Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.401122Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557927,
    events_root: None,
}
2023-01-20T10:48:08.401138Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.401164Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 33
2023-01-20T10:48:08.401191Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::33
2023-01-20T10:48:08.401198Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.401205Z  INFO evm_eth_compliance::statetest::runner: TX len : 16
2023-01-20T10:48:08.401211Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.401750Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557563,
    events_root: None,
}
2023-01-20T10:48:08.401765Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.401792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 34
2023-01-20T10:48:08.401819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::34
2023-01-20T10:48:08.401826Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.401834Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T10:48:08.401840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.402377Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557565,
    events_root: None,
}
2023-01-20T10:48:08.402392Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.402418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 35
2023-01-20T10:48:08.402445Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::35
2023-01-20T10:48:08.402452Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.402459Z  INFO evm_eth_compliance::statetest::runner: TX len : 12
2023-01-20T10:48:08.402465Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.403007Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557559,
    events_root: None,
}
2023-01-20T10:48:08.403023Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.403049Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 36
2023-01-20T10:48:08.403076Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::36
2023-01-20T10:48:08.403083Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.403091Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:48:08.403096Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.403637Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557560,
    events_root: None,
}
2023-01-20T10:48:08.403654Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.403679Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 37
2023-01-20T10:48:08.403706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::37
2023-01-20T10:48:08.403713Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.403720Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T10:48:08.403726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.404266Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557561,
    events_root: None,
}
2023-01-20T10:48:08.404281Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.404307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 38
2023-01-20T10:48:08.404333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::38
2023-01-20T10:48:08.404340Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.404347Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T10:48:08.404353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.404894Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557925,
    events_root: None,
}
2023-01-20T10:48:08.404910Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.404935Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 39
2023-01-20T10:48:08.404971Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::39
2023-01-20T10:48:08.404979Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.404986Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:48:08.404992Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.405533Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557924,
    events_root: None,
}
2023-01-20T10:48:08.405548Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.405573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 40
2023-01-20T10:48:08.405601Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::40
2023-01-20T10:48:08.405608Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.405615Z  INFO evm_eth_compliance::statetest::runner: TX len : 23
2023-01-20T10:48:08.405621Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.406161Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557928,
    events_root: None,
}
2023-01-20T10:48:08.406176Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.406202Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 41
2023-01-20T10:48:08.406229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::41
2023-01-20T10:48:08.406236Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.406243Z  INFO evm_eth_compliance::statetest::runner: TX len : 25
2023-01-20T10:48:08.406249Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.406791Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558019,
    events_root: None,
}
2023-01-20T10:48:08.406806Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.406833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 42
2023-01-20T10:48:08.406860Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::42
2023-01-20T10:48:08.406868Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.406875Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T10:48:08.406881Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.407420Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558021,
    events_root: None,
}
2023-01-20T10:48:08.407435Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.407460Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 43
2023-01-20T10:48:08.407488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::43
2023-01-20T10:48:08.407495Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.407502Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T10:48:08.407508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.408048Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558029,
    events_root: None,
}
2023-01-20T10:48:08.408063Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.408089Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 44
2023-01-20T10:48:08.408116Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::44
2023-01-20T10:48:08.408123Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.408130Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:48:08.408136Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.408679Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557556,
    events_root: None,
}
2023-01-20T10:48:08.408695Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.408720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 45
2023-01-20T10:48:08.408747Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::45
2023-01-20T10:48:08.408754Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.408761Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:48:08.408767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.409314Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557556,
    events_root: None,
}
2023-01-20T10:48:08.409329Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.409354Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 46
2023-01-20T10:48:08.409382Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::46
2023-01-20T10:48:08.409389Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.409396Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:48:08.409402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.409942Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557556,
    events_root: None,
}
2023-01-20T10:48:08.409957Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.409983Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 47
2023-01-20T10:48:08.410011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::47
2023-01-20T10:48:08.410018Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.410025Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:48:08.410031Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.410570Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557924,
    events_root: None,
}
2023-01-20T10:48:08.410585Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.410611Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 48
2023-01-20T10:48:08.410640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::48
2023-01-20T10:48:08.410649Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.410657Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:48:08.410663Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.411205Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557924,
    events_root: None,
}
2023-01-20T10:48:08.411220Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.411245Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 49
2023-01-20T10:48:08.411273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::49
2023-01-20T10:48:08.411280Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.411287Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:48:08.411293Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.411836Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557924,
    events_root: None,
}
2023-01-20T10:48:08.411851Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.411879Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 50
2023-01-20T10:48:08.411906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::50
2023-01-20T10:48:08.411913Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.411920Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:48:08.411926Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.412466Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557924,
    events_root: None,
}
2023-01-20T10:48:08.412481Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.412506Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 51
2023-01-20T10:48:08.412533Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::51
2023-01-20T10:48:08.412541Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.412548Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:48:08.412554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.413106Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557924,
    events_root: None,
}
2023-01-20T10:48:08.413121Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.413146Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 52
2023-01-20T10:48:08.413174Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::52
2023-01-20T10:48:08.413182Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.413189Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:48:08.413195Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.413735Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557924,
    events_root: None,
}
2023-01-20T10:48:08.413749Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.413783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 53
2023-01-20T10:48:08.413816Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::53
2023-01-20T10:48:08.413824Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.413832Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:48:08.413838Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.414382Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558017,
    events_root: None,
}
2023-01-20T10:48:08.414397Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.414422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 54
2023-01-20T10:48:08.414449Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::54
2023-01-20T10:48:08.414456Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.414463Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:48:08.414469Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.415008Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558017,
    events_root: None,
}
2023-01-20T10:48:08.415023Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.415050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 55
2023-01-20T10:48:08.415077Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::55
2023-01-20T10:48:08.415084Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.415092Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:48:08.415097Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.415637Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558017,
    events_root: None,
}
2023-01-20T10:48:08.415653Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.415678Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 56
2023-01-20T10:48:08.415705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::56
2023-01-20T10:48:08.415712Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.415719Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.415725Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.416265Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.416281Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.416306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 57
2023-01-20T10:48:08.416334Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::57
2023-01-20T10:48:08.416341Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.416348Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:48:08.416354Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.416894Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1557556,
    events_root: None,
}
2023-01-20T10:48:08.416909Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.416935Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 58
2023-01-20T10:48:08.416971Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::58
2023-01-20T10:48:08.416979Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.416986Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.416993Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.417534Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.417549Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.417574Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 59
2023-01-20T10:48:08.417601Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::59
2023-01-20T10:48:08.417609Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.417616Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.417622Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.418163Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.418177Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.418203Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 60
2023-01-20T10:48:08.418232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::60
2023-01-20T10:48:08.418239Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.418246Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.418252Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.418792Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.418807Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.418833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 61
2023-01-20T10:48:08.418860Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::61
2023-01-20T10:48:08.418867Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.418874Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.418880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.419420Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.419435Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.419461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 62
2023-01-20T10:48:08.419487Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::62
2023-01-20T10:48:08.419495Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.419502Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.419508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.420052Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.420067Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.420094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 63
2023-01-20T10:48:08.420122Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::63
2023-01-20T10:48:08.420129Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.420136Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.420142Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.420682Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.420697Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.420723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 64
2023-01-20T10:48:08.420750Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::64
2023-01-20T10:48:08.420757Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.420764Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.420770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.421319Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.421335Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.421361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 65
2023-01-20T10:48:08.421388Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::65
2023-01-20T10:48:08.421397Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.421404Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.421410Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.421952Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.421967Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.421992Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 66
2023-01-20T10:48:08.422020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::66
2023-01-20T10:48:08.422027Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.422034Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.422040Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.422579Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.422594Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.422620Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 67
2023-01-20T10:48:08.422647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::67
2023-01-20T10:48:08.422653Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.422661Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.422667Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.423206Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.423221Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.423247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 68
2023-01-20T10:48:08.423275Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::68
2023-01-20T10:48:08.423283Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.423290Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.423296Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.423842Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.423856Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.423881Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 69
2023-01-20T10:48:08.423909Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::69
2023-01-20T10:48:08.423916Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.423923Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.423929Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.424469Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.424484Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.424510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 70
2023-01-20T10:48:08.424537Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::70
2023-01-20T10:48:08.424543Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.424551Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.424556Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.425109Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.425125Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.425151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 71
2023-01-20T10:48:08.425178Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::71
2023-01-20T10:48:08.425185Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.425192Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.425198Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.425739Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.425754Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.425779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 72
2023-01-20T10:48:08.425806Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::72
2023-01-20T10:48:08.425813Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.425820Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.425826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.426365Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.426380Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.426406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 73
2023-01-20T10:48:08.426435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::73
2023-01-20T10:48:08.426442Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.426449Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.426455Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.426995Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.427011Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.427036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 74
2023-01-20T10:48:08.427063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::74
2023-01-20T10:48:08.427071Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.427078Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.427084Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.427624Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.427639Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.427664Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 75
2023-01-20T10:48:08.427692Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::75
2023-01-20T10:48:08.427699Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.427706Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.427712Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.428251Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.428266Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.428294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 76
2023-01-20T10:48:08.428321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::76
2023-01-20T10:48:08.428327Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.428335Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.428341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.428882Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.428897Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.428922Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 77
2023-01-20T10:48:08.428956Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::77
2023-01-20T10:48:08.428966Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.428975Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.428983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.429546Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.429561Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.429587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 78
2023-01-20T10:48:08.429615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::78
2023-01-20T10:48:08.429622Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.429630Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.429636Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.430175Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.430191Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.430216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 79
2023-01-20T10:48:08.430244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::79
2023-01-20T10:48:08.430251Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.430258Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.430264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.430804Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.430819Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.430844Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 80
2023-01-20T10:48:08.430872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::80
2023-01-20T10:48:08.430879Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.430886Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.430892Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.431433Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.431448Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.431476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 81
2023-01-20T10:48:08.431503Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::81
2023-01-20T10:48:08.431510Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.431517Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.431524Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.432062Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.432078Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.432103Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 82
2023-01-20T10:48:08.432131Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::82
2023-01-20T10:48:08.432138Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.432145Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.432151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.432690Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.432705Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.432731Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 83
2023-01-20T10:48:08.432758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::83
2023-01-20T10:48:08.432765Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.432772Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.432778Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.433327Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.433342Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.433369Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 84
2023-01-20T10:48:08.433396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::84
2023-01-20T10:48:08.433403Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.433410Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.433417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.433957Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.433973Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.433998Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 85
2023-01-20T10:48:08.434026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::85
2023-01-20T10:48:08.434033Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.434040Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.434046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.434586Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.434601Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.434627Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 86
2023-01-20T10:48:08.434656Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::86
2023-01-20T10:48:08.434663Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.434670Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.434676Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.435215Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.435230Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.435256Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 87
2023-01-20T10:48:08.435283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::87
2023-01-20T10:48:08.435290Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.435297Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.435303Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.435844Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.435860Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.435885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 88
2023-01-20T10:48:08.435912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::88
2023-01-20T10:48:08.435920Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.435927Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.435933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.436473Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.436488Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.436514Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 89
2023-01-20T10:48:08.436542Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::89
2023-01-20T10:48:08.436549Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.436556Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.436562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.437109Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.437124Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.437151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 90
2023-01-20T10:48:08.437178Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::90
2023-01-20T10:48:08.437184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.437192Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.437199Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.437739Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.437755Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.437781Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 91
2023-01-20T10:48:08.437808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::91
2023-01-20T10:48:08.437815Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.437823Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.437829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.438369Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.438384Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.438410Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 92
2023-01-20T10:48:08.438437Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::92
2023-01-20T10:48:08.438444Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.438451Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.438457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.439001Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.439016Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.439042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 93
2023-01-20T10:48:08.439069Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::93
2023-01-20T10:48:08.439076Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.439083Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.439090Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.439627Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.439643Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.439669Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 94
2023-01-20T10:48:08.439697Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::94
2023-01-20T10:48:08.439705Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.439712Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.439718Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.440259Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.440274Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.440299Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 95
2023-01-20T10:48:08.440327Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::95
2023-01-20T10:48:08.440334Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.440341Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.440347Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.440885Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.440900Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.440926Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 96
2023-01-20T10:48:08.440972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::96
2023-01-20T10:48:08.440980Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.440987Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.440993Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.441536Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.441551Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.441577Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 97
2023-01-20T10:48:08.441604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::97
2023-01-20T10:48:08.441611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.441618Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.441624Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.442164Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.442179Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.442205Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 98
2023-01-20T10:48:08.442232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::98
2023-01-20T10:48:08.442239Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.442246Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.442252Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.442791Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.442807Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.442833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 99
2023-01-20T10:48:08.442861Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::99
2023-01-20T10:48:08.442868Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.442876Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.442882Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.443421Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.443436Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.443461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 100
2023-01-20T10:48:08.443489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::100
2023-01-20T10:48:08.443496Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.443503Z  INFO evm_eth_compliance::statetest::runner: TX len : 77
2023-01-20T10:48:08.443509Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.444047Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558541,
    events_root: None,
}
2023-01-20T10:48:08.444062Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.444088Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 101
2023-01-20T10:48:08.444115Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::101
2023-01-20T10:48:08.444122Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.444129Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.444135Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.444674Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.444688Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.444714Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 102
2023-01-20T10:48:08.444741Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::102
2023-01-20T10:48:08.444748Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.444755Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.444761Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.445327Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.445342Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.445367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 103
2023-01-20T10:48:08.445394Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::103
2023-01-20T10:48:08.445401Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.445408Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.445414Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.445955Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.445970Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.445996Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 104
2023-01-20T10:48:08.446022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::104
2023-01-20T10:48:08.446029Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.446036Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.446042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.446581Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.446596Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.446621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 105
2023-01-20T10:48:08.446648Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::105
2023-01-20T10:48:08.446655Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.446663Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.446669Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.447208Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.447223Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.447248Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 106
2023-01-20T10:48:08.447276Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::106
2023-01-20T10:48:08.447283Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.447290Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.447296Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.447832Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.447848Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.447873Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 107
2023-01-20T10:48:08.447902Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::107
2023-01-20T10:48:08.447909Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.447916Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.447922Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.448457Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.448472Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.448498Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 108
2023-01-20T10:48:08.448525Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::108
2023-01-20T10:48:08.448532Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.448539Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.448545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.449093Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.449108Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.449134Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 109
2023-01-20T10:48:08.449162Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::109
2023-01-20T10:48:08.449169Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.449176Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.449182Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.449721Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.449736Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.449761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 110
2023-01-20T10:48:08.449788Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::110
2023-01-20T10:48:08.449795Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.449802Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.449808Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.450344Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.450359Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.450385Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 111
2023-01-20T10:48:08.450412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::111
2023-01-20T10:48:08.450418Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.450426Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.450431Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.450968Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.450983Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.451009Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 112
2023-01-20T10:48:08.451036Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::112
2023-01-20T10:48:08.451043Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.451051Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.451057Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.451596Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.451612Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.451637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 113
2023-01-20T10:48:08.451665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::113
2023-01-20T10:48:08.451672Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.451679Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T10:48:08.451685Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.452221Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558027,
    events_root: None,
}
2023-01-20T10:48:08.452236Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.452262Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 114
2023-01-20T10:48:08.452289Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::114
2023-01-20T10:48:08.452296Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.452303Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:48:08.452309Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.452847Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558521,
    events_root: None,
}
2023-01-20T10:48:08.452862Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.452888Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 115
2023-01-20T10:48:08.452917Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::115
2023-01-20T10:48:08.452924Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.452931Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:48:08.452937Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.453483Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558521,
    events_root: None,
}
2023-01-20T10:48:08.453499Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.453524Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 116
2023-01-20T10:48:08.453551Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::116
2023-01-20T10:48:08.453559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.453566Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:48:08.453572Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.454111Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558521,
    events_root: None,
}
2023-01-20T10:48:08.454127Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.454152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 117
2023-01-20T10:48:08.454180Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::117
2023-01-20T10:48:08.454186Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.454194Z  INFO evm_eth_compliance::statetest::runner: TX len : 33
2023-01-20T10:48:08.454200Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.454742Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558028,
    events_root: None,
}
2023-01-20T10:48:08.454757Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.454783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 118
2023-01-20T10:48:08.454809Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::118
2023-01-20T10:48:08.454816Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.454823Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.454829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.455362Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.455376Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.455402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 119
2023-01-20T10:48:08.455429Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::119
2023-01-20T10:48:08.455436Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.455443Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.455450Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.455981Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.455997Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.456022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 120
2023-01-20T10:48:08.456049Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::120
2023-01-20T10:48:08.456056Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.456064Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.456069Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.456606Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.456621Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.456646Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 121
2023-01-20T10:48:08.456674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::121
2023-01-20T10:48:08.456680Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.456687Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T10:48:08.456693Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.457234Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558029,
    events_root: None,
}
2023-01-20T10:48:08.457249Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.457274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 122
2023-01-20T10:48:08.457302Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::122
2023-01-20T10:48:08.457308Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.457316Z  INFO evm_eth_compliance::statetest::runner: TX len : 35
2023-01-20T10:48:08.457321Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.457861Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558479,
    events_root: None,
}
2023-01-20T10:48:08.457876Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.457902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 123
2023-01-20T10:48:08.457929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::123
2023-01-20T10:48:08.457938Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.457945Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T10:48:08.457952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.458489Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558480,
    events_root: None,
}
2023-01-20T10:48:08.458504Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.458530Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 124
2023-01-20T10:48:08.458557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::124
2023-01-20T10:48:08.458564Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.458572Z  INFO evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T10:48:08.458578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.459116Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558482,
    events_root: None,
}
2023-01-20T10:48:08.459131Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.459156Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 125
2023-01-20T10:48:08.459184Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::125
2023-01-20T10:48:08.459191Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.459198Z  INFO evm_eth_compliance::statetest::runner: TX len : 39
2023-01-20T10:48:08.459204Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.459743Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558483,
    events_root: None,
}
2023-01-20T10:48:08.459757Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.459784Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 126
2023-01-20T10:48:08.459811Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::126
2023-01-20T10:48:08.459818Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.459825Z  INFO evm_eth_compliance::statetest::runner: TX len : 40
2023-01-20T10:48:08.459831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.460368Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558485,
    events_root: None,
}
2023-01-20T10:48:08.460384Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.460409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 127
2023-01-20T10:48:08.460436Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::127
2023-01-20T10:48:08.460443Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.460451Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.460457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.461000Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.461015Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.461041Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 128
2023-01-20T10:48:08.461069Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::128
2023-01-20T10:48:08.461076Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.461083Z  INFO evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T10:48:08.461089Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.461625Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558487,
    events_root: None,
}
2023-01-20T10:48:08.461641Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.461666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 129
2023-01-20T10:48:08.461698Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::129
2023-01-20T10:48:08.461705Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.461712Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T10:48:08.461718Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.462250Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558491,
    events_root: None,
}
2023-01-20T10:48:08.462264Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.462291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 130
2023-01-20T10:48:08.462317Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::130
2023-01-20T10:48:08.462324Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.462331Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:48:08.462337Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.462870Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558497,
    events_root: None,
}
2023-01-20T10:48:08.462886Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.462912Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 131
2023-01-20T10:48:08.462939Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::131
2023-01-20T10:48:08.462946Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.462953Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:48:08.462961Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.463493Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558497,
    events_root: None,
}
2023-01-20T10:48:08.463509Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.463534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 132
2023-01-20T10:48:08.463560Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::132
2023-01-20T10:48:08.463568Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.463575Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T10:48:08.463581Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.464116Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558494,
    events_root: None,
}
2023-01-20T10:48:08.464130Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.464155Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 133
2023-01-20T10:48:08.464183Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::133
2023-01-20T10:48:08.464190Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.464197Z  INFO evm_eth_compliance::statetest::runner: TX len : 46
2023-01-20T10:48:08.464203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.464739Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558492,
    events_root: None,
}
2023-01-20T10:48:08.464754Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.464778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 134
2023-01-20T10:48:08.464806Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::134
2023-01-20T10:48:08.464813Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.464820Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:48:08.464826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.465368Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558489,
    events_root: None,
}
2023-01-20T10:48:08.465383Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.465409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 135
2023-01-20T10:48:08.465435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::135
2023-01-20T10:48:08.465442Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.465449Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T10:48:08.465456Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.465989Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558493,
    events_root: None,
}
2023-01-20T10:48:08.466004Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.466029Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 136
2023-01-20T10:48:08.466056Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::136
2023-01-20T10:48:08.466063Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.466071Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.466077Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.466612Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.466628Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.466653Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 137
2023-01-20T10:48:08.466680Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::137
2023-01-20T10:48:08.466687Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.466694Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T10:48:08.466700Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.467234Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558518,
    events_root: None,
}
2023-01-20T10:48:08.467249Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.467274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 138
2023-01-20T10:48:08.467301Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::138
2023-01-20T10:48:08.467308Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.467315Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:48:08.467321Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.467861Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558497,
    events_root: None,
}
2023-01-20T10:48:08.467876Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.467902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 139
2023-01-20T10:48:08.467929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::139
2023-01-20T10:48:08.467936Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.467943Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:48:08.467949Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.468487Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558497,
    events_root: None,
}
2023-01-20T10:48:08.468502Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.468528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 140
2023-01-20T10:48:08.468555Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::140
2023-01-20T10:48:08.468562Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.468570Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:48:08.468576Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.469122Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558489,
    events_root: None,
}
2023-01-20T10:48:08.469137Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.469163Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 141
2023-01-20T10:48:08.469190Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::141
2023-01-20T10:48:08.469197Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.469204Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T10:48:08.469210Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.469749Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558511,
    events_root: None,
}
2023-01-20T10:48:08.469764Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.469790Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 142
2023-01-20T10:48:08.469817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::142
2023-01-20T10:48:08.469823Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.469831Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:48:08.469837Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.470376Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558512,
    events_root: None,
}
2023-01-20T10:48:08.470390Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.470417Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 143
2023-01-20T10:48:08.470444Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::143
2023-01-20T10:48:08.470450Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.470457Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:48:08.470464Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.471007Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558512,
    events_root: None,
}
2023-01-20T10:48:08.471023Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.471048Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 144
2023-01-20T10:48:08.471076Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::144
2023-01-20T10:48:08.471083Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.471090Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:48:08.471096Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.471635Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558512,
    events_root: None,
}
2023-01-20T10:48:08.471651Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.471676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 145
2023-01-20T10:48:08.471704Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::145
2023-01-20T10:48:08.471710Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.471718Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T10:48:08.471724Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.472259Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558493,
    events_root: None,
}
2023-01-20T10:48:08.472274Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.472300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 146
2023-01-20T10:48:08.472327Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::146
2023-01-20T10:48:08.472334Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.472341Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T10:48:08.472347Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.472883Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558494,
    events_root: None,
}
2023-01-20T10:48:08.472898Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.472924Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 147
2023-01-20T10:48:08.472957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::147
2023-01-20T10:48:08.472965Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.472972Z  INFO evm_eth_compliance::statetest::runner: TX len : 43
2023-01-20T10:48:08.472978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.473516Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558488,
    events_root: None,
}
2023-01-20T10:48:08.473531Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.473556Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 148
2023-01-20T10:48:08.473584Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::148
2023-01-20T10:48:08.473591Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.473598Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:48:08.473604Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.474141Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558489,
    events_root: None,
}
2023-01-20T10:48:08.474156Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.474181Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 149
2023-01-20T10:48:08.474209Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::149
2023-01-20T10:48:08.474215Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.474222Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T10:48:08.474228Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.474764Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558491,
    events_root: None,
}
2023-01-20T10:48:08.474779Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.474805Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 150
2023-01-20T10:48:08.474832Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::150
2023-01-20T10:48:08.474839Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.474846Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T10:48:08.474852Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.475390Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558511,
    events_root: None,
}
2023-01-20T10:48:08.475406Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.475431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 151
2023-01-20T10:48:08.475458Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::151
2023-01-20T10:48:08.475465Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.475472Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.475478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.476016Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.476030Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.476055Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 152
2023-01-20T10:48:08.476083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::152
2023-01-20T10:48:08.476090Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.476097Z  INFO evm_eth_compliance::statetest::runner: TX len : 54
2023-01-20T10:48:08.476103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.476642Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558513,
    events_root: None,
}
2023-01-20T10:48:08.476657Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.476682Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 153
2023-01-20T10:48:08.476710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::153
2023-01-20T10:48:08.476717Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.476724Z  INFO evm_eth_compliance::statetest::runner: TX len : 56
2023-01-20T10:48:08.476730Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.477280Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558516,
    events_root: None,
}
2023-01-20T10:48:08.477296Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.477321Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 154
2023-01-20T10:48:08.477348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::154
2023-01-20T10:48:08.477355Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.477363Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T10:48:08.477369Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.477906Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558518,
    events_root: None,
}
2023-01-20T10:48:08.477921Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.477946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 155
2023-01-20T10:48:08.477974Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::155
2023-01-20T10:48:08.477981Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.477988Z  INFO evm_eth_compliance::statetest::runner: TX len : 65
2023-01-20T10:48:08.477994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.478531Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558527,
    events_root: None,
}
2023-01-20T10:48:08.478546Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.478571Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 156
2023-01-20T10:48:08.478599Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::156
2023-01-20T10:48:08.478606Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.478613Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.478619Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.479159Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.479173Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.479199Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 157
2023-01-20T10:48:08.479226Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::157
2023-01-20T10:48:08.479233Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.479241Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.479247Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.479790Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.479806Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.479831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 158
2023-01-20T10:48:08.479858Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::158
2023-01-20T10:48:08.479865Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.479873Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.479879Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.480416Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.480431Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.480456Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 159
2023-01-20T10:48:08.480484Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::159
2023-01-20T10:48:08.480490Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.480498Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.480504Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.481055Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.481072Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.481104Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 160
2023-01-20T10:48:08.481137Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::160
2023-01-20T10:48:08.481146Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.481155Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.481163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.481705Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.481720Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.481745Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 161
2023-01-20T10:48:08.481772Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::161
2023-01-20T10:48:08.481779Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.481786Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.481792Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.482328Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.482343Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.482370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 162
2023-01-20T10:48:08.482397Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::162
2023-01-20T10:48:08.482403Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.482411Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.482417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.482952Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.482967Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.482993Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 163
2023-01-20T10:48:08.483020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::163
2023-01-20T10:48:08.483027Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.483035Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.483041Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.483579Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.483594Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.483619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 164
2023-01-20T10:48:08.483647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::164
2023-01-20T10:48:08.483654Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.483661Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:48:08.483667Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.484203Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558510,
    events_root: None,
}
2023-01-20T10:48:08.484218Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.484243Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 165
2023-01-20T10:48:08.484271Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::165
2023-01-20T10:48:08.484278Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.484285Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:48:08.484291Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.484827Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558515,
    events_root: None,
}
2023-01-20T10:48:08.484842Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.484868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 166
2023-01-20T10:48:08.484895Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::166
2023-01-20T10:48:08.484902Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.484909Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:48:08.484915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.485461Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558515,
    events_root: None,
}
2023-01-20T10:48:08.485476Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.485501Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 167
2023-01-20T10:48:08.485528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::167
2023-01-20T10:48:08.485536Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.485543Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:48:08.485549Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.486086Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558515,
    events_root: None,
}
2023-01-20T10:48:08.486101Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.486126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 168
2023-01-20T10:48:08.486154Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::168
2023-01-20T10:48:08.486161Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.486168Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:48:08.486174Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.486711Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558017,
    events_root: None,
}
2023-01-20T10:48:08.486726Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.486751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 169
2023-01-20T10:48:08.486779Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::169
2023-01-20T10:48:08.486786Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.486794Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T10:48:08.486799Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.487343Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558027,
    events_root: None,
}
2023-01-20T10:48:08.487358Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.487384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 170
2023-01-20T10:48:08.487411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::170
2023-01-20T10:48:08.487418Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.487425Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.487432Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.487969Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.487984Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.488010Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 171
2023-01-20T10:48:08.488037Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid_FromEOF"::Shanghai::171
2023-01-20T10:48:08.488044Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.488051Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:48:08.488057Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T10:48:08.488589Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 23,
    },
    return_data: RawBytes {  },
    gas_used: 1558486,
    events_root: None,
}
2023-01-20T10:48:08.488603Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-20T10:48:08.490903Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid_FromEOF.json"
2023-01-20T10:48:08.491253Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.562791434s
```