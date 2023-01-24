> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stZeroCallsRevert

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stZeroCallsRevert \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Belo use-cases, hit with `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-54-05 | stZeroCallsRevert/ZeroValue_CALLCODE_OOGRevert |
| TID-54-06 | stZeroCallsRevert/ZeroValue_CALLCODE_ToEmpty_OOGRevert |
| TID-54-07 | stZeroCallsRevert/ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert |
| TID-54-08 | stZeroCallsRevert/ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert |

> Execution Trace

```
2023-01-24T09:05:28.739345Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stZeroCallsRevert", Total Files :: 16
2023-01-24T09:05:28.739596Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_OOGRevert.json"
2023-01-24T09:05:28.767436Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:28.767625Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:28.767628Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:28.767687Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:28.767758Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:28.767761Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_OOGRevert"::Istanbul::0
2023-01-24T09:05:28.767764Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_OOGRevert.json"
2023-01-24T09:05:28.767768Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:28.767769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.131792Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.131809Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.131824Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:29.131831Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_OOGRevert"::Berlin::0
2023-01-24T09:05:29.131833Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_OOGRevert.json"
2023-01-24T09:05:29.131836Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.131837Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.131963Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.131968Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.131977Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:29.131979Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_OOGRevert"::London::0
2023-01-24T09:05:29.131981Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_OOGRevert.json"
2023-01-24T09:05:29.131983Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.131985Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.132079Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.132084Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.132093Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:29.132095Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_OOGRevert"::Merge::0
2023-01-24T09:05:29.132097Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_OOGRevert.json"
2023-01-24T09:05:29.132099Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.132101Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.132201Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.132206Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.133773Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_OOGRevert.json"
2023-01-24T09:05:29.133806Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:29.159594Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:29.159708Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:29.159711Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:29.159764Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:29.159766Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:29.159824Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:29.159895Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:29.159900Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToEmpty_OOGRevert"::Istanbul::0
2023-01-24T09:05:29.159903Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:29.159906Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.159908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.541325Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.541343Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.541356Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:29.541363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToEmpty_OOGRevert"::Berlin::0
2023-01-24T09:05:29.541365Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:29.541368Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.541369Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.541479Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.541484Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.541493Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:29.541496Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToEmpty_OOGRevert"::London::0
2023-01-24T09:05:29.541498Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:29.541501Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.541502Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.541594Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.541598Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.541607Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:29.541609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToEmpty_OOGRevert"::Merge::0
2023-01-24T09:05:29.541611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:29.541614Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.541615Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.541704Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.541709Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.543150Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:29.543178Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:29.569634Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:29.569769Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:29.569773Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:29.569831Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:29.569833Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:29.569897Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:29.569981Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:29.569987Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert"::Istanbul::0
2023-01-24T09:05:29.569991Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:29.569994Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.569995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.910668Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.910687Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.910701Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:29.910709Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert"::Berlin::0
2023-01-24T09:05:29.910711Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:29.910714Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.910716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.910822Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.910828Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.910837Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:29.910840Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert"::London::0
2023-01-24T09:05:29.910842Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:29.910845Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.910846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.910935Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.910940Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.910948Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:29.910951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert"::Merge::0
2023-01-24T09:05:29.910953Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:29.910956Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.910957Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:29.911043Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:29.911048Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:29.912156Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:29.912186Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:29.936085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:29.936187Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:29.936191Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:29.936243Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:29.936245Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:29.936302Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:29.936375Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:29.936379Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert"::Istanbul::0
2023-01-24T09:05:29.936383Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:29.936386Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:29.936388Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:30.293345Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:30.293364Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:30.293378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:30.293384Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert"::Berlin::0
2023-01-24T09:05:30.293386Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:30.293389Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:30.293390Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:30.293503Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:30.293508Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:30.293517Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:30.293520Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert"::London::0
2023-01-24T09:05:30.293522Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:30.293525Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:30.293526Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:30.293619Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:30.293624Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:30.293633Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:30.293635Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert"::Merge::0
2023-01-24T09:05:30.293637Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:30.293640Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:30.293642Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:30.293733Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1572976,
    events_root: None,
}
2023-01-24T09:05:30.293737Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=38): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T09:05:30.294995Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALLCODE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:30.295023Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_OOGRevert.json"
2023-01-24T09:05:30.321107Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:30.321220Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:30.321224Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:30.321281Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:30.321354Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:30.321359Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_OOGRevert"::Istanbul::0
2023-01-24T09:05:30.321362Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_OOGRevert.json"
2023-01-24T09:05:30.321365Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:30.321366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:30.700335Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4992600,
    events_root: None,
}
2023-01-24T09:05:30.700362Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:30.700374Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_OOGRevert"::Berlin::0
2023-01-24T09:05:30.700378Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_OOGRevert.json"
2023-01-24T09:05:30.700382Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:30.700385Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:30.700712Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5604216,
    events_root: None,
}
2023-01-24T09:05:30.700725Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:30.700729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_OOGRevert"::London::0
2023-01-24T09:05:30.700732Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_OOGRevert.json"
2023-01-24T09:05:30.700736Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:30.700738Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:30.701022Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4673658,
    events_root: None,
}
2023-01-24T09:05:30.701034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:30.701038Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_OOGRevert"::Merge::0
2023-01-24T09:05:30.701042Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_OOGRevert.json"
2023-01-24T09:05:30.701046Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:30.701048Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:30.701302Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3179687,
    events_root: None,
}
2023-01-24T09:05:30.702670Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_OOGRevert.json"
2023-01-24T09:05:30.702702Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:30.728061Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:30.728166Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:30.728169Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:30.728222Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:30.728224Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:30.728285Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:30.728359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:30.728364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToEmpty_OOGRevert"::Istanbul::0
2023-01-24T09:05:30.728367Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:30.728371Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:30.728373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.082343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5549721,
    events_root: None,
}
2023-01-24T09:05:31.082368Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:31.082374Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToEmpty_OOGRevert"::Berlin::0
2023-01-24T09:05:31.082377Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:31.082380Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.082381Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.082645Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6574770,
    events_root: None,
}
2023-01-24T09:05:31.082657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:31.082659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToEmpty_OOGRevert"::London::0
2023-01-24T09:05:31.082661Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:31.082664Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.082666Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.082849Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4594736,
    events_root: None,
}
2023-01-24T09:05:31.082860Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:31.082863Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToEmpty_OOGRevert"::Merge::0
2023-01-24T09:05:31.082865Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:31.082867Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.082869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.083035Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3102925,
    events_root: None,
}
2023-01-24T09:05:31.084169Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:31.084202Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:31.108856Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:31.108964Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:31.108967Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:31.109021Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:31.109023Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:31.109082Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:31.109154Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:31.109158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToNonZeroBalance_OOGRevert"::Istanbul::0
2023-01-24T09:05:31.109161Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:31.109165Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.109166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.476094Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5549721,
    events_root: None,
}
2023-01-24T09:05:31.476117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:31.476123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToNonZeroBalance_OOGRevert"::Berlin::0
2023-01-24T09:05:31.476126Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:31.476129Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.476130Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.476363Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6574770,
    events_root: None,
}
2023-01-24T09:05:31.476373Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:31.476376Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToNonZeroBalance_OOGRevert"::London::0
2023-01-24T09:05:31.476378Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:31.476381Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.476382Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.476569Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4594736,
    events_root: None,
}
2023-01-24T09:05:31.476578Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:31.476581Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToNonZeroBalance_OOGRevert"::Merge::0
2023-01-24T09:05:31.476584Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:31.476586Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.476588Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.476755Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3102925,
    events_root: None,
}
2023-01-24T09:05:31.478125Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:31.478156Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:31.502947Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:31.503052Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:31.503055Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:31.503108Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:31.503110Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:31.503166Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:31.503238Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:31.503244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToOneStorageKey_OOGRevert"::Istanbul::0
2023-01-24T09:05:31.503247Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:31.503250Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.503251Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.850021Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5549721,
    events_root: None,
}
2023-01-24T09:05:31.850045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:31.850052Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToOneStorageKey_OOGRevert"::Berlin::0
2023-01-24T09:05:31.850055Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:31.850058Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.850060Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.850290Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6574770,
    events_root: None,
}
2023-01-24T09:05:31.850300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:31.850303Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToOneStorageKey_OOGRevert"::London::0
2023-01-24T09:05:31.850305Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:31.850308Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.850310Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.850560Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4594736,
    events_root: None,
}
2023-01-24T09:05:31.850571Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:31.850575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_CALL_ToOneStorageKey_OOGRevert"::Merge::0
2023-01-24T09:05:31.850578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:31.850582Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.850584Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:31.850753Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3102925,
    events_root: None,
}
2023-01-24T09:05:31.851907Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_CALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:31.851939Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_OOGRevert.json"
2023-01-24T09:05:31.877663Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:31.877769Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:31.877772Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:31.877825Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:31.877896Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:31.877900Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_OOGRevert"::Istanbul::0
2023-01-24T09:05:31.877903Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_OOGRevert.json"
2023-01-24T09:05:31.877906Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:31.877908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.214950Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4992106,
    events_root: None,
}
2023-01-24T09:05:32.214973Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:32.214978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_OOGRevert"::Berlin::0
2023-01-24T09:05:32.214981Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_OOGRevert.json"
2023-01-24T09:05:32.214984Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.214985Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.215216Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5602214,
    events_root: None,
}
2023-01-24T09:05:32.215224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:32.215227Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_OOGRevert"::London::0
2023-01-24T09:05:32.215229Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_OOGRevert.json"
2023-01-24T09:05:32.215232Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.215233Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.215415Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4672496,
    events_root: None,
}
2023-01-24T09:05:32.215424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:32.215426Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_OOGRevert"::Merge::0
2023-01-24T09:05:32.215428Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_OOGRevert.json"
2023-01-24T09:05:32.215431Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.215433Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.215591Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3180033,
    events_root: None,
}
2023-01-24T09:05:32.216733Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_OOGRevert.json"
2023-01-24T09:05:32.216762Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:32.241314Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:32.241422Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:32.241425Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:32.241476Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:32.241478Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:32.241535Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:32.241605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:32.241609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToEmpty_OOGRevert"::Istanbul::0
2023-01-24T09:05:32.241612Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:32.241615Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.241617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.588090Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6435515,
    events_root: None,
}
2023-01-24T09:05:32.588116Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:32.588123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToEmpty_OOGRevert"::Berlin::0
2023-01-24T09:05:32.588126Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:32.588129Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.588130Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.588422Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7459628,
    events_root: None,
}
2023-01-24T09:05:32.588435Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:32.588439Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToEmpty_OOGRevert"::London::0
2023-01-24T09:05:32.588441Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:32.588444Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.588445Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.588697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5483902,
    events_root: None,
}
2023-01-24T09:05:32.588709Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:32.588712Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToEmpty_OOGRevert"::Merge::0
2023-01-24T09:05:32.588714Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:32.588718Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.588719Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.588954Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3989271,
    events_root: None,
}
2023-01-24T09:05:32.589966Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToEmpty_OOGRevert.json"
2023-01-24T09:05:32.589992Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:32.614997Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:32.615104Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:32.615107Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:32.615160Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:32.615162Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:32.615219Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:32.615290Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:32.615295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert"::Istanbul::0
2023-01-24T09:05:32.615298Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:32.615301Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.615302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.967241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6435515,
    events_root: None,
}
2023-01-24T09:05:32.967268Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:32.967274Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert"::Berlin::0
2023-01-24T09:05:32.967277Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:32.967280Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.967282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.967571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7459628,
    events_root: None,
}
2023-01-24T09:05:32.967583Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:32.967585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert"::London::0
2023-01-24T09:05:32.967588Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:32.967591Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.967592Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.967856Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5483902,
    events_root: None,
}
2023-01-24T09:05:32.967869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:32.967872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert"::Merge::0
2023-01-24T09:05:32.967874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:32.967877Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.967878Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:32.968106Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3989271,
    events_root: None,
}
2023-01-24T09:05:32.969363Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:32.969402Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:32.994528Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:32.994647Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:32.994650Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:32.994703Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:32.994705Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:32.994762Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:32.994832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:32.994837Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert"::Istanbul::0
2023-01-24T09:05:32.994840Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:32.994843Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:32.994845Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:33.326334Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6435515,
    events_root: None,
}
2023-01-24T09:05:33.326359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:33.326365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert"::Berlin::0
2023-01-24T09:05:33.326368Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:33.326372Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:33.326373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:33.326672Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7459628,
    events_root: None,
}
2023-01-24T09:05:33.326688Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:33.326690Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert"::London::0
2023-01-24T09:05:33.326693Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:33.326696Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:33.326698Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:33.326954Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5483902,
    events_root: None,
}
2023-01-24T09:05:33.326966Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:33.326969Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert"::Merge::0
2023-01-24T09:05:33.326972Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:33.326975Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:33.326976Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:33.327226Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3989271,
    events_root: None,
}
2023-01-24T09:05:33.328627Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_DELEGATECALL_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:33.328657Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_OOGRevert.json"
2023-01-24T09:05:33.354141Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:33.354257Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:33.354261Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:33.354317Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:33.354320Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:33.354383Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:33.354458Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:33.354464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_OOGRevert"::Istanbul::0
2023-01-24T09:05:33.354468Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_OOGRevert.json"
2023-01-24T09:05:33.354472Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:33.354474Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:33.690426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4508008,
    events_root: None,
}
2023-01-24T09:05:33.690450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:33.690458Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_OOGRevert"::Berlin::0
2023-01-24T09:05:33.690462Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_OOGRevert.json"
2023-01-24T09:05:33.690466Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:33.690468Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:33.690712Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4394603,
    events_root: None,
}
2023-01-24T09:05:33.690724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:33.690727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_OOGRevert"::London::0
2023-01-24T09:05:33.690730Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_OOGRevert.json"
2023-01-24T09:05:33.690734Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:33.690736Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:33.690899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2899973,
    events_root: None,
}
2023-01-24T09:05:33.690909Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:33.690912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_OOGRevert"::Merge::0
2023-01-24T09:05:33.690915Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_OOGRevert.json"
2023-01-24T09:05:33.690919Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:33.690920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:33.691080Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2899973,
    events_root: None,
}
2023-01-24T09:05:33.692344Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_OOGRevert.json"
2023-01-24T09:05:33.692374Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:33.717107Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:33.717219Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:33.717223Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:33.717277Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:33.717281Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:33.717341Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:33.717344Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T09:05:33.717401Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:33.717474Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:33.717479Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToEmpty_OOGRevert"::Istanbul::0
2023-01-24T09:05:33.717483Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:33.717488Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:33.717490Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.065267Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3923265,
    events_root: None,
}
2023-01-24T09:05:34.065290Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:34.065299Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToEmpty_OOGRevert"::Berlin::0
2023-01-24T09:05:34.065303Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:34.065307Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.065308Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.065468Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2549503,
    events_root: None,
}
2023-01-24T09:05:34.065477Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:34.065481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToEmpty_OOGRevert"::London::0
2023-01-24T09:05:34.065483Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:34.065488Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.065489Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.065650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2549503,
    events_root: None,
}
2023-01-24T09:05:34.065660Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:34.065663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToEmpty_OOGRevert"::Merge::0
2023-01-24T09:05:34.065666Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:34.065670Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.065672Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.065816Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2549503,
    events_root: None,
}
2023-01-24T09:05:34.066950Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToEmpty_OOGRevert.json"
2023-01-24T09:05:34.066983Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:34.091262Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:34.091372Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:34.091376Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:34.091430Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:34.091433Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:34.091493Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:34.091496Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T09:05:34.091551Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:34.091627Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:34.091633Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert"::Istanbul::0
2023-01-24T09:05:34.091637Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:34.091642Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.091644Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.425956Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3923265,
    events_root: None,
}
2023-01-24T09:05:34.425980Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:34.425986Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert"::Berlin::0
2023-01-24T09:05:34.425989Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:34.425992Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.425994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.426162Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2549503,
    events_root: None,
}
2023-01-24T09:05:34.426171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:34.426173Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert"::London::0
2023-01-24T09:05:34.426176Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:34.426178Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.426180Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.426329Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2549503,
    events_root: None,
}
2023-01-24T09:05:34.426337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:34.426340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert"::Merge::0
2023-01-24T09:05:34.426342Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:34.426345Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.426346Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.426493Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2549503,
    events_root: None,
}
2023-01-24T09:05:34.427646Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToNonZeroBalance_OOGRevert.json"
2023-01-24T09:05:34.427673Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:34.451663Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:05:34.451773Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:34.451776Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:05:34.451827Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:34.451830Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:05:34.451886Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:34.451889Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T09:05:34.451942Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:05:34.452012Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:05:34.452017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert"::Istanbul::0
2023-01-24T09:05:34.452021Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:34.452024Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.452026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.784176Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3923265,
    events_root: None,
}
2023-01-24T09:05:34.784200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:05:34.784210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert"::Berlin::0
2023-01-24T09:05:34.784214Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:34.784218Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.784220Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.784389Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2549503,
    events_root: None,
}
2023-01-24T09:05:34.784398Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:05:34.784401Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert"::London::0
2023-01-24T09:05:34.784404Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:34.784408Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.784410Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.784553Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2549503,
    events_root: None,
}
2023-01-24T09:05:34.784563Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:05:34.784566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert"::Merge::0
2023-01-24T09:05:34.784569Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:34.784573Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:05:34.784575Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:05:34.784718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2549503,
    events_root: None,
}
2023-01-24T09:05:34.786010Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stZeroCallsRevert/ZeroValue_SUICIDE_ToOneStorageKey_OOGRevert.json"
2023-01-24T09:05:34.786169Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 16 Files in Time:5.622341894s
```