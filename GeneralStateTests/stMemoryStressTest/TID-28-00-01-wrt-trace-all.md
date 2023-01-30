> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stMemoryStressTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stMemoryStressTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-case failed

- Hit with error `SYS_ILLEGAL_INSTRUCTION` (ExitCode::4)

| Test ID | Use-Case |
| --- | --- |
| TID-28-01 | CALL_Bounds |
| TID-28-02 | CALL_Bounds2 |
| TID-28-09 | CREATE_Bounds |
| TID-28-12 | DELEGATECALL_Bounds |
| TID-28-35 | static_CALL_Bounds |
| TID-28-36 | static_CALL_Bounds2 |

- Hit with error `USR_ASSERTION_FAILED` (ExitCode::24)

| Test ID | Use-Case |
| --- | --- |
| TID-28-10 | CREATE_Bounds2 |
| TID-28-23 | mload32bitBound_return |
| TID-28-24 | mload32bitBound_return2 |

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-28-05 | CALLCODE_Bounds |
| TID-28-06 | CALLCODE_Bounds2 |
| TID-28-07 | CALLCODE_Bounds3 |
| TID-28-08 | CALLCODE_Bounds4 |

- Hit with error `EVM_CONTRACT_STACK_OVERFLOW` (ExitCode::37)

| Test ID | Use-Case |
| --- | --- |
| TID-28-16 | FillStack |

- Hit with error `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS` (ExitCode::38)

| Test ID | Use-Case |
| --- | --- |
| TID-28-03 | CALL_Bounds2a |
| TID-28-04 | CALL_Bounds3 |
| TID-28-11 | CREATE_Bounds3 |
| TID-28-13 | DELEGATECALL_Bounds2 |
| TID-28-14 | DELEGATECALL_Bounds3 |
| TID-28-25 | MLOAD_Bounds |
| TID-28-26 | MLOAD_Bounds2 |
| TID-28-28 | MSTORE_Bounds |
| TID-28-29 | MSTORE_Bounds2 |
| TID-28-20 | mload32bitBound |
| TID-28-21 | mload32bitBound2 |
| TID-28-22 | mload32bitBound_Msize |
| TID-28-37 | static_CALL_Bounds2a |
| TID-28-38 | static_CALL_Bounds3 |

- Hit with error `EVM_CONTRACT_BAD_JUMPDEST` (ExitCode::39)

| Test ID | Use-Case |
| --- | --- |
| TID-28-19 | JUMPI_Bounds |
| TID-28-17 | JUMP_Bounds |
| TID-28-18 | JUMP_Bounds2 |


> Execution Trace

```
2023-01-30T14:28:16.362422Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CALLCODE_Bounds.json", Total Files :: 1
2023-01-30T14:28:16.459039Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:16.459180Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:16.459184Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:16.459237Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:16.459239Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:16.459301Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:16.459374Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:16.459378Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds"::Istanbul::0
2023-01-30T14:28:16.459381Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds.json"
2023-01-30T14:28:16.459383Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:16.841712Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds"
2023-01-30T14:28:16.841730Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562182,
    events_root: None,
}
2023-01-30T14:28:16.841736Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=40): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:16.841749Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:16.841753Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds"::Istanbul::0
2023-01-30T14:28:16.841755Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds.json"
2023-01-30T14:28:16.841756Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:16.841861Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds"
2023-01-30T14:28:16.841867Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562182,
    events_root: None,
}
2023-01-30T14:28:16.841870Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=40): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:16.841879Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:16.841880Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds"::Berlin::0
2023-01-30T14:28:16.841882Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds.json"
2023-01-30T14:28:16.841884Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:16.841969Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds"
2023-01-30T14:28:16.841974Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562182,
    events_root: None,
}
2023-01-30T14:28:16.841977Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=40): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:16.841985Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:16.841988Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds"::Berlin::0
2023-01-30T14:28:16.841989Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds.json"
2023-01-30T14:28:16.841991Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:16.842075Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds"
2023-01-30T14:28:16.842081Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562182,
    events_root: None,
}
2023-01-30T14:28:16.842083Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=40): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:16.842091Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:16.842093Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds"::London::0
2023-01-30T14:28:16.842095Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds.json"
2023-01-30T14:28:16.842097Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:16.842180Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds"
2023-01-30T14:28:16.842186Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562182,
    events_root: None,
}
2023-01-30T14:28:16.842188Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=40): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:16.842196Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:16.842198Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds"::London::0
2023-01-30T14:28:16.842200Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds.json"
2023-01-30T14:28:16.842202Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:16.842286Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds"
2023-01-30T14:28:16.842291Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562182,
    events_root: None,
}
2023-01-30T14:28:16.842294Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=40): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:16.842302Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:16.842304Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds"::Merge::0
2023-01-30T14:28:16.842305Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds.json"
2023-01-30T14:28:16.842307Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:16.842390Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds"
2023-01-30T14:28:16.842396Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562182,
    events_root: None,
}
2023-01-30T14:28:16.842399Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=40): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:16.842407Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:16.842408Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds"::Merge::0
2023-01-30T14:28:16.842410Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds.json"
2023-01-30T14:28:16.842412Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:16.842495Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds"
2023-01-30T14:28:16.842500Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562182,
    events_root: None,
}
2023-01-30T14:28:16.842503Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=40): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:16.843975Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:383.479381ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CALLCODE_Bounds.json::CALLCODE_Bounds": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:17.120804Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CALLCODE_Bounds2.json", Total Files :: 1
2023-01-30T14:28:17.184909Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:17.185099Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:17.185103Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:17.185154Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:17.185156Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:17.185215Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:17.185286Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:17.185289Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds2"::Istanbul::0
2023-01-30T14:28:17.185293Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds2.json"
2023-01-30T14:28:17.185294Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:17.540313Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds2"
2023-01-30T14:28:17.540344Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:17.540350Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:17.540364Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:17.540367Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds2"::Istanbul::0
2023-01-30T14:28:17.540369Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds2.json"
2023-01-30T14:28:17.540370Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:17.540509Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds2"
2023-01-30T14:28:17.540516Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:17.540521Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:17.540530Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:17.540532Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds2"::Berlin::0
2023-01-30T14:28:17.540534Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds2.json"
2023-01-30T14:28:17.540535Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:17.540623Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds2"
2023-01-30T14:28:17.540629Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:17.540632Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:17.540640Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:17.540644Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds2"::Berlin::0
2023-01-30T14:28:17.540646Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds2.json"
2023-01-30T14:28:17.540647Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:17.540734Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds2"
2023-01-30T14:28:17.540740Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:17.540743Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:17.540752Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:17.540754Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds2"::London::0
2023-01-30T14:28:17.540756Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds2.json"
2023-01-30T14:28:17.540758Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:17.540842Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds2"
2023-01-30T14:28:17.540847Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:17.540850Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:17.540858Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:17.540860Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds2"::London::0
2023-01-30T14:28:17.540862Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds2.json"
2023-01-30T14:28:17.540863Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:17.540948Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds2"
2023-01-30T14:28:17.540953Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:17.540956Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:17.540964Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:17.540966Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds2"::Merge::0
2023-01-30T14:28:17.540968Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds2.json"
2023-01-30T14:28:17.540970Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:17.541069Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds2"
2023-01-30T14:28:17.541075Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:17.541078Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:17.541086Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:17.541088Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds2"::Merge::0
2023-01-30T14:28:17.541089Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds2.json"
2023-01-30T14:28:17.541091Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:17.541177Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds2"
2023-01-30T14:28:17.541183Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:17.541186Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:17.542954Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:356.299121ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CALLCODE_Bounds2.json::CALLCODE_Bounds2": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:17.825044Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CALLCODE_Bounds3.json", Total Files :: 1
2023-01-30T14:28:17.864334Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:17.864472Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:17.864475Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:17.864527Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:17.864529Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:17.864589Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:17.864660Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:17.864662Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds3"::Istanbul::0
2023-01-30T14:28:17.864666Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds3.json"
2023-01-30T14:28:17.864667Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.244781Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds3"
2023-01-30T14:28:18.244803Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:18.244808Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.244821Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:18.244825Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds3"::Istanbul::0
2023-01-30T14:28:18.244826Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds3.json"
2023-01-30T14:28:18.244829Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.244949Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds3"
2023-01-30T14:28:18.244955Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:18.244958Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.244968Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:18.244971Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds3"::Berlin::0
2023-01-30T14:28:18.244973Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds3.json"
2023-01-30T14:28:18.244975Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.245071Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds3"
2023-01-30T14:28:18.245078Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:18.245080Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.245090Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:18.245093Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds3"::Berlin::0
2023-01-30T14:28:18.245094Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds3.json"
2023-01-30T14:28:18.245096Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.245183Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds3"
2023-01-30T14:28:18.245188Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:18.245191Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.245199Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:18.245201Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds3"::London::0
2023-01-30T14:28:18.245203Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds3.json"
2023-01-30T14:28:18.245205Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.245292Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds3"
2023-01-30T14:28:18.245297Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:18.245300Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.245308Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:18.245310Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds3"::London::0
2023-01-30T14:28:18.245312Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds3.json"
2023-01-30T14:28:18.245313Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.245399Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds3"
2023-01-30T14:28:18.245404Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:18.245407Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.245415Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:18.245417Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds3"::Merge::0
2023-01-30T14:28:18.245419Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds3.json"
2023-01-30T14:28:18.245420Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.245506Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds3"
2023-01-30T14:28:18.245512Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:18.245514Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.245523Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:18.245525Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds3"::Merge::0
2023-01-30T14:28:18.245527Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds3.json"
2023-01-30T14:28:18.245529Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.245613Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds3"
2023-01-30T14:28:18.245618Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544021,
    events_root: None,
}
2023-01-30T14:28:18.245621Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=52): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.247154Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:381.302451ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CALLCODE_Bounds3.json::CALLCODE_Bounds3": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:18.502296Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CALLCODE_Bounds4.json", Total Files :: 1
2023-01-30T14:28:18.535632Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:18.535765Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:18.535768Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:18.535818Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:18.535820Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:18.535878Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:18.535949Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:18.535951Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::Istanbul::0
2023-01-30T14:28:18.535954Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.535956Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.902674Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.902694Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.902700Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.902712Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:18.902716Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::Istanbul::0
2023-01-30T14:28:18.902717Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.902719Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.902840Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.902846Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.902848Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.902857Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:18.902859Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::Istanbul::0
2023-01-30T14:28:18.902861Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.902862Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.902951Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.902956Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.902959Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.902967Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:18.902969Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::Berlin::0
2023-01-30T14:28:18.902971Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.902972Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.903058Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.903063Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.903066Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.903074Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:18.903076Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::Berlin::0
2023-01-30T14:28:18.903077Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.903079Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.903165Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.903170Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.903173Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.903181Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:18.903183Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::Berlin::0
2023-01-30T14:28:18.903184Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.903186Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.903272Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.903277Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.903281Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.903289Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:18.903292Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::London::0
2023-01-30T14:28:18.903293Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.903295Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.903381Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.903386Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.903389Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.903397Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:18.903399Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::London::0
2023-01-30T14:28:18.903400Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.903402Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.903487Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.903492Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.903495Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.903503Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:18.903504Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::London::0
2023-01-30T14:28:18.903506Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.903508Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.903592Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.903597Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.903599Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.903607Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:18.903609Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::Merge::0
2023-01-30T14:28:18.903611Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.903612Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.903697Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.903702Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.903705Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.903713Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:18.903715Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::Merge::0
2023-01-30T14:28:18.903716Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.903718Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.903802Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.903806Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.903809Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.903817Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:18.903819Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALLCODE_Bounds4"::Merge::0
2023-01-30T14:28:18.903820Z  INFO evm_eth_compliance::statetest::executor: Path : "CALLCODE_Bounds4.json"
2023-01-30T14:28:18.903822Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:18.903906Z  INFO evm_eth_compliance::statetest::executor: UC : "CALLCODE_Bounds4"
2023-01-30T14:28:18.903911Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1564727,
    events_root: None,
}
2023-01-30T14:28:18.903914Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=54): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:18.905516Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.298119ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CALLCODE_Bounds4.json::CALLCODE_Bounds4": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:19.165996Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CALL_Bounds.json", Total Files :: 1
2023-01-30T14:28:19.195552Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:19.195692Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:19.195696Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:19.195746Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:19.195749Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:19.195811Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:19.195883Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:19.195885Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds"::Istanbul::0
2023-01-30T14:28:19.195889Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds.json"
2023-01-30T14:28:19.195891Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:19.603593Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds"
2023-01-30T14:28:19.603616Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 326275145,
    events_root: None,
}
2023-01-30T14:28:19.603622Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:19.603644Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:19.603648Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds"::Istanbul::0
2023-01-30T14:28:19.603650Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds.json"
2023-01-30T14:28:19.603652Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:19.668005Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds"
2023-01-30T14:28:19.668026Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 326275145,
    events_root: None,
}
2023-01-30T14:28:19.668031Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:19.668052Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:19.668055Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds"::Berlin::0
2023-01-30T14:28:19.668057Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds.json"
2023-01-30T14:28:19.668059Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:19.732299Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds"
2023-01-30T14:28:19.732320Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 326275145,
    events_root: None,
}
2023-01-30T14:28:19.732325Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:19.732346Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:19.732350Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds"::Berlin::0
2023-01-30T14:28:19.732353Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds.json"
2023-01-30T14:28:19.732355Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:19.797812Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds"
2023-01-30T14:28:19.797834Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 326275145,
    events_root: None,
}
2023-01-30T14:28:19.797840Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:19.797861Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:19.797866Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds"::London::0
2023-01-30T14:28:19.797868Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds.json"
2023-01-30T14:28:19.797869Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:19.862476Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds"
2023-01-30T14:28:19.862499Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 326275145,
    events_root: None,
}
2023-01-30T14:28:19.862504Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:19.862526Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:19.862531Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds"::London::0
2023-01-30T14:28:19.862533Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds.json"
2023-01-30T14:28:19.862534Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:19.932163Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds"
2023-01-30T14:28:19.932184Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 326275145,
    events_root: None,
}
2023-01-30T14:28:19.932190Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:19.932213Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:19.932217Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds"::Merge::0
2023-01-30T14:28:19.932218Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds.json"
2023-01-30T14:28:19.932220Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:19.997365Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds"
2023-01-30T14:28:19.997387Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 326275145,
    events_root: None,
}
2023-01-30T14:28:19.997392Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:19.997413Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:19.997417Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds"::Merge::0
2023-01-30T14:28:19.997419Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds.json"
2023-01-30T14:28:19.997421Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:20.063510Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds"
2023-01-30T14:28:20.063532Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 326275145,
    events_root: None,
}
2023-01-30T14:28:20.063537Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:20.065393Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:868.016216ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CALL_Bounds.json::CALL_Bounds": [
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:20.326821Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CALL_Bounds2.json", Total Files :: 1
2023-01-30T14:28:20.356937Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:20.357089Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:20.357093Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:20.357145Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:20.357147Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:20.357210Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:20.357281Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:20.357284Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2"::Istanbul::0
2023-01-30T14:28:20.357287Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2.json"
2023-01-30T14:28:20.357288Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:20.705807Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2"
2023-01-30T14:28:20.705828Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216281820,
    events_root: None,
}
2023-01-30T14:28:20.705834Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:20.705847Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:20.705851Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2"::Istanbul::0
2023-01-30T14:28:20.705853Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2.json"
2023-01-30T14:28:20.705856Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:20.705978Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2"
2023-01-30T14:28:20.705983Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216281820,
    events_root: None,
}
2023-01-30T14:28:20.705986Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:20.705997Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:20.705999Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2"::Berlin::0
2023-01-30T14:28:20.706001Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2.json"
2023-01-30T14:28:20.706002Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:20.706091Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2"
2023-01-30T14:28:20.706097Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216281820,
    events_root: None,
}
2023-01-30T14:28:20.706099Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:20.706107Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:20.706109Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2"::Berlin::0
2023-01-30T14:28:20.706111Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2.json"
2023-01-30T14:28:20.706113Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:20.706201Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2"
2023-01-30T14:28:20.706206Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216281820,
    events_root: None,
}
2023-01-30T14:28:20.706209Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:20.706217Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:20.706220Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2"::London::0
2023-01-30T14:28:20.706222Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2.json"
2023-01-30T14:28:20.706223Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:20.706310Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2"
2023-01-30T14:28:20.706316Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216281820,
    events_root: None,
}
2023-01-30T14:28:20.706318Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:20.706326Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:20.706328Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2"::London::0
2023-01-30T14:28:20.706329Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2.json"
2023-01-30T14:28:20.706331Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:20.706418Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2"
2023-01-30T14:28:20.706424Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216281820,
    events_root: None,
}
2023-01-30T14:28:20.706427Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:20.706437Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:20.706440Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2"::Merge::0
2023-01-30T14:28:20.706442Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2.json"
2023-01-30T14:28:20.706446Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:20.706553Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2"
2023-01-30T14:28:20.706559Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216281820,
    events_root: None,
}
2023-01-30T14:28:20.706561Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:20.706570Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:20.706572Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2"::Merge::0
2023-01-30T14:28:20.706573Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2.json"
2023-01-30T14:28:20.706575Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:20.706665Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2"
2023-01-30T14:28:20.706671Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216281820,
    events_root: None,
}
2023-01-30T14:28:20.706674Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:20.708061Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:349.753407ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CALL_Bounds2.json::CALL_Bounds2": [
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:20.982400Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CALL_Bounds2a.json", Total Files :: 1
2023-01-30T14:28:21.040000Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:21.040137Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:21.040141Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:21.040190Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:21.040192Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:21.040251Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:21.040321Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:21.040324Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2a"::Istanbul::0
2023-01-30T14:28:21.040327Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2a.json"
2023-01-30T14:28:21.040329Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:21.401741Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2a"
2023-01-30T14:28:21.401761Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548181,
    events_root: None,
}
2023-01-30T14:28:21.401766Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:21.401779Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:21.401782Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2a"::Istanbul::0
2023-01-30T14:28:21.401784Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2a.json"
2023-01-30T14:28:21.401786Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:21.401897Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2a"
2023-01-30T14:28:21.401903Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548181,
    events_root: None,
}
2023-01-30T14:28:21.401906Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:21.401915Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:21.401917Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2a"::Berlin::0
2023-01-30T14:28:21.401919Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2a.json"
2023-01-30T14:28:21.401920Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:21.402005Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2a"
2023-01-30T14:28:21.402010Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548181,
    events_root: None,
}
2023-01-30T14:28:21.402013Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:21.402021Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:21.402023Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2a"::Berlin::0
2023-01-30T14:28:21.402025Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2a.json"
2023-01-30T14:28:21.402026Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:21.402110Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2a"
2023-01-30T14:28:21.402115Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548181,
    events_root: None,
}
2023-01-30T14:28:21.402117Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:21.402126Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:21.402127Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2a"::London::0
2023-01-30T14:28:21.402129Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2a.json"
2023-01-30T14:28:21.402130Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:21.402213Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2a"
2023-01-30T14:28:21.402218Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548181,
    events_root: None,
}
2023-01-30T14:28:21.402221Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:21.402229Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:21.402231Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2a"::London::0
2023-01-30T14:28:21.402232Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2a.json"
2023-01-30T14:28:21.402234Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:21.402316Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2a"
2023-01-30T14:28:21.402320Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548181,
    events_root: None,
}
2023-01-30T14:28:21.402323Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:21.402331Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:21.402333Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2a"::Merge::0
2023-01-30T14:28:21.402335Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2a.json"
2023-01-30T14:28:21.402337Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:21.402420Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2a"
2023-01-30T14:28:21.402424Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548181,
    events_root: None,
}
2023-01-30T14:28:21.402427Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:21.402435Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:21.402437Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds2a"::Merge::0
2023-01-30T14:28:21.402439Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds2a.json"
2023-01-30T14:28:21.402440Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:21.402522Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds2a"
2023-01-30T14:28:21.402527Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1548181,
    events_root: None,
}
2023-01-30T14:28:21.402529Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:21.403960Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.545484ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CALL_Bounds2a.json::CALL_Bounds2a": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:21.682531Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CALL_Bounds3.json", Total Files :: 1
2023-01-30T14:28:21.736611Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:21.736757Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:21.736761Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:21.736815Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:21.736818Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:21.736881Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:21.736953Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:21.736956Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::Istanbul::0
2023-01-30T14:28:21.736959Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:21.736960Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.079356Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.079378Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.079384Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.079399Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:22.079403Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::Istanbul::0
2023-01-30T14:28:22.079405Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.079408Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.079535Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.079542Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.079546Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.079558Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:22.079561Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::Istanbul::0
2023-01-30T14:28:22.079564Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.079566Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.079659Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.079665Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.079669Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.079681Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:22.079683Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::Berlin::0
2023-01-30T14:28:22.079686Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.079688Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.079780Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.079786Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.079789Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.079801Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:22.079803Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::Berlin::0
2023-01-30T14:28:22.079805Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.079807Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.079916Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.079923Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.079927Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.079938Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:22.079941Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::Berlin::0
2023-01-30T14:28:22.079943Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.079946Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.080039Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.080045Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.080049Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.080060Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:22.080062Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::London::0
2023-01-30T14:28:22.080065Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.080067Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.080161Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.080167Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.080170Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.080181Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:22.080184Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::London::0
2023-01-30T14:28:22.080186Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.080189Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.080278Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.080283Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.080287Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.080298Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:22.080300Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::London::0
2023-01-30T14:28:22.080303Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.080305Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.080421Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.080429Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.080432Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.080443Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:22.080446Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::Merge::0
2023-01-30T14:28:22.080448Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.080451Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.080549Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.080554Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.080557Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.080565Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:22.080567Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::Merge::0
2023-01-30T14:28:22.080569Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.080570Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.080656Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.080661Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.080663Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.080671Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:22.080673Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CALL_Bounds3"::Merge::0
2023-01-30T14:28:22.080675Z  INFO evm_eth_compliance::statetest::executor: Path : "CALL_Bounds3.json"
2023-01-30T14:28:22.080676Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:22.080760Z  INFO evm_eth_compliance::statetest::executor: UC : "CALL_Bounds3"
2023-01-30T14:28:22.080765Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1567657,
    events_root: None,
}
2023-01-30T14:28:22.080768Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=54): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:22.082408Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:344.175203ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CALL_Bounds3.json::CALL_Bounds3": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:22.359045Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CREATE_Bounds.json", Total Files :: 1
2023-01-30T14:28:22.389962Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:22.390097Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:22.390100Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:22.390157Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:22.390227Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:22.390230Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds"::Istanbul::0
2023-01-30T14:28:22.390233Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds.json"
2023-01-30T14:28:22.390235Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-30T14:28:23.072413Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds"
2023-01-30T14:28:23.072435Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 335720746,
    events_root: None,
}
2023-01-30T14:28:23.072442Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:23.072487Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:23.072491Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds"::Istanbul::0
2023-01-30T14:28:23.072493Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds.json"
2023-01-30T14:28:23.072495Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-30T14:28:23.143357Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds"
2023-01-30T14:28:23.143381Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 335908512,
    events_root: None,
}
2023-01-30T14:28:23.143388Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:23.143441Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:23.143445Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds"::Berlin::0
2023-01-30T14:28:23.143447Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds.json"
2023-01-30T14:28:23.143449Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-30T14:28:23.207897Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds"
2023-01-30T14:28:23.207916Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 335686259,
    events_root: None,
}
2023-01-30T14:28:23.207921Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:23.207963Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:23.207967Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds"::Berlin::0
2023-01-30T14:28:23.207969Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds.json"
2023-01-30T14:28:23.207971Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-30T14:28:23.272289Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds"
2023-01-30T14:28:23.272311Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 335848843,
    events_root: None,
}
2023-01-30T14:28:23.272316Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:23.272360Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:23.272364Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds"::London::0
2023-01-30T14:28:23.272366Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds.json"
2023-01-30T14:28:23.272368Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
2023-01-30T14:28:23.336120Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds"
2023-01-30T14:28:23.336139Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 335471666,
    events_root: None,
}
2023-01-30T14:28:23.336144Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:23.336189Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:23.336193Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds"::London::0
2023-01-30T14:28:23.336195Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds.json"
2023-01-30T14:28:23.336197Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
2023-01-30T14:28:23.402239Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds"
2023-01-30T14:28:23.402262Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 335677139,
    events_root: None,
}
2023-01-30T14:28:23.402268Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:23.402315Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:23.402319Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds"::Merge::0
2023-01-30T14:28:23.402321Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds.json"
2023-01-30T14:28:23.402322Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
2023-01-30T14:28:23.466785Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds"
2023-01-30T14:28:23.466805Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 335677993,
    events_root: None,
}
2023-01-30T14:28:23.466810Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:23.466854Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:23.466858Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds"::Merge::0
2023-01-30T14:28:23.466860Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds.json"
2023-01-30T14:28:23.466862Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
2023-01-30T14:28:23.531198Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds"
2023-01-30T14:28:23.531218Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 335655261,
    events_root: None,
}
2023-01-30T14:28:23.531223Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:23.533105Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:1.141314031s
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CREATE_Bounds.json::CREATE_Bounds": [
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:23.792185Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CREATE_Bounds2.json", Total Files :: 1
2023-01-30T14:28:23.848586Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:23.848729Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:23.848733Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:23.848788Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:23.848860Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:23.848863Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds2"::Istanbul::0
2023-01-30T14:28:23.848866Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds2.json"
2023-01-30T14:28:23.848868Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.230021Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds2"
2023-01-30T14:28:24.230044Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1579590,
    events_root: None,
}
2023-01-30T14:28:24.230050Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.230067Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:24.230073Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds2"::Istanbul::0
2023-01-30T14:28:24.230075Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds2.json"
2023-01-30T14:28:24.230080Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.230200Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds2"
2023-01-30T14:28:24.230207Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1579590,
    events_root: None,
}
2023-01-30T14:28:24.230211Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.230223Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:24.230226Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds2"::Berlin::0
2023-01-30T14:28:24.230229Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds2.json"
2023-01-30T14:28:24.230231Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.230329Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds2"
2023-01-30T14:28:24.230335Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1579590,
    events_root: None,
}
2023-01-30T14:28:24.230339Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.230351Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:24.230354Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds2"::Berlin::0
2023-01-30T14:28:24.230356Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds2.json"
2023-01-30T14:28:24.230361Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.230457Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds2"
2023-01-30T14:28:24.230463Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1579590,
    events_root: None,
}
2023-01-30T14:28:24.230467Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.230479Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:24.230483Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds2"::London::0
2023-01-30T14:28:24.230486Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds2.json"
2023-01-30T14:28:24.230488Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.230584Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds2"
2023-01-30T14:28:24.230591Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1579590,
    events_root: None,
}
2023-01-30T14:28:24.230594Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.230607Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:24.230610Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds2"::London::0
2023-01-30T14:28:24.230612Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds2.json"
2023-01-30T14:28:24.230615Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.230710Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds2"
2023-01-30T14:28:24.230716Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1579590,
    events_root: None,
}
2023-01-30T14:28:24.230719Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.230733Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:24.230735Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds2"::Merge::0
2023-01-30T14:28:24.230738Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds2.json"
2023-01-30T14:28:24.230740Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.230847Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds2"
2023-01-30T14:28:24.230854Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1579590,
    events_root: None,
}
2023-01-30T14:28:24.230857Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.230868Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:24.230871Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds2"::Merge::0
2023-01-30T14:28:24.230873Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds2.json"
2023-01-30T14:28:24.230875Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.230993Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds2"
2023-01-30T14:28:24.230999Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1579590,
    events_root: None,
}
2023-01-30T14:28:24.231002Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.232610Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:382.432787ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CREATE_Bounds2.json::CREATE_Bounds2": [
        "Istanbul | 0 | ExitCode { value: 24 }",
        "Istanbul | 0 | ExitCode { value: 24 }",
        "Berlin | 0 | ExitCode { value: 24 }",
        "Berlin | 0 | ExitCode { value: 24 }",
        "London | 0 | ExitCode { value: 24 }",
        "London | 0 | ExitCode { value: 24 }",
        "Merge | 0 | ExitCode { value: 24 }",
        "Merge | 0 | ExitCode { value: 24 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:24.507083Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/CREATE_Bounds3.json", Total Files :: 1
2023-01-30T14:28:24.537624Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:24.537758Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:24.537762Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:24.537814Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:24.537884Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:24.537886Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::Istanbul::0
2023-01-30T14:28:24.537889Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.537891Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.895828Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.895848Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.895854Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.895867Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:24.895870Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::Istanbul::0
2023-01-30T14:28:24.895872Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.895874Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.895992Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.895998Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.896001Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.896009Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:24.896011Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::Istanbul::0
2023-01-30T14:28:24.896013Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.896014Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.896105Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.896113Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.896116Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.896126Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:24.896128Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::Berlin::0
2023-01-30T14:28:24.896130Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.896133Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.896253Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.896259Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.896262Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.896271Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:24.896273Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::Berlin::0
2023-01-30T14:28:24.896274Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.896276Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.896371Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.896377Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.896380Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.896388Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:24.896391Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::Berlin::0
2023-01-30T14:28:24.896393Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.896394Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.896485Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.896490Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.896493Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.896501Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:24.896503Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::London::0
2023-01-30T14:28:24.896504Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.896506Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.896593Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.896598Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.896601Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.896610Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:24.896612Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::London::0
2023-01-30T14:28:24.896613Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.896615Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.896704Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.896709Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.896712Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.896719Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:24.896721Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::London::0
2023-01-30T14:28:24.896723Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.896724Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.896823Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.896829Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.896833Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.896845Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:24.896847Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::Merge::0
2023-01-30T14:28:24.896850Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.896852Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.896951Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.896957Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.896960Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.896968Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:24.896970Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::Merge::0
2023-01-30T14:28:24.896972Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.896973Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.897070Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.897075Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.897078Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.897086Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:24.897088Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CREATE_Bounds3"::Merge::0
2023-01-30T14:28:24.897090Z  INFO evm_eth_compliance::statetest::executor: Path : "CREATE_Bounds3.json"
2023-01-30T14:28:24.897091Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:24.897179Z  INFO evm_eth_compliance::statetest::executor: UC : "CREATE_Bounds3"
2023-01-30T14:28:24.897184Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1596781,
    events_root: None,
}
2023-01-30T14:28:24.897187Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=59): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:24.898805Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.579587ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "CREATE_Bounds3.json::CREATE_Bounds3": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:25.173383Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/DELEGATECALL_Bounds.json", Total Files :: 1
2023-01-30T14:28:25.203121Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:25.203260Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:25.203264Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:25.203326Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:25.203329Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:25.203413Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:25.203516Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:25.203519Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds"::Istanbul::0
2023-01-30T14:28:25.203523Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds.json"
2023-01-30T14:28:25.203525Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:25.632840Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds"
2023-01-30T14:28:25.632860Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 328585691,
    events_root: None,
}
2023-01-30T14:28:25.632866Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:25.632890Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:25.632894Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds"::Istanbul::0
2023-01-30T14:28:25.632897Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds.json"
2023-01-30T14:28:25.632898Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:25.697728Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds"
2023-01-30T14:28:25.697749Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 328585691,
    events_root: None,
}
2023-01-30T14:28:25.697754Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:25.697776Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:25.697780Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds"::Berlin::0
2023-01-30T14:28:25.697781Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds.json"
2023-01-30T14:28:25.697783Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:25.764170Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds"
2023-01-30T14:28:25.764192Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 328585691,
    events_root: None,
}
2023-01-30T14:28:25.764199Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:25.764230Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:25.764237Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds"::Berlin::0
2023-01-30T14:28:25.764239Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds.json"
2023-01-30T14:28:25.764241Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:25.830454Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds"
2023-01-30T14:28:25.830471Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 328585691,
    events_root: None,
}
2023-01-30T14:28:25.830476Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:25.830499Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:25.830503Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds"::London::0
2023-01-30T14:28:25.830505Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds.json"
2023-01-30T14:28:25.830507Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:25.895400Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds"
2023-01-30T14:28:25.895419Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 328585691,
    events_root: None,
}
2023-01-30T14:28:25.895424Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:25.895446Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:25.895450Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds"::London::0
2023-01-30T14:28:25.895452Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds.json"
2023-01-30T14:28:25.895454Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:25.961119Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds"
2023-01-30T14:28:25.961138Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 328585691,
    events_root: None,
}
2023-01-30T14:28:25.961143Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:25.961168Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:25.961172Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds"::Merge::0
2023-01-30T14:28:25.961176Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds.json"
2023-01-30T14:28:25.961178Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:26.026416Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds"
2023-01-30T14:28:26.026434Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 328585691,
    events_root: None,
}
2023-01-30T14:28:26.026439Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:26.026463Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:26.026467Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds"::Merge::0
2023-01-30T14:28:26.026468Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds.json"
2023-01-30T14:28:26.026472Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:26.090981Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds"
2023-01-30T14:28:26.091003Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 328585691,
    events_root: None,
}
2023-01-30T14:28:26.091007Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:26.092763Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:887.918908ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "DELEGATECALL_Bounds.json::DELEGATECALL_Bounds": [
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:26.371046Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/DELEGATECALL_Bounds2.json", Total Files :: 1
2023-01-30T14:28:26.424523Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:26.424657Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:26.424661Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:26.424711Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:26.424713Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:26.424773Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:26.424842Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:26.424845Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds2"::Istanbul::0
2023-01-30T14:28:26.424848Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds2.json"
2023-01-30T14:28:26.424850Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:26.764091Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds2"
2023-01-30T14:28:26.764114Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:26.764121Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:26.764139Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:26.764144Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds2"::Istanbul::0
2023-01-30T14:28:26.764147Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds2.json"
2023-01-30T14:28:26.764150Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:26.764318Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds2"
2023-01-30T14:28:26.764326Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:26.764329Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:26.764339Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:26.764341Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds2"::Berlin::0
2023-01-30T14:28:26.764343Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds2.json"
2023-01-30T14:28:26.764345Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:26.764453Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds2"
2023-01-30T14:28:26.764465Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:26.764468Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:26.764481Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:26.764483Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds2"::Berlin::0
2023-01-30T14:28:26.764486Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds2.json"
2023-01-30T14:28:26.764488Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:26.764587Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds2"
2023-01-30T14:28:26.764594Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:26.764597Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:26.764608Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:26.764611Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds2"::London::0
2023-01-30T14:28:26.764614Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds2.json"
2023-01-30T14:28:26.764617Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:26.764706Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds2"
2023-01-30T14:28:26.764712Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:26.764716Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:26.764727Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:26.764729Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds2"::London::0
2023-01-30T14:28:26.764732Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds2.json"
2023-01-30T14:28:26.764735Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:26.764824Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds2"
2023-01-30T14:28:26.764830Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:26.764833Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:26.764845Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:26.764848Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds2"::Merge::0
2023-01-30T14:28:26.764851Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds2.json"
2023-01-30T14:28:26.764854Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:26.764946Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds2"
2023-01-30T14:28:26.764953Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:26.764956Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:26.764967Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:26.764970Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds2"::Merge::0
2023-01-30T14:28:26.764972Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds2.json"
2023-01-30T14:28:26.764974Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:26.765081Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds2"
2023-01-30T14:28:26.765087Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:26.765090Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:26.766681Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:340.58702ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "DELEGATECALL_Bounds2.json::DELEGATECALL_Bounds2": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:27.041286Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/DELEGATECALL_Bounds3.json", Total Files :: 1
2023-01-30T14:28:27.111102Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:27.111236Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:27.111239Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:27.111289Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:27.111291Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:27.111350Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:27.111420Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:27.111422Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::Istanbul::0
2023-01-30T14:28:27.111425Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.111428Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.471543Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.471563Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.471569Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.471585Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:27.471590Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::Istanbul::0
2023-01-30T14:28:27.471593Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.471596Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.471731Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.471737Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.471741Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.471753Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:27.471755Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::Istanbul::0
2023-01-30T14:28:27.471758Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.471761Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.471853Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.471859Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.471863Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.471875Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:27.471878Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::Berlin::0
2023-01-30T14:28:27.471881Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.471884Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.471978Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.471985Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.471988Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.471999Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:27.472002Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::Berlin::0
2023-01-30T14:28:27.472005Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.472007Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.472098Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.472106Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.472110Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.472122Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:27.472124Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::Berlin::0
2023-01-30T14:28:27.472127Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.472129Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.472225Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.472231Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.472235Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.472246Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:27.472249Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::London::0
2023-01-30T14:28:27.472252Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.472254Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.472346Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.472352Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.472355Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.472367Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:27.472369Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::London::0
2023-01-30T14:28:27.472372Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.472375Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.472465Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.472472Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.472475Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.472486Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:27.472489Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::London::0
2023-01-30T14:28:27.472491Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.472494Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.472587Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.472594Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.472597Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.472609Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:27.472612Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::Merge::0
2023-01-30T14:28:27.472615Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.472617Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.472714Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.472720Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.472724Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.472736Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:27.472738Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::Merge::0
2023-01-30T14:28:27.472741Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.472744Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.472838Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.472844Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.472847Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.472858Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:27.472861Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DELEGATECALL_Bounds3"::Merge::0
2023-01-30T14:28:27.472864Z  INFO evm_eth_compliance::statetest::executor: Path : "DELEGATECALL_Bounds3.json"
2023-01-30T14:28:27.472866Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:27.472958Z  INFO evm_eth_compliance::statetest::executor: UC : "DELEGATECALL_Bounds3"
2023-01-30T14:28:27.472964Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1563587,
    events_root: None,
}
2023-01-30T14:28:27.472968Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:27.474843Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.88542ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "DELEGATECALL_Bounds3.json::DELEGATECALL_Bounds3": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:27.736667Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/DUP_Bounds.json", Total Files :: 1
2023-01-30T14:28:27.795023Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:27.795168Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:27.795172Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:27.795225Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:27.795297Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:27.795300Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::Istanbul::0
2023-01-30T14:28:27.795303Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:27.795305Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.137076Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.137096Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.137104Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:28.137108Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::Istanbul::0
2023-01-30T14:28:28.137109Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.137111Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.137252Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.137257Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.137262Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:28.137264Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::Istanbul::0
2023-01-30T14:28:28.137265Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.137267Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.137373Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.137378Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.137382Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:28.137384Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::Berlin::0
2023-01-30T14:28:28.137386Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.137387Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.137492Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.137497Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.137501Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:28.137503Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::Berlin::0
2023-01-30T14:28:28.137505Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.137506Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.137609Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.137614Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.137618Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:28.137620Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::Berlin::0
2023-01-30T14:28:28.137622Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.137623Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.137727Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.137731Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.137736Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:28.137738Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::London::0
2023-01-30T14:28:28.137740Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.137741Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.137844Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.137849Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.137853Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:28.137855Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::London::0
2023-01-30T14:28:28.137857Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.137858Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.137961Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.137966Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.137971Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:28.137972Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::London::0
2023-01-30T14:28:28.137974Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.137976Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.138078Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.138083Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.138087Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:28.138089Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::Merge::0
2023-01-30T14:28:28.138091Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.138092Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.138194Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.138199Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.138203Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:28.138205Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::Merge::0
2023-01-30T14:28:28.138207Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.138208Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.138311Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.138315Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.138320Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:28.138321Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "DUP_Bounds"::Merge::0
2023-01-30T14:28:28.138323Z  INFO evm_eth_compliance::statetest::executor: Path : "DUP_Bounds.json"
2023-01-30T14:28:28.138325Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:28.138427Z  INFO evm_eth_compliance::statetest::executor: UC : "DUP_Bounds"
2023-01-30T14:28:28.138431Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877990,
    events_root: None,
}
2023-01-30T14:28:28.139900Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:343.421725ms
=== Start ===
=== OK Status ===
Count :: 1
{
    "DUP_Bounds.json::DUP_Bounds": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:28.397666Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/FillStack.json", Total Files :: 1
2023-01-30T14:28:28.427759Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:28.427905Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:28.427908Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:28.427960Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:28.427962Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:28.428026Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:28.428097Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:28.428100Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "FillStack"::Istanbul::0
2023-01-30T14:28:28.428103Z  INFO evm_eth_compliance::statetest::executor: Path : "FillStack.json"
2023-01-30T14:28:28.428104Z  INFO evm_eth_compliance::statetest::executor: TX len : 175
2023-01-30T14:28:28.769418Z  INFO evm_eth_compliance::statetest::executor: UC : "FillStack"
2023-01-30T14:28:28.769436Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 37,
    },
    return_data: RawBytes {  },
    gas_used: 3291546,
    events_root: None,
}
2023-01-30T14:28:28.769441Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 37,
                    },
                    message: "ABORT(pc=102): stack overflow",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:28.769455Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:28.769458Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "FillStack"::Istanbul::0
2023-01-30T14:28:28.769459Z  INFO evm_eth_compliance::statetest::executor: Path : "FillStack.json"
2023-01-30T14:28:28.769461Z  INFO evm_eth_compliance::statetest::executor: TX len : 175
2023-01-30T14:28:28.769653Z  INFO evm_eth_compliance::statetest::executor: UC : "FillStack"
2023-01-30T14:28:28.769659Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 37,
    },
    return_data: RawBytes {  },
    gas_used: 3291546,
    events_root: None,
}
2023-01-30T14:28:28.769662Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 37,
                    },
                    message: "ABORT(pc=102): stack overflow",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:28.769671Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:28.769672Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "FillStack"::Berlin::0
2023-01-30T14:28:28.769674Z  INFO evm_eth_compliance::statetest::executor: Path : "FillStack.json"
2023-01-30T14:28:28.769676Z  INFO evm_eth_compliance::statetest::executor: TX len : 175
2023-01-30T14:28:28.769840Z  INFO evm_eth_compliance::statetest::executor: UC : "FillStack"
2023-01-30T14:28:28.769845Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 37,
    },
    return_data: RawBytes {  },
    gas_used: 3291546,
    events_root: None,
}
2023-01-30T14:28:28.769848Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 37,
                    },
                    message: "ABORT(pc=102): stack overflow",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:28.769856Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:28.769858Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "FillStack"::Berlin::0
2023-01-30T14:28:28.769859Z  INFO evm_eth_compliance::statetest::executor: Path : "FillStack.json"
2023-01-30T14:28:28.769861Z  INFO evm_eth_compliance::statetest::executor: TX len : 175
2023-01-30T14:28:28.770041Z  INFO evm_eth_compliance::statetest::executor: UC : "FillStack"
2023-01-30T14:28:28.770048Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 37,
    },
    return_data: RawBytes {  },
    gas_used: 3291546,
    events_root: None,
}
2023-01-30T14:28:28.770052Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 37,
                    },
                    message: "ABORT(pc=102): stack overflow",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:28.770061Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:28.770063Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "FillStack"::London::0
2023-01-30T14:28:28.770065Z  INFO evm_eth_compliance::statetest::executor: Path : "FillStack.json"
2023-01-30T14:28:28.770066Z  INFO evm_eth_compliance::statetest::executor: TX len : 175
2023-01-30T14:28:28.770236Z  INFO evm_eth_compliance::statetest::executor: UC : "FillStack"
2023-01-30T14:28:28.770241Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 37,
    },
    return_data: RawBytes {  },
    gas_used: 3291546,
    events_root: None,
}
2023-01-30T14:28:28.770244Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 37,
                    },
                    message: "ABORT(pc=102): stack overflow",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:28.770252Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:28.770254Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "FillStack"::London::0
2023-01-30T14:28:28.770255Z  INFO evm_eth_compliance::statetest::executor: Path : "FillStack.json"
2023-01-30T14:28:28.770257Z  INFO evm_eth_compliance::statetest::executor: TX len : 175
2023-01-30T14:28:28.770421Z  INFO evm_eth_compliance::statetest::executor: UC : "FillStack"
2023-01-30T14:28:28.770426Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 37,
    },
    return_data: RawBytes {  },
    gas_used: 3291546,
    events_root: None,
}
2023-01-30T14:28:28.770429Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 37,
                    },
                    message: "ABORT(pc=102): stack overflow",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:28.770437Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:28.770439Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "FillStack"::Merge::0
2023-01-30T14:28:28.770440Z  INFO evm_eth_compliance::statetest::executor: Path : "FillStack.json"
2023-01-30T14:28:28.770442Z  INFO evm_eth_compliance::statetest::executor: TX len : 175
2023-01-30T14:28:28.770608Z  INFO evm_eth_compliance::statetest::executor: UC : "FillStack"
2023-01-30T14:28:28.770614Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 37,
    },
    return_data: RawBytes {  },
    gas_used: 3291546,
    events_root: None,
}
2023-01-30T14:28:28.770618Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 37,
                    },
                    message: "ABORT(pc=102): stack overflow",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:28.770626Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:28.770628Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "FillStack"::Merge::0
2023-01-30T14:28:28.770629Z  INFO evm_eth_compliance::statetest::executor: Path : "FillStack.json"
2023-01-30T14:28:28.770631Z  INFO evm_eth_compliance::statetest::executor: TX len : 175
2023-01-30T14:28:28.770805Z  INFO evm_eth_compliance::statetest::executor: UC : "FillStack"
2023-01-30T14:28:28.770810Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 37,
    },
    return_data: RawBytes {  },
    gas_used: 3291546,
    events_root: None,
}
2023-01-30T14:28:28.770812Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 37,
                    },
                    message: "ABORT(pc=102): stack overflow",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:28.772339Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:343.071803ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "FillStack.json::FillStack": [
        "Istanbul | 0 | ExitCode { value: 37 }",
        "Istanbul | 0 | ExitCode { value: 37 }",
        "Berlin | 0 | ExitCode { value: 37 }",
        "Berlin | 0 | ExitCode { value: 37 }",
        "London | 0 | ExitCode { value: 37 }",
        "London | 0 | ExitCode { value: 37 }",
        "Merge | 0 | ExitCode { value: 37 }",
        "Merge | 0 | ExitCode { value: 37 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:29.036369Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/JUMPI_Bounds.json", Total Files :: 1
2023-01-30T14:28:29.077272Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:29.077410Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:29.077414Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:29.077477Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:29.077562Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:29.077566Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMPI_Bounds"::Istanbul::0
2023-01-30T14:28:29.077569Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMPI_Bounds.json"
2023-01-30T14:28:29.077570Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:29.430485Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMPI_Bounds"
2023-01-30T14:28:29.430505Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1547156,
    events_root: None,
}
2023-01-30T14:28:29.430511Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=7): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:29.430524Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:29.430528Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMPI_Bounds"::Istanbul::0
2023-01-30T14:28:29.430531Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMPI_Bounds.json"
2023-01-30T14:28:29.430533Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:29.430657Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMPI_Bounds"
2023-01-30T14:28:29.430663Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1547156,
    events_root: None,
}
2023-01-30T14:28:29.430666Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=7): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:29.430677Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:29.430679Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMPI_Bounds"::Berlin::0
2023-01-30T14:28:29.430681Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMPI_Bounds.json"
2023-01-30T14:28:29.430682Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:29.430774Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMPI_Bounds"
2023-01-30T14:28:29.430780Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1547156,
    events_root: None,
}
2023-01-30T14:28:29.430782Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=7): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:29.430792Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:29.430794Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMPI_Bounds"::Berlin::0
2023-01-30T14:28:29.430796Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMPI_Bounds.json"
2023-01-30T14:28:29.430798Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:29.430887Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMPI_Bounds"
2023-01-30T14:28:29.430892Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1547156,
    events_root: None,
}
2023-01-30T14:28:29.430896Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=7): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:29.430905Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:29.430907Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMPI_Bounds"::London::0
2023-01-30T14:28:29.430909Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMPI_Bounds.json"
2023-01-30T14:28:29.430910Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:29.430999Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMPI_Bounds"
2023-01-30T14:28:29.431004Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1547156,
    events_root: None,
}
2023-01-30T14:28:29.431006Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=7): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:29.431015Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:29.431018Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMPI_Bounds"::London::0
2023-01-30T14:28:29.431020Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMPI_Bounds.json"
2023-01-30T14:28:29.431022Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:29.431110Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMPI_Bounds"
2023-01-30T14:28:29.431116Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1547156,
    events_root: None,
}
2023-01-30T14:28:29.431119Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=7): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:29.431127Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:29.431129Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMPI_Bounds"::Merge::0
2023-01-30T14:28:29.431131Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMPI_Bounds.json"
2023-01-30T14:28:29.431132Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:29.431221Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMPI_Bounds"
2023-01-30T14:28:29.431227Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1547156,
    events_root: None,
}
2023-01-30T14:28:29.431229Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=7): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:29.431238Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:29.431240Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMPI_Bounds"::Merge::0
2023-01-30T14:28:29.431242Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMPI_Bounds.json"
2023-01-30T14:28:29.431243Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:29.431331Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMPI_Bounds"
2023-01-30T14:28:29.431336Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1547156,
    events_root: None,
}
2023-01-30T14:28:29.431338Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=7): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:29.433010Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.083186ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "JUMPI_Bounds.json::JUMPI_Bounds": [
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:29.696991Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/JUMP_Bounds.json", Total Files :: 1
2023-01-30T14:28:29.726761Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:29.726906Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:29.726911Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:29.726968Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:29.727044Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:29.727047Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds"::Istanbul::0
2023-01-30T14:28:29.727051Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds.json"
2023-01-30T14:28:29.727053Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.077052Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds"
2023-01-30T14:28:30.077072Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1539761,
    events_root: None,
}
2023-01-30T14:28:30.077077Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=2): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.077090Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:30.077093Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds"::Istanbul::0
2023-01-30T14:28:30.077095Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds.json"
2023-01-30T14:28:30.077097Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.077219Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds"
2023-01-30T14:28:30.077224Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1539761,
    events_root: None,
}
2023-01-30T14:28:30.077227Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=2): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.077236Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:30.077238Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds"::Berlin::0
2023-01-30T14:28:30.077240Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds.json"
2023-01-30T14:28:30.077241Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.077329Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds"
2023-01-30T14:28:30.077335Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1539761,
    events_root: None,
}
2023-01-30T14:28:30.077339Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=2): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.077349Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:30.077352Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds"::Berlin::0
2023-01-30T14:28:30.077354Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds.json"
2023-01-30T14:28:30.077356Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.077460Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds"
2023-01-30T14:28:30.077466Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1539761,
    events_root: None,
}
2023-01-30T14:28:30.077470Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=2): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.077480Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:30.077483Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds"::London::0
2023-01-30T14:28:30.077485Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds.json"
2023-01-30T14:28:30.077487Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.077586Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds"
2023-01-30T14:28:30.077592Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1539761,
    events_root: None,
}
2023-01-30T14:28:30.077595Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=2): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.077602Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:30.077604Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds"::London::0
2023-01-30T14:28:30.077606Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds.json"
2023-01-30T14:28:30.077608Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.077692Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds"
2023-01-30T14:28:30.077697Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1539761,
    events_root: None,
}
2023-01-30T14:28:30.077699Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=2): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.077707Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:30.077709Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds"::Merge::0
2023-01-30T14:28:30.077710Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds.json"
2023-01-30T14:28:30.077712Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.077795Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds"
2023-01-30T14:28:30.077800Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1539761,
    events_root: None,
}
2023-01-30T14:28:30.077802Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=2): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.077810Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:30.077812Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds"::Merge::0
2023-01-30T14:28:30.077813Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds.json"
2023-01-30T14:28:30.077815Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.077899Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds"
2023-01-30T14:28:30.077905Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1539761,
    events_root: None,
}
2023-01-30T14:28:30.077908Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=2): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.079464Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:351.166468ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "JUMP_Bounds.json::JUMP_Bounds": [
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:30.340913Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/JUMP_Bounds2.json", Total Files :: 1
2023-01-30T14:28:30.371172Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:30.371312Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:30.371316Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:30.371371Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:30.371445Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:30.371448Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds2"::Istanbul::0
2023-01-30T14:28:30.371451Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds2.json"
2023-01-30T14:28:30.371453Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.754961Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds2"
2023-01-30T14:28:30.754983Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1545603,
    events_root: None,
}
2023-01-30T14:28:30.754989Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=5): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.755002Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:30.755005Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds2"::Istanbul::0
2023-01-30T14:28:30.755007Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds2.json"
2023-01-30T14:28:30.755009Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.755134Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds2"
2023-01-30T14:28:30.755141Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1545603,
    events_root: None,
}
2023-01-30T14:28:30.755144Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=5): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.755154Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:30.755156Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds2"::Berlin::0
2023-01-30T14:28:30.755158Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds2.json"
2023-01-30T14:28:30.755160Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.755249Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds2"
2023-01-30T14:28:30.755254Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1545603,
    events_root: None,
}
2023-01-30T14:28:30.755257Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=5): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.755266Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:30.755270Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds2"::Berlin::0
2023-01-30T14:28:30.755271Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds2.json"
2023-01-30T14:28:30.755273Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.755365Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds2"
2023-01-30T14:28:30.755371Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1545603,
    events_root: None,
}
2023-01-30T14:28:30.755373Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=5): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.755382Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:30.755383Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds2"::London::0
2023-01-30T14:28:30.755386Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds2.json"
2023-01-30T14:28:30.755387Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.755475Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds2"
2023-01-30T14:28:30.755481Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1545603,
    events_root: None,
}
2023-01-30T14:28:30.755483Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=5): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.755492Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:30.755494Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds2"::London::0
2023-01-30T14:28:30.755495Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds2.json"
2023-01-30T14:28:30.755497Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.755584Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds2"
2023-01-30T14:28:30.755589Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1545603,
    events_root: None,
}
2023-01-30T14:28:30.755593Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=5): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.755601Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:30.755603Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds2"::Merge::0
2023-01-30T14:28:30.755605Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds2.json"
2023-01-30T14:28:30.755607Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.755692Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds2"
2023-01-30T14:28:30.755699Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1545603,
    events_root: None,
}
2023-01-30T14:28:30.755701Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=5): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.755710Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:30.755711Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "JUMP_Bounds2"::Merge::0
2023-01-30T14:28:30.755713Z  INFO evm_eth_compliance::statetest::executor: Path : "JUMP_Bounds2.json"
2023-01-30T14:28:30.755714Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:30.755800Z  INFO evm_eth_compliance::statetest::executor: UC : "JUMP_Bounds2"
2023-01-30T14:28:30.755806Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1545603,
    events_root: None,
}
2023-01-30T14:28:30.755809Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=5): jumpdest 4294967295 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:30.757394Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:384.65427ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "JUMP_Bounds2.json::JUMP_Bounds2": [
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:31.016615Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/MLOAD_Bounds.json", Total Files :: 1
2023-01-30T14:28:31.046251Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:31.046389Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:31.046392Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:31.046448Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:31.046521Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:31.046524Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds"::Istanbul::0
2023-01-30T14:28:31.046526Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds.json"
2023-01-30T14:28:31.046528Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:31.419572Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds"
2023-01-30T14:28:31.419594Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540772,
    events_root: None,
}
2023-01-30T14:28:31.419599Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:31.419612Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:31.419616Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds"::Istanbul::0
2023-01-30T14:28:31.419618Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds.json"
2023-01-30T14:28:31.419619Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:31.419756Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds"
2023-01-30T14:28:31.419763Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540772,
    events_root: None,
}
2023-01-30T14:28:31.419767Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:31.419778Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:31.419781Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds"::Berlin::0
2023-01-30T14:28:31.419783Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds.json"
2023-01-30T14:28:31.419785Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:31.419898Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds"
2023-01-30T14:28:31.419904Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540772,
    events_root: None,
}
2023-01-30T14:28:31.419908Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:31.419920Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:31.419922Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds"::Berlin::0
2023-01-30T14:28:31.419923Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds.json"
2023-01-30T14:28:31.419925Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:31.420018Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds"
2023-01-30T14:28:31.420023Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540772,
    events_root: None,
}
2023-01-30T14:28:31.420026Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:31.420036Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:31.420038Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds"::London::0
2023-01-30T14:28:31.420040Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds.json"
2023-01-30T14:28:31.420041Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:31.420129Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds"
2023-01-30T14:28:31.420134Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540772,
    events_root: None,
}
2023-01-30T14:28:31.420137Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:31.420145Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:31.420147Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds"::London::0
2023-01-30T14:28:31.420149Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds.json"
2023-01-30T14:28:31.420150Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:31.420238Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds"
2023-01-30T14:28:31.420244Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540772,
    events_root: None,
}
2023-01-30T14:28:31.420247Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:31.420255Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:31.420257Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds"::Merge::0
2023-01-30T14:28:31.420259Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds.json"
2023-01-30T14:28:31.420260Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:31.420358Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds"
2023-01-30T14:28:31.420364Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540772,
    events_root: None,
}
2023-01-30T14:28:31.420368Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:31.420379Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:31.420381Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds"::Merge::0
2023-01-30T14:28:31.420383Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds.json"
2023-01-30T14:28:31.420385Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:31.420483Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds"
2023-01-30T14:28:31.420490Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540772,
    events_root: None,
}
2023-01-30T14:28:31.420492Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:31.422263Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.25835ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "MLOAD_Bounds.json::MLOAD_Bounds": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:31.706508Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/MLOAD_Bounds2.json", Total Files :: 1
2023-01-30T14:28:31.760203Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:31.760352Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:31.760357Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:31.760430Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:31.760541Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:31.760546Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds2"::Istanbul::0
2023-01-30T14:28:31.760550Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds2.json"
2023-01-30T14:28:31.760553Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.145834Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds2"
2023-01-30T14:28:32.145902Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540783,
    events_root: None,
}
2023-01-30T14:28:32.145917Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:32.145944Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:32.145954Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds2"::Istanbul::0
2023-01-30T14:28:32.145961Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds2.json"
2023-01-30T14:28:32.145966Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.146095Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds2"
2023-01-30T14:28:32.146110Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540783,
    events_root: None,
}
2023-01-30T14:28:32.146119Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:32.146137Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:32.146143Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds2"::Berlin::0
2023-01-30T14:28:32.146149Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds2.json"
2023-01-30T14:28:32.146154Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.146270Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds2"
2023-01-30T14:28:32.146295Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540783,
    events_root: None,
}
2023-01-30T14:28:32.146304Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:32.146321Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:32.146327Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds2"::Berlin::0
2023-01-30T14:28:32.146333Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds2.json"
2023-01-30T14:28:32.146338Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.146446Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds2"
2023-01-30T14:28:32.146459Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540783,
    events_root: None,
}
2023-01-30T14:28:32.146467Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:32.146484Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:32.146490Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds2"::London::0
2023-01-30T14:28:32.146496Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds2.json"
2023-01-30T14:28:32.146502Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.146599Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds2"
2023-01-30T14:28:32.146612Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540783,
    events_root: None,
}
2023-01-30T14:28:32.146621Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:32.146637Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:32.146643Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds2"::London::0
2023-01-30T14:28:32.146648Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds2.json"
2023-01-30T14:28:32.146654Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.146752Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds2"
2023-01-30T14:28:32.146765Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540783,
    events_root: None,
}
2023-01-30T14:28:32.146773Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:32.146789Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:32.146795Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds2"::Merge::0
2023-01-30T14:28:32.146801Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds2.json"
2023-01-30T14:28:32.146807Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.146908Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds2"
2023-01-30T14:28:32.146920Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540783,
    events_root: None,
}
2023-01-30T14:28:32.146929Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:32.146945Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:32.146951Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds2"::Merge::0
2023-01-30T14:28:32.146956Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds2.json"
2023-01-30T14:28:32.146962Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.147060Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds2"
2023-01-30T14:28:32.147074Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540783,
    events_root: None,
}
2023-01-30T14:28:32.147082Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=9): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:32.148743Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:386.905224ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "MLOAD_Bounds2.json::MLOAD_Bounds2": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:32.414424Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/MLOAD_Bounds3.json", Total Files :: 1
2023-01-30T14:28:32.444302Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:32.444463Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:32.444469Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:32.444524Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:32.444597Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:32.444600Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds3"::Istanbul::0
2023-01-30T14:28:32.444603Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds3.json"
2023-01-30T14:28:32.444606Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.851563Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds3"
2023-01-30T14:28:32.851584Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4978427,
    events_root: None,
}
2023-01-30T14:28:32.851593Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:32.851597Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds3"::Istanbul::0
2023-01-30T14:28:32.851599Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds3.json"
2023-01-30T14:28:32.851601Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.852482Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds3"
2023-01-30T14:28:32.852489Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4978427,
    events_root: None,
}
2023-01-30T14:28:32.852494Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:32.852495Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds3"::Berlin::0
2023-01-30T14:28:32.852497Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds3.json"
2023-01-30T14:28:32.852499Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.853344Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds3"
2023-01-30T14:28:32.853350Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4978427,
    events_root: None,
}
2023-01-30T14:28:32.853355Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:32.853356Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds3"::Berlin::0
2023-01-30T14:28:32.853358Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds3.json"
2023-01-30T14:28:32.853360Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.854192Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds3"
2023-01-30T14:28:32.854198Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4978427,
    events_root: None,
}
2023-01-30T14:28:32.854203Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:32.854205Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds3"::London::0
2023-01-30T14:28:32.854206Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds3.json"
2023-01-30T14:28:32.854208Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.855039Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds3"
2023-01-30T14:28:32.855044Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4978427,
    events_root: None,
}
2023-01-30T14:28:32.855049Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:32.855052Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds3"::London::0
2023-01-30T14:28:32.855053Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds3.json"
2023-01-30T14:28:32.855055Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.855887Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds3"
2023-01-30T14:28:32.855893Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4978427,
    events_root: None,
}
2023-01-30T14:28:32.855898Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:32.855899Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds3"::Merge::0
2023-01-30T14:28:32.855901Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds3.json"
2023-01-30T14:28:32.855903Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.856738Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds3"
2023-01-30T14:28:32.856744Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4978427,
    events_root: None,
}
2023-01-30T14:28:32.856748Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:32.856750Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MLOAD_Bounds3"::Merge::0
2023-01-30T14:28:32.856751Z  INFO evm_eth_compliance::statetest::executor: Path : "MLOAD_Bounds3.json"
2023-01-30T14:28:32.856753Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:32.857623Z  INFO evm_eth_compliance::statetest::executor: UC : "MLOAD_Bounds3"
2023-01-30T14:28:32.857629Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4978427,
    events_root: None,
}
2023-01-30T14:28:32.859175Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:413.340197ms
=== Start ===
=== OK Status ===
Count :: 1
{
    "MLOAD_Bounds3.json::MLOAD_Bounds3": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:33.128118Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/MSTORE_Bounds.json", Total Files :: 1
2023-01-30T14:28:33.158459Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:33.158600Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:33.158604Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:33.158661Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:33.158733Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:33.158736Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds"::Istanbul::0
2023-01-30T14:28:33.158739Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds.json"
2023-01-30T14:28:33.158741Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:33.512853Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds"
2023-01-30T14:28:33.512877Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540247,
    events_root: None,
}
2023-01-30T14:28:33.512884Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=11): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:33.512899Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:33.512903Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds"::Istanbul::0
2023-01-30T14:28:33.512906Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds.json"
2023-01-30T14:28:33.512908Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:33.513070Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds"
2023-01-30T14:28:33.513078Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540247,
    events_root: None,
}
2023-01-30T14:28:33.513082Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=11): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:33.513093Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:33.513095Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds"::Berlin::0
2023-01-30T14:28:33.513098Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds.json"
2023-01-30T14:28:33.513100Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:33.513221Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds"
2023-01-30T14:28:33.513228Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540247,
    events_root: None,
}
2023-01-30T14:28:33.513232Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=11): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:33.513243Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:33.513245Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds"::Berlin::0
2023-01-30T14:28:33.513248Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds.json"
2023-01-30T14:28:33.513250Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:33.513368Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds"
2023-01-30T14:28:33.513375Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540247,
    events_root: None,
}
2023-01-30T14:28:33.513378Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=11): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:33.513390Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:33.513392Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds"::London::0
2023-01-30T14:28:33.513395Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds.json"
2023-01-30T14:28:33.513397Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:33.513502Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds"
2023-01-30T14:28:33.513509Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540247,
    events_root: None,
}
2023-01-30T14:28:33.513512Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=11): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:33.513522Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:33.513524Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds"::London::0
2023-01-30T14:28:33.513526Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds.json"
2023-01-30T14:28:33.513529Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:33.513640Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds"
2023-01-30T14:28:33.513647Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540247,
    events_root: None,
}
2023-01-30T14:28:33.513650Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=11): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:33.513658Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:33.513661Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds"::Merge::0
2023-01-30T14:28:33.513662Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds.json"
2023-01-30T14:28:33.513664Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:33.513755Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds"
2023-01-30T14:28:33.513760Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540247,
    events_root: None,
}
2023-01-30T14:28:33.513764Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=11): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:33.513772Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:33.513774Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds"::Merge::0
2023-01-30T14:28:33.513776Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds.json"
2023-01-30T14:28:33.513777Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:33.513862Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds"
2023-01-30T14:28:33.513867Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1540247,
    events_root: None,
}
2023-01-30T14:28:33.513870Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=11): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:33.515481Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.427901ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "MSTORE_Bounds.json::MSTORE_Bounds": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:33.788355Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/MSTORE_Bounds2.json", Total Files :: 1
2023-01-30T14:28:33.841534Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:33.841678Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:33.841682Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:33.841741Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:33.841818Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:33.841822Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2"::Istanbul::0
2023-01-30T14:28:33.841826Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2.json"
2023-01-30T14:28:33.841828Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.198329Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2"
2023-01-30T14:28:34.198349Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1537323,
    events_root: None,
}
2023-01-30T14:28:34.198356Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=8): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:34.198368Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:34.198372Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2"::Istanbul::0
2023-01-30T14:28:34.198374Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2.json"
2023-01-30T14:28:34.198375Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.198518Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2"
2023-01-30T14:28:34.198525Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1537323,
    events_root: None,
}
2023-01-30T14:28:34.198529Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=8): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:34.198540Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:34.198543Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2"::Berlin::0
2023-01-30T14:28:34.198545Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2.json"
2023-01-30T14:28:34.198547Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.198652Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2"
2023-01-30T14:28:34.198659Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1537323,
    events_root: None,
}
2023-01-30T14:28:34.198662Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=8): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:34.198673Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:34.198675Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2"::Berlin::0
2023-01-30T14:28:34.198678Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2.json"
2023-01-30T14:28:34.198680Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.198784Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2"
2023-01-30T14:28:34.198789Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1537323,
    events_root: None,
}
2023-01-30T14:28:34.198792Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=8): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:34.198801Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:34.198803Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2"::London::0
2023-01-30T14:28:34.198804Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2.json"
2023-01-30T14:28:34.198806Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.198894Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2"
2023-01-30T14:28:34.198900Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1537323,
    events_root: None,
}
2023-01-30T14:28:34.198904Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=8): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:34.198915Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:34.198918Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2"::London::0
2023-01-30T14:28:34.198920Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2.json"
2023-01-30T14:28:34.198923Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.199032Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2"
2023-01-30T14:28:34.199038Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1537323,
    events_root: None,
}
2023-01-30T14:28:34.199042Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=8): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:34.199052Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:34.199055Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2"::Merge::0
2023-01-30T14:28:34.199057Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2.json"
2023-01-30T14:28:34.199059Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.199169Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2"
2023-01-30T14:28:34.199177Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1537323,
    events_root: None,
}
2023-01-30T14:28:34.199180Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=8): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:34.199190Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:34.199192Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2"::Merge::0
2023-01-30T14:28:34.199193Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2.json"
2023-01-30T14:28:34.199195Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.199285Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2"
2023-01-30T14:28:34.199291Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1537323,
    events_root: None,
}
2023-01-30T14:28:34.199294Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=8): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:34.201007Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.777027ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "MSTORE_Bounds2.json::MSTORE_Bounds2": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:34.469258Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/MSTORE_Bounds2a.json", Total Files :: 1
2023-01-30T14:28:34.499973Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:34.500112Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:34.500117Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:34.500172Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:34.500246Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:34.500248Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2a"::Istanbul::0
2023-01-30T14:28:34.500251Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2a.json"
2023-01-30T14:28:34.500253Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.904997Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2a"
2023-01-30T14:28:34.905019Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4979007,
    events_root: None,
}
2023-01-30T14:28:34.905029Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:34.905033Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2a"::Istanbul::0
2023-01-30T14:28:34.905035Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2a.json"
2023-01-30T14:28:34.905036Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.905930Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2a"
2023-01-30T14:28:34.905936Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4979007,
    events_root: None,
}
2023-01-30T14:28:34.905941Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:34.905944Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2a"::Berlin::0
2023-01-30T14:28:34.905946Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2a.json"
2023-01-30T14:28:34.905948Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.906801Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2a"
2023-01-30T14:28:34.906806Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4979007,
    events_root: None,
}
2023-01-30T14:28:34.906811Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:34.906812Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2a"::Berlin::0
2023-01-30T14:28:34.906814Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2a.json"
2023-01-30T14:28:34.906816Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.907653Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2a"
2023-01-30T14:28:34.907659Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4979007,
    events_root: None,
}
2023-01-30T14:28:34.907663Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:34.907665Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2a"::London::0
2023-01-30T14:28:34.907667Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2a.json"
2023-01-30T14:28:34.907668Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.908547Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2a"
2023-01-30T14:28:34.908553Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4979007,
    events_root: None,
}
2023-01-30T14:28:34.908558Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:34.908560Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2a"::London::0
2023-01-30T14:28:34.908562Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2a.json"
2023-01-30T14:28:34.908564Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.909491Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2a"
2023-01-30T14:28:34.909498Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4979007,
    events_root: None,
}
2023-01-30T14:28:34.909503Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:34.909506Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2a"::Merge::0
2023-01-30T14:28:34.909508Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2a.json"
2023-01-30T14:28:34.909510Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.910451Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2a"
2023-01-30T14:28:34.910460Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4979007,
    events_root: None,
}
2023-01-30T14:28:34.910467Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:34.910470Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "MSTORE_Bounds2a"::Merge::0
2023-01-30T14:28:34.910472Z  INFO evm_eth_compliance::statetest::executor: Path : "MSTORE_Bounds2a.json"
2023-01-30T14:28:34.910474Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:34.911602Z  INFO evm_eth_compliance::statetest::executor: UC : "MSTORE_Bounds2a"
2023-01-30T14:28:34.911616Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4979007,
    events_root: None,
}
2023-01-30T14:28:34.913627Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:411.661535ms
=== Start ===
=== OK Status ===
Count :: 1
{
    "MSTORE_Bounds2a.json::MSTORE_Bounds2a": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:35.174317Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/POP_Bounds.json", Total Files :: 1
2023-01-30T14:28:35.204453Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:35.204590Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.204594Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:35.204649Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.204719Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:35.204722Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "POP_Bounds"::Istanbul::0
2023-01-30T14:28:35.204725Z  INFO evm_eth_compliance::statetest::executor: Path : "POP_Bounds.json"
2023-01-30T14:28:35.204727Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:35.575219Z  INFO evm_eth_compliance::statetest::executor: UC : "POP_Bounds"
2023-01-30T14:28:35.575240Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1531510,
    events_root: None,
}
2023-01-30T14:28:35.575249Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:35.575253Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "POP_Bounds"::Istanbul::0
2023-01-30T14:28:35.575255Z  INFO evm_eth_compliance::statetest::executor: Path : "POP_Bounds.json"
2023-01-30T14:28:35.575257Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:35.575362Z  INFO evm_eth_compliance::statetest::executor: UC : "POP_Bounds"
2023-01-30T14:28:35.575368Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1531510,
    events_root: None,
}
2023-01-30T14:28:35.575374Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:35.575375Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "POP_Bounds"::Berlin::0
2023-01-30T14:28:35.575377Z  INFO evm_eth_compliance::statetest::executor: Path : "POP_Bounds.json"
2023-01-30T14:28:35.575379Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:35.575464Z  INFO evm_eth_compliance::statetest::executor: UC : "POP_Bounds"
2023-01-30T14:28:35.575468Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1531510,
    events_root: None,
}
2023-01-30T14:28:35.575473Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:35.575475Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "POP_Bounds"::Berlin::0
2023-01-30T14:28:35.575476Z  INFO evm_eth_compliance::statetest::executor: Path : "POP_Bounds.json"
2023-01-30T14:28:35.575478Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:35.575558Z  INFO evm_eth_compliance::statetest::executor: UC : "POP_Bounds"
2023-01-30T14:28:35.575563Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1531510,
    events_root: None,
}
2023-01-30T14:28:35.575568Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:35.575569Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "POP_Bounds"::London::0
2023-01-30T14:28:35.575572Z  INFO evm_eth_compliance::statetest::executor: Path : "POP_Bounds.json"
2023-01-30T14:28:35.575574Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:35.575667Z  INFO evm_eth_compliance::statetest::executor: UC : "POP_Bounds"
2023-01-30T14:28:35.575674Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1531510,
    events_root: None,
}
2023-01-30T14:28:35.575679Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:35.575680Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "POP_Bounds"::London::0
2023-01-30T14:28:35.575682Z  INFO evm_eth_compliance::statetest::executor: Path : "POP_Bounds.json"
2023-01-30T14:28:35.575685Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:35.575769Z  INFO evm_eth_compliance::statetest::executor: UC : "POP_Bounds"
2023-01-30T14:28:35.575774Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1531510,
    events_root: None,
}
2023-01-30T14:28:35.575778Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:35.575780Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "POP_Bounds"::Merge::0
2023-01-30T14:28:35.575782Z  INFO evm_eth_compliance::statetest::executor: Path : "POP_Bounds.json"
2023-01-30T14:28:35.575783Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:35.575863Z  INFO evm_eth_compliance::statetest::executor: UC : "POP_Bounds"
2023-01-30T14:28:35.575868Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1531510,
    events_root: None,
}
2023-01-30T14:28:35.575872Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:35.575874Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "POP_Bounds"::Merge::0
2023-01-30T14:28:35.575876Z  INFO evm_eth_compliance::statetest::executor: Path : "POP_Bounds.json"
2023-01-30T14:28:35.575877Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:35.575957Z  INFO evm_eth_compliance::statetest::executor: UC : "POP_Bounds"
2023-01-30T14:28:35.575962Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1531510,
    events_root: None,
}
2023-01-30T14:28:35.577525Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.5217ms
=== Start ===
=== OK Status ===
Count :: 1
{
    "POP_Bounds.json::POP_Bounds": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:35.848008Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/RETURN_Bounds.json", Total Files :: 1
2023-01-30T14:28:35.899367Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:35.899508Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.899511Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:35.899565Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.899568Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:35.899626Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.899628Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 3
2023-01-30T14:28:35.899682Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.899685Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 4
2023-01-30T14:28:35.899734Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.899736Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 5
2023-01-30T14:28:35.899799Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.899802Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 6
2023-01-30T14:28:35.899859Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.899861Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 7
2023-01-30T14:28:35.899902Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.899905Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 8
2023-01-30T14:28:35.899945Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.899946Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 9
2023-01-30T14:28:35.900000Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.900002Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 10
2023-01-30T14:28:35.900045Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.900047Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 11
2023-01-30T14:28:35.900091Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.900094Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 12
2023-01-30T14:28:35.900144Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.900147Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 13
2023-01-30T14:28:35.900197Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.900199Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 14
2023-01-30T14:28:35.900258Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.900261Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 15
2023-01-30T14:28:35.900308Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.900310Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 16
2023-01-30T14:28:35.900348Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.900350Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 17
2023-01-30T14:28:35.900399Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:35.900472Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:35.900475Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::Istanbul::0
2023-01-30T14:28:35.900478Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:35.900479Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.245914Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.245933Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 56474055,
    events_root: None,
}
2023-01-30T14:28:36.245992Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:36.245996Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::Istanbul::0
2023-01-30T14:28:36.245998Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.246000Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.247705Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.247713Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.247757Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:36.247760Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::Istanbul::0
2023-01-30T14:28:36.247762Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.247763Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.249478Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.249485Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.249530Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:36.249533Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::Berlin::0
2023-01-30T14:28:36.249534Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.249536Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.251231Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.251237Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.251282Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:36.251284Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::Berlin::0
2023-01-30T14:28:36.251286Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.251287Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.252977Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.252988Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.253033Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:36.253035Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::Berlin::0
2023-01-30T14:28:36.253037Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.253038Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.254726Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.254732Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.254777Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:36.254780Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::London::0
2023-01-30T14:28:36.254781Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.254783Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.256510Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.256516Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.256566Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:36.256569Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::London::0
2023-01-30T14:28:36.256570Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.256572Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.258289Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.258295Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.258341Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:36.258344Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::London::0
2023-01-30T14:28:36.258345Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.258347Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.260033Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.260040Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.260084Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:36.260086Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::Merge::0
2023-01-30T14:28:36.260089Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.260091Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.261820Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.261827Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.261872Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:36.261875Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::Merge::0
2023-01-30T14:28:36.261876Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.261878Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.263548Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.263556Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.263599Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:36.263602Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "RETURN_Bounds"::Merge::0
2023-01-30T14:28:36.263603Z  INFO evm_eth_compliance::statetest::executor: Path : "RETURN_Bounds.json"
2023-01-30T14:28:36.263605Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.265362Z  INFO evm_eth_compliance::statetest::executor: UC : "RETURN_Bounds"
2023-01-30T14:28:36.265370Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 29073529,
    events_root: None,
}
2023-01-30T14:28:36.267424Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.07515ms
=== Start ===
=== OK Status ===
Count :: 1
{
    "RETURN_Bounds.json::RETURN_Bounds": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:36.527386Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/SLOAD_Bounds.json", Total Files :: 1
2023-01-30T14:28:36.557579Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:36.557723Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:36.557727Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:36.557782Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:36.557856Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:36.557859Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SLOAD_Bounds"::Istanbul::0
2023-01-30T14:28:36.557862Z  INFO evm_eth_compliance::statetest::executor: Path : "SLOAD_Bounds.json"
2023-01-30T14:28:36.557864Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.923497Z  INFO evm_eth_compliance::statetest::executor: UC : "SLOAD_Bounds"
2023-01-30T14:28:36.923521Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1546104,
    events_root: None,
}
2023-01-30T14:28:36.923534Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:36.923539Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SLOAD_Bounds"::Istanbul::0
2023-01-30T14:28:36.923542Z  INFO evm_eth_compliance::statetest::executor: Path : "SLOAD_Bounds.json"
2023-01-30T14:28:36.923544Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.923674Z  INFO evm_eth_compliance::statetest::executor: UC : "SLOAD_Bounds"
2023-01-30T14:28:36.923681Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1546104,
    events_root: None,
}
2023-01-30T14:28:36.923687Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:36.923690Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SLOAD_Bounds"::Berlin::0
2023-01-30T14:28:36.923692Z  INFO evm_eth_compliance::statetest::executor: Path : "SLOAD_Bounds.json"
2023-01-30T14:28:36.923695Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.923789Z  INFO evm_eth_compliance::statetest::executor: UC : "SLOAD_Bounds"
2023-01-30T14:28:36.923797Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1546104,
    events_root: None,
}
2023-01-30T14:28:36.923809Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:36.923812Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SLOAD_Bounds"::Berlin::0
2023-01-30T14:28:36.923814Z  INFO evm_eth_compliance::statetest::executor: Path : "SLOAD_Bounds.json"
2023-01-30T14:28:36.923816Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.923937Z  INFO evm_eth_compliance::statetest::executor: UC : "SLOAD_Bounds"
2023-01-30T14:28:36.923945Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1546104,
    events_root: None,
}
2023-01-30T14:28:36.923951Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:36.923954Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SLOAD_Bounds"::London::0
2023-01-30T14:28:36.923956Z  INFO evm_eth_compliance::statetest::executor: Path : "SLOAD_Bounds.json"
2023-01-30T14:28:36.923958Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.924053Z  INFO evm_eth_compliance::statetest::executor: UC : "SLOAD_Bounds"
2023-01-30T14:28:36.924058Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1546104,
    events_root: None,
}
2023-01-30T14:28:36.924063Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:36.924065Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SLOAD_Bounds"::London::0
2023-01-30T14:28:36.924068Z  INFO evm_eth_compliance::statetest::executor: Path : "SLOAD_Bounds.json"
2023-01-30T14:28:36.924070Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.924154Z  INFO evm_eth_compliance::statetest::executor: UC : "SLOAD_Bounds"
2023-01-30T14:28:36.924159Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1546104,
    events_root: None,
}
2023-01-30T14:28:36.924165Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:36.924167Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SLOAD_Bounds"::Merge::0
2023-01-30T14:28:36.924169Z  INFO evm_eth_compliance::statetest::executor: Path : "SLOAD_Bounds.json"
2023-01-30T14:28:36.924170Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.924255Z  INFO evm_eth_compliance::statetest::executor: UC : "SLOAD_Bounds"
2023-01-30T14:28:36.924260Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1546104,
    events_root: None,
}
2023-01-30T14:28:36.924264Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:36.924266Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SLOAD_Bounds"::Merge::0
2023-01-30T14:28:36.924269Z  INFO evm_eth_compliance::statetest::executor: Path : "SLOAD_Bounds.json"
2023-01-30T14:28:36.924270Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:36.924356Z  INFO evm_eth_compliance::statetest::executor: UC : "SLOAD_Bounds"
2023-01-30T14:28:36.924361Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1546104,
    events_root: None,
}
2023-01-30T14:28:36.926144Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.794496ms
=== Start ===
=== OK Status ===
Count :: 1
{
    "SLOAD_Bounds.json::SLOAD_Bounds": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:37.185140Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/SSTORE_Bounds.json", Total Files :: 1
2023-01-30T14:28:37.237208Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:37.237344Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:37.237347Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:37.237399Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:37.237469Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:37.237472Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SSTORE_Bounds"::Istanbul::0
2023-01-30T14:28:37.237476Z  INFO evm_eth_compliance::statetest::executor: Path : "SSTORE_Bounds.json"
2023-01-30T14:28:37.237477Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:37.574262Z  INFO evm_eth_compliance::statetest::executor: UC : "SSTORE_Bounds"
2023-01-30T14:28:37.574282Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5136671,
    events_root: None,
}
2023-01-30T14:28:37.574292Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:37.574296Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SSTORE_Bounds"::Istanbul::0
2023-01-30T14:28:37.574298Z  INFO evm_eth_compliance::statetest::executor: Path : "SSTORE_Bounds.json"
2023-01-30T14:28:37.574300Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:37.574475Z  INFO evm_eth_compliance::statetest::executor: UC : "SSTORE_Bounds"
2023-01-30T14:28:37.574480Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3206820,
    events_root: None,
}
2023-01-30T14:28:37.574486Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:37.574488Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SSTORE_Bounds"::Berlin::0
2023-01-30T14:28:37.574490Z  INFO evm_eth_compliance::statetest::executor: Path : "SSTORE_Bounds.json"
2023-01-30T14:28:37.574492Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:37.574639Z  INFO evm_eth_compliance::statetest::executor: UC : "SSTORE_Bounds"
2023-01-30T14:28:37.574644Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3206820,
    events_root: None,
}
2023-01-30T14:28:37.574649Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:37.574651Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SSTORE_Bounds"::Berlin::0
2023-01-30T14:28:37.574653Z  INFO evm_eth_compliance::statetest::executor: Path : "SSTORE_Bounds.json"
2023-01-30T14:28:37.574654Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:37.574798Z  INFO evm_eth_compliance::statetest::executor: UC : "SSTORE_Bounds"
2023-01-30T14:28:37.574803Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3206820,
    events_root: None,
}
2023-01-30T14:28:37.574808Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:37.574811Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SSTORE_Bounds"::London::0
2023-01-30T14:28:37.574812Z  INFO evm_eth_compliance::statetest::executor: Path : "SSTORE_Bounds.json"
2023-01-30T14:28:37.574815Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:37.574959Z  INFO evm_eth_compliance::statetest::executor: UC : "SSTORE_Bounds"
2023-01-30T14:28:37.574964Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3206820,
    events_root: None,
}
2023-01-30T14:28:37.574969Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:37.574971Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SSTORE_Bounds"::London::0
2023-01-30T14:28:37.574973Z  INFO evm_eth_compliance::statetest::executor: Path : "SSTORE_Bounds.json"
2023-01-30T14:28:37.574975Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:37.575118Z  INFO evm_eth_compliance::statetest::executor: UC : "SSTORE_Bounds"
2023-01-30T14:28:37.575123Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3206820,
    events_root: None,
}
2023-01-30T14:28:37.575128Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:37.575130Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SSTORE_Bounds"::Merge::0
2023-01-30T14:28:37.575132Z  INFO evm_eth_compliance::statetest::executor: Path : "SSTORE_Bounds.json"
2023-01-30T14:28:37.575134Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:37.575281Z  INFO evm_eth_compliance::statetest::executor: UC : "SSTORE_Bounds"
2023-01-30T14:28:37.575286Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3206820,
    events_root: None,
}
2023-01-30T14:28:37.575291Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:37.575293Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "SSTORE_Bounds"::Merge::0
2023-01-30T14:28:37.575295Z  INFO evm_eth_compliance::statetest::executor: Path : "SSTORE_Bounds.json"
2023-01-30T14:28:37.575297Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:37.575439Z  INFO evm_eth_compliance::statetest::executor: UC : "SSTORE_Bounds"
2023-01-30T14:28:37.575444Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3206820,
    events_root: None,
}
2023-01-30T14:28:37.577060Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:338.248608ms
=== Start ===
=== OK Status ===
Count :: 1
{
    "SSTORE_Bounds.json::SSTORE_Bounds": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:37.858776Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/mload32bitBound.json", Total Files :: 1
2023-01-30T14:28:37.888697Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:37.888832Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:37.888835Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:37.888887Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:37.888958Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:37.888961Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound"::Istanbul::0
2023-01-30T14:28:37.888964Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound.json"
2023-01-30T14:28:37.888966Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.241660Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound"
2023-01-30T14:28:38.241682Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.241689Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.241703Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:38.241706Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound"::Istanbul::0
2023-01-30T14:28:38.241708Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound.json"
2023-01-30T14:28:38.241710Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.241850Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound"
2023-01-30T14:28:38.241858Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.241861Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.241874Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:38.241877Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound"::Berlin::0
2023-01-30T14:28:38.241879Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound.json"
2023-01-30T14:28:38.241881Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.241996Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound"
2023-01-30T14:28:38.242003Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.242006Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.242015Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:38.242017Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound"::Berlin::0
2023-01-30T14:28:38.242019Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound.json"
2023-01-30T14:28:38.242021Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.242111Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound"
2023-01-30T14:28:38.242117Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.242120Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.242130Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:38.242131Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound"::London::0
2023-01-30T14:28:38.242133Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound.json"
2023-01-30T14:28:38.242135Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.242221Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound"
2023-01-30T14:28:38.242229Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.242232Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.242243Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:38.242245Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound"::London::0
2023-01-30T14:28:38.242248Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound.json"
2023-01-30T14:28:38.242250Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.242336Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound"
2023-01-30T14:28:38.242341Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.242344Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.242352Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:38.242354Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound"::Merge::0
2023-01-30T14:28:38.242357Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound.json"
2023-01-30T14:28:38.242359Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.242457Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound"
2023-01-30T14:28:38.242463Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.242466Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.242475Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:38.242477Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound"::Merge::0
2023-01-30T14:28:38.242480Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound.json"
2023-01-30T14:28:38.242483Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.242572Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound"
2023-01-30T14:28:38.242578Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.242580Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.244459Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:353.900364ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "mload32bitBound.json::mload32bitBound": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:38.497212Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/mload32bitBound2.json", Total Files :: 1
2023-01-30T14:28:38.527232Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:38.527373Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:38.527376Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:38.527431Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:38.527522Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:38.527527Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound2"::Istanbul::0
2023-01-30T14:28:38.527531Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound2.json"
2023-01-30T14:28:38.527534Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.904625Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound2"
2023-01-30T14:28:38.904643Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.904649Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.904662Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:38.904665Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound2"::Istanbul::0
2023-01-30T14:28:38.904666Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound2.json"
2023-01-30T14:28:38.904668Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.904784Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound2"
2023-01-30T14:28:38.904790Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.904793Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.904802Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:38.904804Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound2"::Berlin::0
2023-01-30T14:28:38.904806Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound2.json"
2023-01-30T14:28:38.904807Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.904893Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound2"
2023-01-30T14:28:38.904900Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.904902Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.904910Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:38.904912Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound2"::Berlin::0
2023-01-30T14:28:38.904914Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound2.json"
2023-01-30T14:28:38.904916Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.905011Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound2"
2023-01-30T14:28:38.905017Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.905019Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.905027Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:38.905029Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound2"::London::0
2023-01-30T14:28:38.905031Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound2.json"
2023-01-30T14:28:38.905034Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.905120Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound2"
2023-01-30T14:28:38.905126Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.905128Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.905137Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:38.905138Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound2"::London::0
2023-01-30T14:28:38.905140Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound2.json"
2023-01-30T14:28:38.905142Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.905240Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound2"
2023-01-30T14:28:38.905246Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.905248Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.905257Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:38.905259Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound2"::Merge::0
2023-01-30T14:28:38.905261Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound2.json"
2023-01-30T14:28:38.905262Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.905348Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound2"
2023-01-30T14:28:38.905353Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.905356Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.905364Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:38.905366Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound2"::Merge::0
2023-01-30T14:28:38.905367Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound2.json"
2023-01-30T14:28:38.905369Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:38.905452Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound2"
2023-01-30T14:28:38.905457Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1536762,
    events_root: None,
}
2023-01-30T14:28:38.905460Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=6): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:38.906952Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:378.243413ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "mload32bitBound2.json::mload32bitBound2": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:39.179188Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/mload32bitBound_Msize.json", Total Files :: 1
2023-01-30T14:28:39.209410Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:39.209588Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:39.209593Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:39.209662Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:39.209759Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:39.209763Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_Msize"::Istanbul::0
2023-01-30T14:28:39.209766Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_Msize.json"
2023-01-30T14:28:39.209769Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:39.589428Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_Msize"
2023-01-30T14:28:39.589449Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1541027,
    events_root: None,
}
2023-01-30T14:28:39.589454Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=7): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:39.589467Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:39.589470Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_Msize"::Istanbul::0
2023-01-30T14:28:39.589472Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_Msize.json"
2023-01-30T14:28:39.589474Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:39.589594Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_Msize"
2023-01-30T14:28:39.589600Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1541027,
    events_root: None,
}
2023-01-30T14:28:39.589603Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=7): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:39.589612Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:39.589616Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_Msize"::Berlin::0
2023-01-30T14:28:39.589618Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_Msize.json"
2023-01-30T14:28:39.589619Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:39.589706Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_Msize"
2023-01-30T14:28:39.589713Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1541027,
    events_root: None,
}
2023-01-30T14:28:39.589716Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=7): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:39.589724Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:39.589726Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_Msize"::Berlin::0
2023-01-30T14:28:39.589728Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_Msize.json"
2023-01-30T14:28:39.589731Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:39.589817Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_Msize"
2023-01-30T14:28:39.589823Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1541027,
    events_root: None,
}
2023-01-30T14:28:39.589825Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=7): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:39.589834Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:39.589836Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_Msize"::London::0
2023-01-30T14:28:39.589837Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_Msize.json"
2023-01-30T14:28:39.589839Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:39.589926Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_Msize"
2023-01-30T14:28:39.589931Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1541027,
    events_root: None,
}
2023-01-30T14:28:39.589934Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=7): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:39.589942Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:39.589944Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_Msize"::London::0
2023-01-30T14:28:39.589946Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_Msize.json"
2023-01-30T14:28:39.589948Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:39.590034Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_Msize"
2023-01-30T14:28:39.590039Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1541027,
    events_root: None,
}
2023-01-30T14:28:39.590042Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=7): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:39.590051Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:39.590052Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_Msize"::Merge::0
2023-01-30T14:28:39.590054Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_Msize.json"
2023-01-30T14:28:39.590056Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:39.590142Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_Msize"
2023-01-30T14:28:39.590147Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1541027,
    events_root: None,
}
2023-01-30T14:28:39.590150Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=7): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:39.590159Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:39.590161Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_Msize"::Merge::0
2023-01-30T14:28:39.590163Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_Msize.json"
2023-01-30T14:28:39.590165Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:39.590250Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_Msize"
2023-01-30T14:28:39.590255Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1541027,
    events_root: None,
}
2023-01-30T14:28:39.590258Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=7): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:39.591811Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:380.865381ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "mload32bitBound_Msize.json::mload32bitBound_Msize": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:39.853165Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/mload32bitBound_return.json", Total Files :: 1
2023-01-30T14:28:39.883322Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:39.883476Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:39.883480Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:39.883535Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:39.883619Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:39.883622Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return"::Istanbul::0
2023-01-30T14:28:39.883625Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return.json"
2023-01-30T14:28:39.883627Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.247928Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return"
2023-01-30T14:28:40.247951Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1535437,
    events_root: None,
}
2023-01-30T14:28:40.247956Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.247971Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:40.247974Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return"::Istanbul::0
2023-01-30T14:28:40.247976Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return.json"
2023-01-30T14:28:40.247980Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.248091Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return"
2023-01-30T14:28:40.248097Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1535437,
    events_root: None,
}
2023-01-30T14:28:40.248100Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.248110Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:40.248112Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return"::Berlin::0
2023-01-30T14:28:40.248114Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return.json"
2023-01-30T14:28:40.248116Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.248205Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return"
2023-01-30T14:28:40.248211Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1535437,
    events_root: None,
}
2023-01-30T14:28:40.248213Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.248222Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:40.248224Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return"::Berlin::0
2023-01-30T14:28:40.248226Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return.json"
2023-01-30T14:28:40.248228Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.248316Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return"
2023-01-30T14:28:40.248321Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1535437,
    events_root: None,
}
2023-01-30T14:28:40.248324Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.248334Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:40.248336Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return"::London::0
2023-01-30T14:28:40.248337Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return.json"
2023-01-30T14:28:40.248339Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.248426Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return"
2023-01-30T14:28:40.248431Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1535437,
    events_root: None,
}
2023-01-30T14:28:40.248434Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.248443Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:40.248445Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return"::London::0
2023-01-30T14:28:40.248446Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return.json"
2023-01-30T14:28:40.248448Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.248537Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return"
2023-01-30T14:28:40.248543Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1535437,
    events_root: None,
}
2023-01-30T14:28:40.248546Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.248557Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:40.248560Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return"::Merge::0
2023-01-30T14:28:40.248562Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return.json"
2023-01-30T14:28:40.248564Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.248675Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return"
2023-01-30T14:28:40.248682Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1535437,
    events_root: None,
}
2023-01-30T14:28:40.248686Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.248697Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:40.248699Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return"::Merge::0
2023-01-30T14:28:40.248702Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return.json"
2023-01-30T14:28:40.248705Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.248803Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return"
2023-01-30T14:28:40.248809Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1535437,
    events_root: None,
}
2023-01-30T14:28:40.248812Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.250406Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:365.509477ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "mload32bitBound_return.json::mload32bitBound_return": [
        "Istanbul | 0 | ExitCode { value: 24 }",
        "Istanbul | 0 | ExitCode { value: 24 }",
        "Berlin | 0 | ExitCode { value: 24 }",
        "Berlin | 0 | ExitCode { value: 24 }",
        "London | 0 | ExitCode { value: 24 }",
        "London | 0 | ExitCode { value: 24 }",
        "Merge | 0 | ExitCode { value: 24 }",
        "Merge | 0 | ExitCode { value: 24 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:40.526415Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/mload32bitBound_return2.json", Total Files :: 1
2023-01-30T14:28:40.554934Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:40.555068Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:40.555072Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:40.555122Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:40.555190Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:40.555193Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return2"::Istanbul::0
2023-01-30T14:28:40.555196Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return2.json"
2023-01-30T14:28:40.555198Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.895934Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return2"
2023-01-30T14:28:40.895955Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1541626,
    events_root: None,
}
2023-01-30T14:28:40.895961Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.895974Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:40.895977Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return2"::Istanbul::0
2023-01-30T14:28:40.895980Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return2.json"
2023-01-30T14:28:40.895981Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.896103Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return2"
2023-01-30T14:28:40.896109Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1541626,
    events_root: None,
}
2023-01-30T14:28:40.896113Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.896124Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:40.896126Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return2"::Berlin::0
2023-01-30T14:28:40.896128Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return2.json"
2023-01-30T14:28:40.896130Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.896229Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return2"
2023-01-30T14:28:40.896235Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1541626,
    events_root: None,
}
2023-01-30T14:28:40.896238Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.896247Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:40.896249Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return2"::Berlin::0
2023-01-30T14:28:40.896251Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return2.json"
2023-01-30T14:28:40.896253Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.896338Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return2"
2023-01-30T14:28:40.896343Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1541626,
    events_root: None,
}
2023-01-30T14:28:40.896346Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.896356Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:40.896358Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return2"::London::0
2023-01-30T14:28:40.896360Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return2.json"
2023-01-30T14:28:40.896361Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.896445Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return2"
2023-01-30T14:28:40.896451Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1541626,
    events_root: None,
}
2023-01-30T14:28:40.896454Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.896463Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:40.896464Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return2"::London::0
2023-01-30T14:28:40.896466Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return2.json"
2023-01-30T14:28:40.896468Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.896552Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return2"
2023-01-30T14:28:40.896558Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1541626,
    events_root: None,
}
2023-01-30T14:28:40.896560Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.896569Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:40.896571Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return2"::Merge::0
2023-01-30T14:28:40.896573Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return2.json"
2023-01-30T14:28:40.896574Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.896658Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return2"
2023-01-30T14:28:40.896663Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1541626,
    events_root: None,
}
2023-01-30T14:28:40.896666Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.896675Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:40.896677Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "mload32bitBound_return2"::Merge::0
2023-01-30T14:28:40.896678Z  INFO evm_eth_compliance::statetest::executor: Path : "mload32bitBound_return2.json"
2023-01-30T14:28:40.896680Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:40.896772Z  INFO evm_eth_compliance::statetest::executor: UC : "mload32bitBound_return2"
2023-01-30T14:28:40.896778Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1541626,
    events_root: None,
}
2023-01-30T14:28:40.896781Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'attempt to add with overflow', actors/evm/src/interpreter/instructions/memory.rs:29:9",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:40.898524Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:341.863615ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "mload32bitBound_return2.json::mload32bitBound_return2": [
        "Istanbul | 0 | ExitCode { value: 24 }",
        "Istanbul | 0 | ExitCode { value: 24 }",
        "Berlin | 0 | ExitCode { value: 24 }",
        "Berlin | 0 | ExitCode { value: 24 }",
        "London | 0 | ExitCode { value: 24 }",
        "London | 0 | ExitCode { value: 24 }",
        "Merge | 0 | ExitCode { value: 24 }",
        "Merge | 0 | ExitCode { value: 24 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:41.175663Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/static_CALL_Bounds.json", Total Files :: 1
2023-01-30T14:28:41.205883Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:41.206027Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:41.206031Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:41.206084Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:41.206086Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:41.206148Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:41.206224Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:41.206226Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds"::Istanbul::0
2023-01-30T14:28:41.206230Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds.json"
2023-01-30T14:28:41.206232Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:41.605350Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds"
2023-01-30T14:28:41.605374Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 325324444,
    events_root: None,
}
2023-01-30T14:28:41.605380Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:41.605402Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:41.605407Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds"::Istanbul::0
2023-01-30T14:28:41.605409Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds.json"
2023-01-30T14:28:41.605410Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:41.671468Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds"
2023-01-30T14:28:41.671486Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 325324444,
    events_root: None,
}
2023-01-30T14:28:41.671491Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:41.671513Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:41.671517Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds"::Berlin::0
2023-01-30T14:28:41.671519Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds.json"
2023-01-30T14:28:41.671520Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:41.737855Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds"
2023-01-30T14:28:41.737877Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 325324444,
    events_root: None,
}
2023-01-30T14:28:41.737882Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:41.737905Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:41.737909Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds"::Berlin::0
2023-01-30T14:28:41.737911Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds.json"
2023-01-30T14:28:41.737914Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:41.804993Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds"
2023-01-30T14:28:41.805013Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 325324444,
    events_root: None,
}
2023-01-30T14:28:41.805019Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:41.805040Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:41.805044Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds"::London::0
2023-01-30T14:28:41.805046Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds.json"
2023-01-30T14:28:41.805048Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:41.870837Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds"
2023-01-30T14:28:41.870860Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 325324444,
    events_root: None,
}
2023-01-30T14:28:41.870865Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:41.870885Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:41.870889Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds"::London::0
2023-01-30T14:28:41.870891Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds.json"
2023-01-30T14:28:41.870893Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:41.936127Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds"
2023-01-30T14:28:41.936150Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 325324444,
    events_root: None,
}
2023-01-30T14:28:41.936155Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:41.936177Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:41.936181Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds"::Merge::0
2023-01-30T14:28:41.936183Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds.json"
2023-01-30T14:28:41.936185Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:42.003078Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds"
2023-01-30T14:28:42.003102Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 325324444,
    events_root: None,
}
2023-01-30T14:28:42.003107Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:42.003127Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:42.003131Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds"::Merge::0
2023-01-30T14:28:42.003133Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds.json"
2023-01-30T14:28:42.003135Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:42.069861Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds"
2023-01-30T14:28:42.069883Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 325324444,
    events_root: None,
}
2023-01-30T14:28:42.069888Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:42.071549Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:864.037222ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "static_CALL_Bounds.json::static_CALL_Bounds": [
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:42.344179Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/static_CALL_Bounds2.json", Total Files :: 1
2023-01-30T14:28:42.400287Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:42.400429Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:42.400432Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:42.400484Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:42.400486Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:42.400546Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:42.400620Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:42.400623Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2"::Istanbul::0
2023-01-30T14:28:42.400626Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2.json"
2023-01-30T14:28:42.400628Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:42.752388Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2"
2023-01-30T14:28:42.752407Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216280927,
    events_root: None,
}
2023-01-30T14:28:42.752413Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:42.752428Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:42.752432Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2"::Istanbul::0
2023-01-30T14:28:42.752434Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2.json"
2023-01-30T14:28:42.752435Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:42.752561Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2"
2023-01-30T14:28:42.752567Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216280927,
    events_root: None,
}
2023-01-30T14:28:42.752570Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:42.752579Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:42.752581Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2"::Berlin::0
2023-01-30T14:28:42.752583Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2.json"
2023-01-30T14:28:42.752585Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:42.752678Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2"
2023-01-30T14:28:42.752683Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216280927,
    events_root: None,
}
2023-01-30T14:28:42.752686Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:42.752694Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:42.752696Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2"::Berlin::0
2023-01-30T14:28:42.752698Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2.json"
2023-01-30T14:28:42.752699Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:42.752784Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2"
2023-01-30T14:28:42.752790Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216280927,
    events_root: None,
}
2023-01-30T14:28:42.752793Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:42.752802Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:42.752803Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2"::London::0
2023-01-30T14:28:42.752805Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2.json"
2023-01-30T14:28:42.752807Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:42.752893Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2"
2023-01-30T14:28:42.752898Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216280927,
    events_root: None,
}
2023-01-30T14:28:42.752901Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:42.752909Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:42.752912Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2"::London::0
2023-01-30T14:28:42.752913Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2.json"
2023-01-30T14:28:42.752915Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:42.753016Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2"
2023-01-30T14:28:42.753021Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216280927,
    events_root: None,
}
2023-01-30T14:28:42.753024Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:42.753035Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:42.753036Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2"::Merge::0
2023-01-30T14:28:42.753038Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2.json"
2023-01-30T14:28:42.753040Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:42.753136Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2"
2023-01-30T14:28:42.753142Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216280927,
    events_root: None,
}
2023-01-30T14:28:42.753146Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:42.753157Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:42.753160Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2"::Merge::0
2023-01-30T14:28:42.753162Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2.json"
2023-01-30T14:28:42.753164Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:42.753260Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2"
2023-01-30T14:28:42.753265Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 216280927,
    events_root: None,
}
2023-01-30T14:28:42.753268Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:42.754951Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.998943ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "static_CALL_Bounds2.json::static_CALL_Bounds2": [
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:43.025255Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/static_CALL_Bounds2a.json", Total Files :: 1
2023-01-30T14:28:43.065880Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:43.066030Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:43.066034Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:43.066088Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:43.066090Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:43.066153Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:43.066227Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:43.066230Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2a"::Istanbul::0
2023-01-30T14:28:43.066233Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2a.json"
2023-01-30T14:28:43.066236Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:43.448167Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2a"
2023-01-30T14:28:43.448190Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:43.448197Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:43.448212Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:43.448216Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2a"::Istanbul::0
2023-01-30T14:28:43.448219Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2a.json"
2023-01-30T14:28:43.448222Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:43.448348Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2a"
2023-01-30T14:28:43.448355Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:43.448359Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:43.448372Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:43.448375Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2a"::Berlin::0
2023-01-30T14:28:43.448377Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2a.json"
2023-01-30T14:28:43.448380Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:43.448472Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2a"
2023-01-30T14:28:43.448479Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:43.448482Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:43.448494Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:43.448497Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2a"::Berlin::0
2023-01-30T14:28:43.448499Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2a.json"
2023-01-30T14:28:43.448502Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:43.448593Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2a"
2023-01-30T14:28:43.448599Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:43.448602Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:43.448614Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:43.448616Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2a"::London::0
2023-01-30T14:28:43.448619Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2a.json"
2023-01-30T14:28:43.448621Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:43.448712Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2a"
2023-01-30T14:28:43.448718Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:43.448721Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:43.448732Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:43.448735Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2a"::London::0
2023-01-30T14:28:43.448737Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2a.json"
2023-01-30T14:28:43.448740Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:43.448828Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2a"
2023-01-30T14:28:43.448834Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:43.448838Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:43.448849Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:43.448851Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2a"::Merge::0
2023-01-30T14:28:43.448854Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2a.json"
2023-01-30T14:28:43.448856Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:43.448950Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2a"
2023-01-30T14:28:43.448957Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:43.448960Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:43.448971Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:43.448974Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds2a"::Merge::0
2023-01-30T14:28:43.448977Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds2a.json"
2023-01-30T14:28:43.448979Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:43.449079Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds2a"
2023-01-30T14:28:43.449086Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1547289,
    events_root: None,
}
2023-01-30T14:28:43.449089Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=50): new memory size exceeds max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:43.450695Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:383.228616ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "static_CALL_Bounds2a.json::static_CALL_Bounds2a": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
2023-01-30T14:28:43.719652Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemoryStressTest/static_CALL_Bounds3.json", Total Files :: 1
2023-01-30T14:28:43.749628Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-01-30T14:28:43.749771Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:43.749775Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-01-30T14:28:43.749827Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:43.749829Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-01-30T14:28:43.749891Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-01-30T14:28:43.749965Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:43.749968Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds3"::Istanbul::0
2023-01-30T14:28:43.749971Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds3.json"
2023-01-30T14:28:43.749972Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:44.106204Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds3"
2023-01-30T14:28:44.106225Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1565759,
    events_root: None,
}
2023-01-30T14:28:44.106230Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:44.106242Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-01-30T14:28:44.106246Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds3"::Istanbul::0
2023-01-30T14:28:44.106248Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds3.json"
2023-01-30T14:28:44.106250Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:44.106370Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds3"
2023-01-30T14:28:44.106376Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1565759,
    events_root: None,
}
2023-01-30T14:28:44.106379Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:44.106388Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:44.106392Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds3"::Berlin::0
2023-01-30T14:28:44.106393Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds3.json"
2023-01-30T14:28:44.106395Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:44.106481Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds3"
2023-01-30T14:28:44.106486Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1565759,
    events_root: None,
}
2023-01-30T14:28:44.106489Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:44.106497Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-01-30T14:28:44.106499Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds3"::Berlin::0
2023-01-30T14:28:44.106501Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds3.json"
2023-01-30T14:28:44.106502Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:44.106589Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds3"
2023-01-30T14:28:44.106594Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1565759,
    events_root: None,
}
2023-01-30T14:28:44.106596Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:44.106604Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:44.106606Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds3"::London::0
2023-01-30T14:28:44.106608Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds3.json"
2023-01-30T14:28:44.106610Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:44.106694Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds3"
2023-01-30T14:28:44.106700Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1565759,
    events_root: None,
}
2023-01-30T14:28:44.106703Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:44.106712Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-01-30T14:28:44.106714Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds3"::London::0
2023-01-30T14:28:44.106715Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds3.json"
2023-01-30T14:28:44.106717Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:44.106800Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds3"
2023-01-30T14:28:44.106805Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1565759,
    events_root: None,
}
2023-01-30T14:28:44.106808Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:44.106818Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:44.106820Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds3"::Merge::0
2023-01-30T14:28:44.106822Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds3.json"
2023-01-30T14:28:44.106823Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:44.106908Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds3"
2023-01-30T14:28:44.106913Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1565759,
    events_root: None,
}
2023-01-30T14:28:44.106916Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:44.106924Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-01-30T14:28:44.106926Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "static_CALL_Bounds3"::Merge::0
2023-01-30T14:28:44.106927Z  INFO evm_eth_compliance::statetest::executor: Path : "static_CALL_Bounds3.json"
2023-01-30T14:28:44.106929Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-01-30T14:28:44.107014Z  INFO evm_eth_compliance::statetest::executor: UC : "static_CALL_Bounds3"
2023-01-30T14:28:44.107019Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1565759,
    events_root: None,
}
2023-01-30T14:28:44.107022Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=52): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-30T14:28:44.108605Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.410868ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "static_CALL_Bounds3.json::static_CALL_Bounds3": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
```

