> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stExtCodeHash

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stExtCodeHash \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-case are skipped due to `transaction.tx` empty. Have to re-check on revm

| Test ID | Use-Case |
| --- | --- |
| TID-23-23 | extCodeHashInInitCode |

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-23-01 | callToNonExistent |
| TID-23-02 | callToSuicideThenExtcodehash |
| TID-23-03 | codeCopyZero |
| TID-23-05 | dynamicAccountOverwriteEmpty |
| TID-23-09 | extCodeHashCALLCODE |
| TID-23-31 | extCodeHashSubcallOOG |

- Hit with error `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS` (ExitCode::38)

| Test ID | Use-Case |
| --- | --- |
| TID-23-07 | extCodeHashAccountWithoutCode |
| TID-23-08 | extCodeHashCALL |
| TID-23-15 | extCodeHashDELEGATECALL |
| TID-23-16 | extCodeHashDeletedAccount |
| TID-23-24 | extCodeHashMaxCodeSize |
| TID-23-26 | extCodeHashNonExistingAccount |
| TID-23-30 | extCodeHashSTATICCALL |

> Execution Trace

```
2023-01-26T10:21:11.109132Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json", Total Files :: 1
2023-01-26T10:21:11.137978Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:11.138164Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.138168Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:11.138220Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.138222Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:11.138282Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.138284Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:11.138335Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.138338Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:11.138389Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.138391Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-26T10:21:11.138460Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.138530Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:11.138533Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Istanbul::0
2023-01-26T10:21:11.138535Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.138538Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.138540Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.500245Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.500262Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.500270Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.500285Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T10:21:11.500293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Istanbul::1
2023-01-26T10:21:11.500296Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.500300Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.500301Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.500422Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.500426Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.500430Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.500442Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-26T10:21:11.500446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Istanbul::2
2023-01-26T10:21:11.500448Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.500452Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.500454Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.500546Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.500551Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.500554Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.500566Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-26T10:21:11.500569Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Istanbul::3
2023-01-26T10:21:11.500572Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.500575Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.500577Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.500671Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.500675Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.500679Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.500691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:11.500694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Berlin::0
2023-01-26T10:21:11.500696Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.500699Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.500701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.500796Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.500801Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.500804Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.500816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T10:21:11.500819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Berlin::1
2023-01-26T10:21:11.500821Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.500825Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.500827Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.500919Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.500924Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.500927Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.500939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T10:21:11.500942Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Berlin::2
2023-01-26T10:21:11.500944Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.500948Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.500950Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.501042Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.501046Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.501050Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.501061Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T10:21:11.501064Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Berlin::3
2023-01-26T10:21:11.501066Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.501070Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.501072Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.501168Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.501173Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.501177Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.501187Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:11.501189Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::London::0
2023-01-26T10:21:11.501192Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.501195Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.501197Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.501303Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.501308Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.501311Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.501319Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T10:21:11.501321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::London::1
2023-01-26T10:21:11.501323Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.501325Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.501326Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.501443Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.501449Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.501453Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.501465Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T10:21:11.501468Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::London::2
2023-01-26T10:21:11.501470Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.501473Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.501475Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.501585Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.501589Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.501592Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.501600Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T10:21:11.501602Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::London::3
2023-01-26T10:21:11.501604Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.501607Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.501608Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.501698Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.501702Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.501705Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.501713Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:11.501715Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Merge::0
2023-01-26T10:21:11.501717Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.501719Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.501720Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.501806Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.501809Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.501812Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.501820Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T10:21:11.501822Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Merge::1
2023-01-26T10:21:11.501824Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.501826Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.501827Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.501912Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.501916Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.501919Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.501927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T10:21:11.501929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Merge::2
2023-01-26T10:21:11.501930Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.501933Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.501934Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.502018Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.502021Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.502024Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.502032Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T10:21:11.502034Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToNonExistent"::Merge::3
2023-01-26T10:21:11.502036Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToNonExistent.json"
2023-01-26T10:21:11.502039Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.502040Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:11.502124Z  INFO evm_eth_compliance::statetest::runner: UC : "callToNonExistent"
2023-01-26T10:21:11.502128Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:11.502131Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:11.503812Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.166063ms
2023-01-26T10:21:11.781777Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json", Total Files :: 1
2023-01-26T10:21:11.809849Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:11.810034Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.810038Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:11.810090Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.810092Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:11.810149Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.810151Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:11.810202Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.810204Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:11.810255Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.810256Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-26T10:21:11.810321Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.810323Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-26T10:21:11.810373Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:11.810443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:11.810446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Istanbul::0
2023-01-26T10:21:11.810448Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:11.810451Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:11.810453Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.156387Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.156404Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.156412Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.156427Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T10:21:12.156434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Istanbul::1
2023-01-26T10:21:12.156436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.156441Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.156443Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.156572Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.156577Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.156581Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.156591Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-26T10:21:12.156593Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Istanbul::2
2023-01-26T10:21:12.156595Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.156598Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.156599Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.156690Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.156694Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.156697Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.156707Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-26T10:21:12.156710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Istanbul::3
2023-01-26T10:21:12.156711Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.156714Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.156716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.156802Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.156806Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.156810Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.156820Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:12.156822Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Berlin::0
2023-01-26T10:21:12.156824Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.156827Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.156828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.156915Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.156919Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.156922Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.156932Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T10:21:12.156935Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Berlin::1
2023-01-26T10:21:12.156937Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.156939Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.156941Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.157028Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.157033Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.157036Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.157045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T10:21:12.157047Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Berlin::2
2023-01-26T10:21:12.157049Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.157052Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.157053Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.157141Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.157144Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.157147Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.157156Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T10:21:12.157158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Berlin::3
2023-01-26T10:21:12.157160Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.157163Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.157164Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.157250Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.157254Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.157257Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.157266Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:12.157268Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::London::0
2023-01-26T10:21:12.157270Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.157273Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.157274Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.157368Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.157373Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.157375Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.157384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T10:21:12.157387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::London::1
2023-01-26T10:21:12.157389Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.157391Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.157393Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.157485Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.157489Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.157492Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.157501Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T10:21:12.157503Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::London::2
2023-01-26T10:21:12.157505Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.157508Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.157509Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.157594Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.157598Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.157602Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.157612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T10:21:12.157614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::London::3
2023-01-26T10:21:12.157616Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.157618Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.157620Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.157705Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.157710Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.157713Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.157722Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:12.157725Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Merge::0
2023-01-26T10:21:12.157728Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.157731Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.157733Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.157831Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.157836Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.157840Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.157853Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T10:21:12.157856Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Merge::1
2023-01-26T10:21:12.157859Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.157862Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.157864Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.157968Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.157974Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.157977Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.157986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T10:21:12.157988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Merge::2
2023-01-26T10:21:12.157990Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.157992Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.157995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.158112Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.158117Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.158120Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.158129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T10:21:12.158132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callToSuicideThenExtcodehash"::Merge::3
2023-01-26T10:21:12.158134Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/callToSuicideThenExtcodehash.json"
2023-01-26T10:21:12.158138Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:12.158140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.158261Z  INFO evm_eth_compliance::statetest::runner: UC : "callToSuicideThenExtcodehash"
2023-01-26T10:21:12.158267Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1563885,
    events_root: None,
}
2023-01-26T10:21:12.158270Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=14): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:12.160401Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:348.43941ms
2023-01-26T10:21:12.436636Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/codeCopyZero.json", Total Files :: 1
2023-01-26T10:21:12.465912Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:12.466102Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:12.466105Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:12.466160Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:12.466162Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:12.466223Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:12.466225Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:12.466281Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:12.466283Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:12.466337Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:12.466409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:12.466412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codeCopyZero"::Istanbul::0
2023-01-26T10:21:12.466416Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/codeCopyZero.json"
2023-01-26T10:21:12.466419Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:12.466420Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.807330Z  INFO evm_eth_compliance::statetest::runner: UC : "codeCopyZero"
2023-01-26T10:21:12.807347Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1661205,
    events_root: None,
}
2023-01-26T10:21:12.807353Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=118): undefined instruction",
                },
            ],
            cause: Some(
                Syscall {
                    module: "actor",
                    function: "resolve_address",
                    error: NotFound,
                    message: "actor not found",
                },
            ),
        },
    ),
)
2023-01-26T10:21:12.807370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:12.807375Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codeCopyZero"::Berlin::0
2023-01-26T10:21:12.807377Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/codeCopyZero.json"
2023-01-26T10:21:12.807380Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:12.807382Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.807543Z  INFO evm_eth_compliance::statetest::runner: UC : "codeCopyZero"
2023-01-26T10:21:12.807547Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1661205,
    events_root: None,
}
2023-01-26T10:21:12.807550Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=118): undefined instruction",
                },
            ],
            cause: Some(
                Syscall {
                    module: "actor",
                    function: "resolve_address",
                    error: NotFound,
                    message: "actor not found",
                },
            ),
        },
    ),
)
2023-01-26T10:21:12.807562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:12.807565Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codeCopyZero"::London::0
2023-01-26T10:21:12.807567Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/codeCopyZero.json"
2023-01-26T10:21:12.807570Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:12.807572Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.807702Z  INFO evm_eth_compliance::statetest::runner: UC : "codeCopyZero"
2023-01-26T10:21:12.807706Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1661205,
    events_root: None,
}
2023-01-26T10:21:12.807709Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=118): undefined instruction",
                },
            ],
            cause: Some(
                Syscall {
                    module: "actor",
                    function: "resolve_address",
                    error: NotFound,
                    message: "actor not found",
                },
            ),
        },
    ),
)
2023-01-26T10:21:12.807721Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:12.807724Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codeCopyZero"::Merge::0
2023-01-26T10:21:12.807726Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/codeCopyZero.json"
2023-01-26T10:21:12.807728Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:12.807729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:12.807855Z  INFO evm_eth_compliance::statetest::runner: UC : "codeCopyZero"
2023-01-26T10:21:12.807859Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1661205,
    events_root: None,
}
2023-01-26T10:21:12.807862Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=118): undefined instruction",
                },
            ],
            cause: Some(
                Syscall {
                    module: "actor",
                    function: "resolve_address",
                    error: NotFound,
                    message: "actor not found",
                },
            ),
        },
    ),
)
2023-01-26T10:21:12.809634Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:341.965439ms
2023-01-26T10:21:13.090216Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/createEmptyThenExtcodehash.json", Total Files :: 1
2023-01-26T10:21:13.119201Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:13.119385Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:13.119388Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:13.119442Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:13.119513Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:13.119516Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createEmptyThenExtcodehash"::Istanbul::0
2023-01-26T10:21:13.119519Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/createEmptyThenExtcodehash.json"
2023-01-26T10:21:13.119522Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:13.119524Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [8, 38, 86, 42, 201, 55, 56, 24, 247, 160, 85, 22, 111, 123, 12, 200, 116, 133, 240, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [124, 90, 44, 145, 178, 45, 122, 146, 38, 82, 61, 75, 167, 23, 219, 106, 251, 116, 30, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 136, 95, 13, 181, 217, 120, 204, 197, 243, 155, 145, 50, 151, 43, 92, 167, 175, 132, 25]) }
2023-01-26T10:21:13.737306Z  INFO evm_eth_compliance::statetest::runner: UC : "createEmptyThenExtcodehash"
2023-01-26T10:21:13.737317Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 33603974,
    events_root: None,
}
2023-01-26T10:21:13.737369Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:13.737376Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createEmptyThenExtcodehash"::Berlin::0
2023-01-26T10:21:13.737378Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/createEmptyThenExtcodehash.json"
2023-01-26T10:21:13.737382Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:13.737383Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 32, 219, 74, 113, 179, 136, 255, 7, 69, 60, 90, 226, 153, 143, 86, 21, 251, 52, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-26T10:21:13.738408Z  INFO evm_eth_compliance::statetest::runner: UC : "createEmptyThenExtcodehash"
2023-01-26T10:21:13.738413Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 22866238,
    events_root: None,
}
2023-01-26T10:21:13.738438Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:13.738440Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createEmptyThenExtcodehash"::London::0
2023-01-26T10:21:13.738443Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/createEmptyThenExtcodehash.json"
2023-01-26T10:21:13.738445Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:13.738447Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [66, 193, 50, 209, 221, 130, 255, 103, 163, 250, 83, 102, 107, 193, 147, 247, 124, 68, 94, 204, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-26T10:21:13.739365Z  INFO evm_eth_compliance::statetest::runner: UC : "createEmptyThenExtcodehash"
2023-01-26T10:21:13.739370Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20630722,
    events_root: None,
}
2023-01-26T10:21:13.739393Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:13.739396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createEmptyThenExtcodehash"::Merge::0
2023-01-26T10:21:13.739398Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/createEmptyThenExtcodehash.json"
2023-01-26T10:21:13.739401Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:13.739402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [244, 43, 160, 239, 169, 125, 72, 146, 124, 135, 106, 148, 6, 74, 106, 180, 201, 58, 153, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-26T10:21:13.740358Z  INFO evm_eth_compliance::statetest::runner: UC : "createEmptyThenExtcodehash"
2023-01-26T10:21:13.740363Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20605398,
    events_root: None,
}
2023-01-26T10:21:13.742194Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:621.190815ms
2023-01-26T10:21:14.024420Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/dynamicAccountOverwriteEmpty.json", Total Files :: 1
2023-01-26T10:21:14.053146Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:14.053339Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:14.053349Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:14.053409Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:14.053411Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:14.053468Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:14.053470Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:14.053530Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:14.053605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:14.053608Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dynamicAccountOverwriteEmpty"::Istanbul::0
2023-01-26T10:21:14.053611Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/dynamicAccountOverwriteEmpty.json"
2023-01-26T10:21:14.053615Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:14.053617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:14.398280Z  INFO evm_eth_compliance::statetest::runner: UC : "dynamicAccountOverwriteEmpty"
2023-01-26T10:21:14.398296Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 5842248,
    events_root: None,
}
2023-01-26T10:21:14.398302Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=118): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:14.398320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:14.398325Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dynamicAccountOverwriteEmpty"::Berlin::0
2023-01-26T10:21:14.398328Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/dynamicAccountOverwriteEmpty.json"
2023-01-26T10:21:14.398330Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:14.398333Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:14.398666Z  INFO evm_eth_compliance::statetest::runner: UC : "dynamicAccountOverwriteEmpty"
2023-01-26T10:21:14.398671Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 5842248,
    events_root: None,
}
2023-01-26T10:21:14.398674Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=118): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:14.398688Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:14.398691Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dynamicAccountOverwriteEmpty"::London::0
2023-01-26T10:21:14.398693Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/dynamicAccountOverwriteEmpty.json"
2023-01-26T10:21:14.398696Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:14.398697Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:14.399024Z  INFO evm_eth_compliance::statetest::runner: UC : "dynamicAccountOverwriteEmpty"
2023-01-26T10:21:14.399029Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 5842248,
    events_root: None,
}
2023-01-26T10:21:14.399032Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=118): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:14.399045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:14.399047Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dynamicAccountOverwriteEmpty"::Merge::0
2023-01-26T10:21:14.399050Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/dynamicAccountOverwriteEmpty.json"
2023-01-26T10:21:14.399053Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:14.399054Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:14.399387Z  INFO evm_eth_compliance::statetest::runner: UC : "dynamicAccountOverwriteEmpty"
2023-01-26T10:21:14.399392Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 5842248,
    events_root: None,
}
2023-01-26T10:21:14.399395Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=118): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:14.401033Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.266862ms
2023-01-26T10:21:14.676596Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeCopyBounds.json", Total Files :: 1
2023-01-26T10:21:14.704933Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:14.705119Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:14.705123Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:14.705179Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:14.705181Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:14.705242Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:14.705314Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:14.705317Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeCopyBounds"::Istanbul::0
2023-01-26T10:21:14.705320Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeCopyBounds.json"
2023-01-26T10:21:14.705323Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:14.705325Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:15.073496Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeCopyBounds"
2023-01-26T10:21:15.073509Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6165211,
    events_root: None,
}
2023-01-26T10:21:15.073527Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:15.073532Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeCopyBounds"::Berlin::0
2023-01-26T10:21:15.073534Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeCopyBounds.json"
2023-01-26T10:21:15.073538Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:15.073539Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:15.073856Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeCopyBounds"
2023-01-26T10:21:15.073861Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5156293,
    events_root: None,
}
2023-01-26T10:21:15.073873Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:15.073876Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeCopyBounds"::London::0
2023-01-26T10:21:15.073877Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeCopyBounds.json"
2023-01-26T10:21:15.073880Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:15.073881Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:15.074180Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeCopyBounds"
2023-01-26T10:21:15.074184Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5156293,
    events_root: None,
}
2023-01-26T10:21:15.074196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:15.074199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeCopyBounds"::Merge::0
2023-01-26T10:21:15.074201Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeCopyBounds.json"
2023-01-26T10:21:15.074203Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:15.074205Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:15.074502Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeCopyBounds"
2023-01-26T10:21:15.074506Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5156293,
    events_root: None,
}
2023-01-26T10:21:15.076031Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:369.589847ms
2023-01-26T10:21:15.347590Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashAccountWithoutCode.json", Total Files :: 1
2023-01-26T10:21:15.375651Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:15.375841Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:15.375846Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:15.375903Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:15.375906Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:15.375964Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:15.375967Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:15.376017Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:15.376020Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:15.376066Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:15.376139Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:15.376144Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashAccountWithoutCode"::Istanbul::0
2023-01-26T10:21:15.376147Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashAccountWithoutCode.json"
2023-01-26T10:21:15.376152Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:15.376154Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:15.725673Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashAccountWithoutCode"
2023-01-26T10:21:15.725688Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:15.725694Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:15.725711Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:15.725717Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashAccountWithoutCode"::Berlin::0
2023-01-26T10:21:15.725718Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashAccountWithoutCode.json"
2023-01-26T10:21:15.725721Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:15.725723Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:15.725839Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashAccountWithoutCode"
2023-01-26T10:21:15.725843Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:15.725846Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:15.725858Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:15.725861Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashAccountWithoutCode"::London::0
2023-01-26T10:21:15.725862Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashAccountWithoutCode.json"
2023-01-26T10:21:15.725865Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:15.725866Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:15.725970Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashAccountWithoutCode"
2023-01-26T10:21:15.725974Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:15.725976Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:15.725988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:15.725991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashAccountWithoutCode"::Merge::0
2023-01-26T10:21:15.725992Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashAccountWithoutCode.json"
2023-01-26T10:21:15.725995Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:15.725997Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:15.726114Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashAccountWithoutCode"
2023-01-26T10:21:15.726118Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:15.726121Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:15.727469Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:350.485922ms
2023-01-26T10:21:15.983672Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCALL.json", Total Files :: 1
2023-01-26T10:21:16.013699Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:16.013890Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:16.013895Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:16.013951Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:16.013953Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:16.014012Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:16.014014Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:16.014067Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:16.014069Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:16.014113Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:16.014188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:16.014192Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCALL"::Istanbul::0
2023-01-26T10:21:16.014194Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCALL.json"
2023-01-26T10:21:16.014198Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:16.014199Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:16.360658Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCALL"
2023-01-26T10:21:16.360673Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:16.360680Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:16.360698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:16.360704Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCALL"::Berlin::0
2023-01-26T10:21:16.360707Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCALL.json"
2023-01-26T10:21:16.360709Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:16.360711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:16.360831Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCALL"
2023-01-26T10:21:16.360836Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:16.360839Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:16.360851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:16.360854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCALL"::London::0
2023-01-26T10:21:16.360855Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCALL.json"
2023-01-26T10:21:16.360858Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:16.360859Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:16.360971Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCALL"
2023-01-26T10:21:16.360975Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:16.360979Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:16.360991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:16.360994Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCALL"::Merge::0
2023-01-26T10:21:16.360995Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCALL.json"
2023-01-26T10:21:16.360998Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:16.360999Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:16.361130Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCALL"
2023-01-26T10:21:16.361134Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:16.361137Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:16.362764Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:347.455346ms
2023-01-26T10:21:16.626462Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCALLCODE.json", Total Files :: 1
2023-01-26T10:21:16.654620Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:16.654803Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:16.654807Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:16.654859Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:16.654861Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:16.654916Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:16.654918Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:16.654968Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:16.654970Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:16.655011Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:16.655082Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:16.655085Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCALLCODE"::Istanbul::0
2023-01-26T10:21:16.655088Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCALLCODE.json"
2023-01-26T10:21:16.655091Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:16.655093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:17.003720Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCALLCODE"
2023-01-26T10:21:17.003735Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1547982,
    events_root: None,
}
2023-01-26T10:21:17.003743Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:17.003756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:17.003762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCALLCODE"::Berlin::0
2023-01-26T10:21:17.003765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCALLCODE.json"
2023-01-26T10:21:17.003769Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:17.003770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:17.003892Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCALLCODE"
2023-01-26T10:21:17.003896Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1547982,
    events_root: None,
}
2023-01-26T10:21:17.003899Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:17.003908Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:17.003910Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCALLCODE"::London::0
2023-01-26T10:21:17.003912Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCALLCODE.json"
2023-01-26T10:21:17.003914Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:17.003915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:17.004000Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCALLCODE"
2023-01-26T10:21:17.004004Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1547982,
    events_root: None,
}
2023-01-26T10:21:17.004006Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:17.004015Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:17.004017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCALLCODE"::Merge::0
2023-01-26T10:21:17.004019Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCALLCODE.json"
2023-01-26T10:21:17.004021Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:17.004023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:17.004132Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCALLCODE"
2023-01-26T10:21:17.004137Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1547982,
    events_root: None,
}
2023-01-26T10:21:17.004141Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:17.005930Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:349.536678ms
2023-01-26T10:21:17.271690Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashChangedAccount.json", Total Files :: 1
2023-01-26T10:21:17.301126Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:17.301314Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:17.301319Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:17.301379Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:17.301382Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:17.301434Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:17.301437Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:17.301492Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:17.301566Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:17.301570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashChangedAccount"::Istanbul::0
2023-01-26T10:21:17.301573Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashChangedAccount.json"
2023-01-26T10:21:17.301576Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:17.301577Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:17.680996Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashChangedAccount"
2023-01-26T10:21:17.681013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12351707,
    events_root: None,
}
2023-01-26T10:21:17.681034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:17.681039Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashChangedAccount"::Berlin::0
2023-01-26T10:21:17.681041Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashChangedAccount.json"
2023-01-26T10:21:17.681045Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:17.681046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:17.681498Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashChangedAccount"
2023-01-26T10:21:17.681503Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7167057,
    events_root: None,
}
2023-01-26T10:21:17.681517Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:17.681520Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashChangedAccount"::London::0
2023-01-26T10:21:17.681522Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashChangedAccount.json"
2023-01-26T10:21:17.681525Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:17.681526Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:17.681956Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashChangedAccount"
2023-01-26T10:21:17.681961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7167057,
    events_root: None,
}
2023-01-26T10:21:17.681976Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:17.681979Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashChangedAccount"::Merge::0
2023-01-26T10:21:17.681981Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashChangedAccount.json"
2023-01-26T10:21:17.681984Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:17.681985Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:17.682413Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashChangedAccount"
2023-01-26T10:21:17.682418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7167057,
    events_root: None,
}
2023-01-26T10:21:17.683911Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:381.310803ms
2023-01-26T10:21:17.948933Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccount.json", Total Files :: 1
2023-01-26T10:21:17.979240Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:17.979450Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:17.979455Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:17.979509Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:17.979586Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:17.979589Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccount"::Istanbul::0
2023-01-26T10:21:17.979592Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccount.json"
2023-01-26T10:21:17.979596Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:17.979598Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [18, 63, 76, 65, 81, 113, 56, 61, 207, 111, 58, 198, 195, 183, 15, 227, 33, 225, 27, 94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T10:21:18.633504Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccount"
2023-01-26T10:21:18.633514Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24280616,
    events_root: None,
}
2023-01-26T10:21:18.633549Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:18.633554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccount"::Berlin::0
2023-01-26T10:21:18.633557Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccount.json"
2023-01-26T10:21:18.633560Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:18.633561Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:18.634008Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccount"
2023-01-26T10:21:18.634013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6035627,
    events_root: None,
}
2023-01-26T10:21:18.634026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:18.634029Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccount"::London::0
2023-01-26T10:21:18.634032Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccount.json"
2023-01-26T10:21:18.634035Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:18.634037Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:18.634351Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccount"
2023-01-26T10:21:18.634356Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4036109,
    events_root: None,
}
2023-01-26T10:21:18.634368Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:18.634371Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccount"::Merge::0
2023-01-26T10:21:18.634373Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccount.json"
2023-01-26T10:21:18.634375Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:18.634377Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:18.634690Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccount"
2023-01-26T10:21:18.634695Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4036109,
    events_root: None,
}
2023-01-26T10:21:18.636359Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:655.471966ms
2023-01-26T10:21:18.907145Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountCall.json", Total Files :: 1
2023-01-26T10:21:18.936475Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:18.936664Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:18.936667Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:18.936719Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:18.936791Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:18.936794Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountCall"::Istanbul::0
2023-01-26T10:21:18.936798Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountCall.json"
2023-01-26T10:21:18.936802Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:18.936803Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [18, 63, 76, 65, 81, 113, 56, 61, 207, 111, 58, 198, 195, 183, 15, 227, 33, 225, 27, 94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T10:21:19.551601Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountCall"
2023-01-26T10:21:19.551612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24280616,
    events_root: None,
}
2023-01-26T10:21:19.551645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:19.551651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountCall"::Berlin::0
2023-01-26T10:21:19.551653Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountCall.json"
2023-01-26T10:21:19.551656Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:19.551658Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:19.552102Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountCall"
2023-01-26T10:21:19.552108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6035627,
    events_root: None,
}
2023-01-26T10:21:19.552120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:19.552123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountCall"::London::0
2023-01-26T10:21:19.552125Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountCall.json"
2023-01-26T10:21:19.552128Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:19.552129Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:19.552441Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountCall"
2023-01-26T10:21:19.552445Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4036109,
    events_root: None,
}
2023-01-26T10:21:19.552457Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:19.552460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountCall"::Merge::0
2023-01-26T10:21:19.552462Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountCall.json"
2023-01-26T10:21:19.552465Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:19.552466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:19.552772Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountCall"
2023-01-26T10:21:19.552777Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4036109,
    events_root: None,
}
2023-01-26T10:21:19.554536Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:616.316803ms
2023-01-26T10:21:19.832051Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountRecheckInOuterCall.json", Total Files :: 1
2023-01-26T10:21:19.861980Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:19.862173Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:19.862177Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:19.862230Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:19.862232Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:19.862284Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:19.862358Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:19.862362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountRecheckInOuterCall"::Istanbul::0
2023-01-26T10:21:19.862367Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountRecheckInOuterCall.json"
2023-01-26T10:21:19.862372Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:19.862374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:20.228330Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountRecheckInOuterCall"
2023-01-26T10:21:20.228352Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1896835,
    events_root: None,
}
2023-01-26T10:21:20.228366Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:20.228373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountRecheckInOuterCall"::Berlin::0
2023-01-26T10:21:20.228376Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountRecheckInOuterCall.json"
2023-01-26T10:21:20.228380Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:20.228381Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:20.228551Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountRecheckInOuterCall"
2023-01-26T10:21:20.228557Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1896835,
    events_root: None,
}
2023-01-26T10:21:20.228566Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:20.228569Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountRecheckInOuterCall"::London::0
2023-01-26T10:21:20.228572Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountRecheckInOuterCall.json"
2023-01-26T10:21:20.228576Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:20.228577Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:20.228775Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountRecheckInOuterCall"
2023-01-26T10:21:20.228781Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1896835,
    events_root: None,
}
2023-01-26T10:21:20.228787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:20.228789Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountRecheckInOuterCall"::Merge::0
2023-01-26T10:21:20.228791Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountRecheckInOuterCall.json"
2023-01-26T10:21:20.228794Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:20.228795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:20.228938Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountRecheckInOuterCall"
2023-01-26T10:21:20.228943Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1896835,
    events_root: None,
}
2023-01-26T10:21:20.230510Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.97442ms
2023-01-26T10:21:20.503932Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountStaticCall.json", Total Files :: 1
2023-01-26T10:21:20.533172Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:20.533369Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:20.533373Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:20.533423Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:20.533496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:20.533499Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountStaticCall"::Istanbul::0
2023-01-26T10:21:20.533502Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountStaticCall.json"
2023-01-26T10:21:20.533506Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:20.533507Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [18, 63, 76, 65, 81, 113, 56, 61, 207, 111, 58, 198, 195, 183, 15, 227, 33, 225, 27, 94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T10:21:21.156297Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountStaticCall"
2023-01-26T10:21:21.156308Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24279859,
    events_root: None,
}
2023-01-26T10:21:21.156348Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:21.156354Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountStaticCall"::Berlin::0
2023-01-26T10:21:21.156356Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountStaticCall.json"
2023-01-26T10:21:21.156360Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:21.156361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:21.156791Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountStaticCall"
2023-01-26T10:21:21.156796Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6034870,
    events_root: None,
}
2023-01-26T10:21:21.156808Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:21.156811Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountStaticCall"::London::0
2023-01-26T10:21:21.156813Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountStaticCall.json"
2023-01-26T10:21:21.156815Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:21.156817Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:21.157111Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountStaticCall"
2023-01-26T10:21:21.157116Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4035352,
    events_root: None,
}
2023-01-26T10:21:21.157126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:21.157129Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashCreatedAndDeletedAccountStaticCall"::Merge::0
2023-01-26T10:21:21.157131Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashCreatedAndDeletedAccountStaticCall.json"
2023-01-26T10:21:21.157134Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:21.157135Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:21.157441Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashCreatedAndDeletedAccountStaticCall"
2023-01-26T10:21:21.157446Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4035352,
    events_root: None,
}
2023-01-26T10:21:21.159597Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:624.288015ms
2023-01-26T10:21:21.429888Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDELEGATECALL.json", Total Files :: 1
2023-01-26T10:21:21.462999Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:21.463233Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:21.463238Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:21.463315Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:21.463318Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:21.463397Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:21.463404Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:21.463476Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:21.463481Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:21.463542Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:21.463648Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:21.463653Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDELEGATECALL"::Istanbul::0
2023-01-26T10:21:21.463656Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDELEGATECALL.json"
2023-01-26T10:21:21.463660Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:21.463662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:21.840839Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDELEGATECALL"
2023-01-26T10:21:21.840855Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2766026,
    events_root: None,
}
2023-01-26T10:21:21.840861Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 6,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=41): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:21.840879Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:21.840885Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDELEGATECALL"::Berlin::0
2023-01-26T10:21:21.840887Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDELEGATECALL.json"
2023-01-26T10:21:21.840890Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:21.840892Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:21.841079Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDELEGATECALL"
2023-01-26T10:21:21.841084Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2766026,
    events_root: None,
}
2023-01-26T10:21:21.841087Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 6,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=41): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:21.841100Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:21.841103Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDELEGATECALL"::London::0
2023-01-26T10:21:21.841105Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDELEGATECALL.json"
2023-01-26T10:21:21.841108Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:21.841109Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:21.841284Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDELEGATECALL"
2023-01-26T10:21:21.841288Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2766026,
    events_root: None,
}
2023-01-26T10:21:21.841291Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 6,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=41): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:21.841304Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:21.841308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDELEGATECALL"::Merge::0
2023-01-26T10:21:21.841310Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDELEGATECALL.json"
2023-01-26T10:21:21.841313Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:21.841314Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:21.841497Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDELEGATECALL"
2023-01-26T10:21:21.841501Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2766026,
    events_root: None,
}
2023-01-26T10:21:21.841504Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 6,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=41): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:21.843215Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:378.524517ms
2023-01-26T10:21:22.112029Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount.json", Total Files :: 1
2023-01-26T10:21:22.140212Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:22.140395Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:22.140399Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:22.140452Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:22.140454Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:22.140511Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:22.140513Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:22.140563Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:22.140565Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:22.140606Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:22.140609Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-26T10:21:22.140671Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:22.140741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:22.140744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount"::Istanbul::0
2023-01-26T10:21:22.140747Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount.json"
2023-01-26T10:21:22.140750Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:22.140751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:22.483374Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount"
2023-01-26T10:21:22.483389Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1897033,
    events_root: None,
}
2023-01-26T10:21:22.483395Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:22.483413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:22.483419Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount"::Berlin::0
2023-01-26T10:21:22.483421Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount.json"
2023-01-26T10:21:22.483424Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:22.483425Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:22.483549Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount"
2023-01-26T10:21:22.483554Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1897033,
    events_root: None,
}
2023-01-26T10:21:22.483556Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:22.483569Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:22.483571Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount"::London::0
2023-01-26T10:21:22.483573Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount.json"
2023-01-26T10:21:22.483575Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:22.483577Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:22.483698Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount"
2023-01-26T10:21:22.483703Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1897033,
    events_root: None,
}
2023-01-26T10:21:22.483705Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:22.483718Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:22.483720Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount"::Merge::0
2023-01-26T10:21:22.483722Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount.json"
2023-01-26T10:21:22.483724Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:22.483726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:22.483859Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount"
2023-01-26T10:21:22.483864Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1897033,
    events_root: None,
}
2023-01-26T10:21:22.483867Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:22.485638Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:343.674531ms
2023-01-26T10:21:22.767169Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount1.json", Total Files :: 1
2023-01-26T10:21:22.797632Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:22.797826Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:22.797830Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:22.797887Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:22.797889Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:22.797948Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:22.797950Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:22.798009Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:22.798083Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:22.798086Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount1"::Istanbul::0
2023-01-26T10:21:22.798089Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount1.json"
2023-01-26T10:21:22.798093Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:22.798094Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:23.140049Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount1"
2023-01-26T10:21:23.140066Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1961805,
    events_root: None,
}
2023-01-26T10:21:23.140077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:23.140083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount1"::Berlin::0
2023-01-26T10:21:23.140085Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount1.json"
2023-01-26T10:21:23.140088Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:23.140090Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:23.140210Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount1"
2023-01-26T10:21:23.140215Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1961805,
    events_root: None,
}
2023-01-26T10:21:23.140220Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:23.140223Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount1"::London::0
2023-01-26T10:21:23.140225Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount1.json"
2023-01-26T10:21:23.140227Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:23.140229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:23.140337Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount1"
2023-01-26T10:21:23.140341Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1961805,
    events_root: None,
}
2023-01-26T10:21:23.140346Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:23.140349Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount1"::Merge::0
2023-01-26T10:21:23.140350Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount1.json"
2023-01-26T10:21:23.140353Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:23.140354Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:23.140483Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount1"
2023-01-26T10:21:23.140488Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1961805,
    events_root: None,
}
2023-01-26T10:21:23.142072Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:342.866389ms
2023-01-26T10:21:23.419992Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount2.json", Total Files :: 1
2023-01-26T10:21:23.448136Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:23.448315Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:23.448319Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:23.448374Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:23.448376Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:23.448431Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:23.448433Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:23.448488Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:23.448556Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:23.448559Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount2"::Istanbul::0
2023-01-26T10:21:23.448562Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount2.json"
2023-01-26T10:21:23.448565Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:23.448566Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:23.794254Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount2"
2023-01-26T10:21:23.794269Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2550401,
    events_root: None,
}
2023-01-26T10:21:23.794281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:23.794288Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount2"::Berlin::0
2023-01-26T10:21:23.794289Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount2.json"
2023-01-26T10:21:23.794292Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:23.794294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:23.794461Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount2"
2023-01-26T10:21:23.794465Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2550401,
    events_root: None,
}
2023-01-26T10:21:23.794473Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:23.794475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount2"::London::0
2023-01-26T10:21:23.794477Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount2.json"
2023-01-26T10:21:23.794480Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:23.794481Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:23.794625Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount2"
2023-01-26T10:21:23.794630Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2550401,
    events_root: None,
}
2023-01-26T10:21:23.794636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:23.794639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount2"::Merge::0
2023-01-26T10:21:23.794641Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount2.json"
2023-01-26T10:21:23.794645Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:23.794646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:23.794790Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount2"
2023-01-26T10:21:23.794794Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2550401,
    events_root: None,
}
2023-01-26T10:21:23.796361Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.669183ms
2023-01-26T10:21:24.063159Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount3.json", Total Files :: 1
2023-01-26T10:21:24.092434Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:24.092619Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:24.092623Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:24.092678Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:24.092680Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:24.092743Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:24.092745Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:24.092798Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:24.092868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:24.092871Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount3"::Istanbul::0
2023-01-26T10:21:24.092874Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount3.json"
2023-01-26T10:21:24.092878Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:24.092879Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 78, 54, 38, 44, 14, 10, 177, 86, 57, 124, 50, 68, 78, 74, 1, 143, 233, 59, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T10:21:24.716582Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount3"
2023-01-26T10:21:24.716592Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17984603,
    events_root: None,
}
2023-01-26T10:21:24.716624Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:24.716630Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount3"::Berlin::0
2023-01-26T10:21:24.716632Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount3.json"
2023-01-26T10:21:24.716635Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:24.716637Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:24.717022Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount3"
2023-01-26T10:21:24.717027Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5119538,
    events_root: None,
}
2023-01-26T10:21:24.717036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:24.717039Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount3"::London::0
2023-01-26T10:21:24.717041Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount3.json"
2023-01-26T10:21:24.717044Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:24.717045Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:24.717326Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount3"
2023-01-26T10:21:24.717331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4192972,
    events_root: None,
}
2023-01-26T10:21:24.717340Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:24.717351Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount3"::Merge::0
2023-01-26T10:21:24.717354Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount3.json"
2023-01-26T10:21:24.717357Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:24.717358Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:24.717640Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount3"
2023-01-26T10:21:24.717645Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4192972,
    events_root: None,
}
2023-01-26T10:21:24.719274Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:625.224538ms
2023-01-26T10:21:24.988248Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount4.json", Total Files :: 1
2023-01-26T10:21:25.016916Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:25.017102Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:25.017106Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:25.017159Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:25.017162Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:25.017223Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:25.017225Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:25.017278Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:25.017280Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:25.017332Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:25.017426Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:25.017430Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount4"::Istanbul::0
2023-01-26T10:21:25.017432Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount4.json"
2023-01-26T10:21:25.017436Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:25.017437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [197, 105, 29, 201, 13, 159, 210, 162, 233, 165, 250, 91, 210, 139, 247, 127, 253, 96, 170, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T10:21:25.630687Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount4"
2023-01-26T10:21:25.630696Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18610640,
    events_root: None,
}
2023-01-26T10:21:25.630730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:25.630736Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount4"::Berlin::0
2023-01-26T10:21:25.630738Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount4.json"
2023-01-26T10:21:25.630741Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:25.630743Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:25.631194Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount4"
2023-01-26T10:21:25.631199Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5822710,
    events_root: None,
}
2023-01-26T10:21:25.631209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:25.631211Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount4"::London::0
2023-01-26T10:21:25.631214Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount4.json"
2023-01-26T10:21:25.631216Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:25.631218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:25.631533Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount4"
2023-01-26T10:21:25.631538Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4891568,
    events_root: None,
}
2023-01-26T10:21:25.631548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:25.631550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDeletedAccount4"::Merge::0
2023-01-26T10:21:25.631552Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDeletedAccount4.json"
2023-01-26T10:21:25.631555Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:25.631556Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:25.631868Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDeletedAccount4"
2023-01-26T10:21:25.631873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4891568,
    events_root: None,
}
2023-01-26T10:21:25.633714Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:614.971016ms
2023-01-26T10:21:25.902476Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json", Total Files :: 1
2023-01-26T10:21:25.932334Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:25.932428Z  WARN evm_eth_compliance::statetest::runner: Skipping Pre Test test_name: '"extCodeHashDynamicArgument"', owner_address: '0x0000000000000000000000000000000000000002'
2023-01-26T10:21:25.932432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:25.932535Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:25.932538Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:25.932598Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:25.932600Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:25.932648Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:25.932650Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:25.932706Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:25.932777Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:25.932780Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Istanbul::0
2023-01-26T10:21:25.932783Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:25.932786Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:25.932788Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.288789Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.288806Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2525038,
    events_root: None,
}
2023-01-26T10:21:26.288817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T10:21:26.288823Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Istanbul::1
2023-01-26T10:21:26.288825Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.288828Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.288829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.288961Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.288965Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1581719,
    events_root: None,
}
2023-01-26T10:21:26.288970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-26T10:21:26.288972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Istanbul::2
2023-01-26T10:21:26.288974Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.288977Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.288978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.289282Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.289287Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6261758,
    events_root: None,
}
2023-01-26T10:21:26.289296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-26T10:21:26.289298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Istanbul::3
2023-01-26T10:21:26.289300Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.289303Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.289305Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.289671Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.289677Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6510279,
    events_root: None,
}
2023-01-26T10:21:26.289686Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-26T10:21:26.289689Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Istanbul::4
2023-01-26T10:21:26.289692Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.289695Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.289697Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.289859Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.289863Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2515406,
    events_root: None,
}
2023-01-26T10:21:26.289869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:26.289871Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Berlin::0
2023-01-26T10:21:26.289873Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.289876Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.289878Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.289985Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.289989Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2525038,
    events_root: None,
}
2023-01-26T10:21:26.289994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T10:21:26.289997Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Berlin::1
2023-01-26T10:21:26.290000Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.290002Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.290004Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.290099Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.290103Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1581719,
    events_root: None,
}
2023-01-26T10:21:26.290108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T10:21:26.290110Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Berlin::2
2023-01-26T10:21:26.290112Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.290114Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.290116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.290397Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.290402Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6261758,
    events_root: None,
}
2023-01-26T10:21:26.290409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T10:21:26.290412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Berlin::3
2023-01-26T10:21:26.290414Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.290416Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.290418Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.290710Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.290714Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6510279,
    events_root: None,
}
2023-01-26T10:21:26.290722Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-26T10:21:26.290725Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Berlin::4
2023-01-26T10:21:26.290727Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.290729Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.290731Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.290869Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.290873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2515406,
    events_root: None,
}
2023-01-26T10:21:26.290879Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:26.290882Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::London::0
2023-01-26T10:21:26.290884Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.290886Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.290888Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.291019Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.291025Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2525038,
    events_root: None,
}
2023-01-26T10:21:26.291031Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T10:21:26.291034Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::London::1
2023-01-26T10:21:26.291037Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.291041Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.291043Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.291147Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.291151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1581719,
    events_root: None,
}
2023-01-26T10:21:26.291156Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T10:21:26.291158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::London::2
2023-01-26T10:21:26.291161Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.291164Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.291165Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.291444Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.291449Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6261758,
    events_root: None,
}
2023-01-26T10:21:26.291457Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T10:21:26.291459Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::London::3
2023-01-26T10:21:26.291461Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.291465Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.291466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.291760Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.291765Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6510279,
    events_root: None,
}
2023-01-26T10:21:26.291773Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-26T10:21:26.291776Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::London::4
2023-01-26T10:21:26.291778Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.291780Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.291782Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.291920Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.291925Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2515406,
    events_root: None,
}
2023-01-26T10:21:26.291930Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:26.291932Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Merge::0
2023-01-26T10:21:26.291934Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.291937Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.291938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.292043Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.292047Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2525038,
    events_root: None,
}
2023-01-26T10:21:26.292052Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T10:21:26.292055Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Merge::1
2023-01-26T10:21:26.292057Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.292060Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.292061Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.292152Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.292156Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1581719,
    events_root: None,
}
2023-01-26T10:21:26.292162Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T10:21:26.292164Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Merge::2
2023-01-26T10:21:26.292166Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.292168Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.292170Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.292467Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.292471Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6261758,
    events_root: None,
}
2023-01-26T10:21:26.292480Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T10:21:26.292482Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Merge::3
2023-01-26T10:21:26.292484Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.292487Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.292489Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.292782Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.292786Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6510279,
    events_root: None,
}
2023-01-26T10:21:26.292794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-26T10:21:26.292797Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashDynamicArgument"::Merge::4
2023-01-26T10:21:26.292799Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashDynamicArgument.json"
2023-01-26T10:21:26.292802Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:26.292803Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:26.292940Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashDynamicArgument"
2023-01-26T10:21:26.292945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2515406,
    events_root: None,
}
2023-01-26T10:21:26.294776Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:360.621162ms
2023-01-26T10:21:26.559234Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashInInitCode.json", Total Files :: 1
2023-01-26T10:21:26.589050Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:26.589247Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:26.589251Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:26.589311Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:26.589400Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:26.589405Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "extCodeHashInInitCode"::Istanbul::0
2023-01-26T10:21:26.589409Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashInInitCode.json"
2023-01-26T10:21:26.589413Z  WARN evm_eth_compliance::statetest::runner: TX len : 51
2023-01-26T10:21:26.589415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T10:21:26.589417Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "extCodeHashInInitCode"::Istanbul::1
2023-01-26T10:21:26.589420Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashInInitCode.json"
2023-01-26T10:21:26.589422Z  WARN evm_eth_compliance::statetest::runner: TX len : 70
2023-01-26T10:21:26.589424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:26.589426Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "extCodeHashInInitCode"::Berlin::0
2023-01-26T10:21:26.589429Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashInInitCode.json"
2023-01-26T10:21:26.589431Z  WARN evm_eth_compliance::statetest::runner: TX len : 51
2023-01-26T10:21:26.589433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T10:21:26.589435Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "extCodeHashInInitCode"::Berlin::1
2023-01-26T10:21:26.589437Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashInInitCode.json"
2023-01-26T10:21:26.589440Z  WARN evm_eth_compliance::statetest::runner: TX len : 70
2023-01-26T10:21:26.589441Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:26.589443Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "extCodeHashInInitCode"::London::0
2023-01-26T10:21:26.589445Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashInInitCode.json"
2023-01-26T10:21:26.589448Z  WARN evm_eth_compliance::statetest::runner: TX len : 51
2023-01-26T10:21:26.589449Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T10:21:26.589451Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "extCodeHashInInitCode"::London::1
2023-01-26T10:21:26.589453Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashInInitCode.json"
2023-01-26T10:21:26.589456Z  WARN evm_eth_compliance::statetest::runner: TX len : 70
2023-01-26T10:21:26.589457Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:26.589459Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "extCodeHashInInitCode"::Merge::0
2023-01-26T10:21:26.589461Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashInInitCode.json"
2023-01-26T10:21:26.589465Z  WARN evm_eth_compliance::statetest::runner: TX len : 51
2023-01-26T10:21:26.589466Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T10:21:26.589468Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "extCodeHashInInitCode"::Merge::1
2023-01-26T10:21:26.589470Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashInInitCode.json"
2023-01-26T10:21:26.589473Z  WARN evm_eth_compliance::statetest::runner: TX len : 70
2023-01-26T10:21:26.590206Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:431.793s
2023-01-26T10:21:26.851362Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashMaxCodeSize.json", Total Files :: 1
2023-01-26T10:21:26.880540Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:26.880740Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:26.880744Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:26.880797Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:26.880800Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:26.880855Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:26.880857Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:26.880913Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:26.880916Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:26.881049Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:26.881121Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:26.881125Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashMaxCodeSize"::Istanbul::0
2023-01-26T10:21:26.881127Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashMaxCodeSize.json"
2023-01-26T10:21:26.881131Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:26.881132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:27.225905Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashMaxCodeSize"
2023-01-26T10:21:27.225921Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:27.225927Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:27.225945Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:27.225950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashMaxCodeSize"::Berlin::0
2023-01-26T10:21:27.225952Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashMaxCodeSize.json"
2023-01-26T10:21:27.225954Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:27.225956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:27.226078Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashMaxCodeSize"
2023-01-26T10:21:27.226083Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:27.226086Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:27.226098Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:27.226100Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashMaxCodeSize"::London::0
2023-01-26T10:21:27.226102Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashMaxCodeSize.json"
2023-01-26T10:21:27.226104Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:27.226106Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:27.226214Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashMaxCodeSize"
2023-01-26T10:21:27.226218Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:27.226220Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:27.226232Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:27.226235Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashMaxCodeSize"::Merge::0
2023-01-26T10:21:27.226236Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashMaxCodeSize.json"
2023-01-26T10:21:27.226239Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:27.226240Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:27.226362Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashMaxCodeSize"
2023-01-26T10:21:27.226366Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:27.226369Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:27.228356Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:345.846117ms
2023-01-26T10:21:27.515469Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashNewAccount.json", Total Files :: 1
2023-01-26T10:21:27.544212Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:27.544403Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:27.544407Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:27.544458Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:27.544542Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:27.544547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashNewAccount"::Istanbul::0
2023-01-26T10:21:27.544550Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashNewAccount.json"
2023-01-26T10:21:27.544555Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:27.544557Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [117, 226, 63, 133, 28, 233, 46, 230, 40, 150, 193, 251, 17, 39, 212, 190, 44, 83, 245, 157, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T10:21:28.184885Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashNewAccount"
2023-01-26T10:21:28.184895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 18266227,
    events_root: None,
}
2023-01-26T10:21:28.184922Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:28.184928Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashNewAccount"::Berlin::0
2023-01-26T10:21:28.184930Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashNewAccount.json"
2023-01-26T10:21:28.184933Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:28.184934Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:28.185301Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashNewAccount"
2023-01-26T10:21:28.185305Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5190673,
    events_root: None,
}
2023-01-26T10:21:28.185314Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:28.185317Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashNewAccount"::London::0
2023-01-26T10:21:28.185319Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashNewAccount.json"
2023-01-26T10:21:28.185323Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:28.185324Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:28.185600Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashNewAccount"
2023-01-26T10:21:28.185605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3919119,
    events_root: None,
}
2023-01-26T10:21:28.185613Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:28.185615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashNewAccount"::Merge::0
2023-01-26T10:21:28.185617Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashNewAccount.json"
2023-01-26T10:21:28.185620Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:28.185621Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:28.185879Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashNewAccount"
2023-01-26T10:21:28.185884Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3919119,
    events_root: None,
}
2023-01-26T10:21:28.187529Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:641.685337ms
2023-01-26T10:21:28.472580Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashNonExistingAccount.json", Total Files :: 1
2023-01-26T10:21:28.501765Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:28.501969Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:28.501974Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:28.502033Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:28.502036Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:28.502097Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:28.502100Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:28.502155Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:28.502230Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:28.502234Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashNonExistingAccount"::Istanbul::0
2023-01-26T10:21:28.502238Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashNonExistingAccount.json"
2023-01-26T10:21:28.502242Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:28.502244Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:28.862331Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashNonExistingAccount"
2023-01-26T10:21:28.862348Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:28.862354Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:28.862371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:28.862377Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashNonExistingAccount"::Berlin::0
2023-01-26T10:21:28.862380Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashNonExistingAccount.json"
2023-01-26T10:21:28.862383Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:28.862384Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:28.862508Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashNonExistingAccount"
2023-01-26T10:21:28.862513Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:28.862516Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:28.862528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:28.862531Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashNonExistingAccount"::London::0
2023-01-26T10:21:28.862533Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashNonExistingAccount.json"
2023-01-26T10:21:28.862535Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:28.862537Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:28.862653Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashNonExistingAccount"
2023-01-26T10:21:28.862658Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:28.862661Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:28.862673Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:28.862675Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashNonExistingAccount"::Merge::0
2023-01-26T10:21:28.862677Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashNonExistingAccount.json"
2023-01-26T10:21:28.862680Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:28.862681Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:28.862795Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashNonExistingAccount"
2023-01-26T10:21:28.862799Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1880349,
    events_root: None,
}
2023-01-26T10:21:28.862802Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=43): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:28.864288Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.055342ms
2023-01-26T10:21:29.142848Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json", Total Files :: 1
2023-01-26T10:21:29.171846Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:29.172030Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:29.172034Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:29.172088Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:29.172158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:29.172161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Istanbul::0
2023-01-26T10:21:29.172164Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.172167Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.172169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.525616Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.525631Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6219887,
    events_root: None,
}
2023-01-26T10:21:29.525645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T10:21:29.525651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Istanbul::1
2023-01-26T10:21:29.525653Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.525656Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.525657Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.525802Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.525806Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2951831,
    events_root: None,
}
2023-01-26T10:21:29.525812Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-26T10:21:29.525814Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Istanbul::2
2023-01-26T10:21:29.525816Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.525820Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.525822Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.525917Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.525922Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.525927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-26T10:21:29.525929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Istanbul::3
2023-01-26T10:21:29.525931Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.525934Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.525935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.526027Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.526032Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.526036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-26T10:21:29.526039Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Istanbul::4
2023-01-26T10:21:29.526041Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.526043Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.526045Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.526137Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.526141Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.526146Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-26T10:21:29.526148Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Istanbul::5
2023-01-26T10:21:29.526150Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.526153Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.526154Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.526253Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.526258Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.526263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-26T10:21:29.526267Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Istanbul::6
2023-01-26T10:21:29.526269Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.526273Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.526274Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.526388Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.526393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.526399Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-26T10:21:29.526402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Istanbul::7
2023-01-26T10:21:29.526404Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.526408Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.526409Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.526516Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.526521Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.526525Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-26T10:21:29.526528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Istanbul::8
2023-01-26T10:21:29.526531Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.526534Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.526536Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.526653Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.526658Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.526663Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:29.526666Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Berlin::0
2023-01-26T10:21:29.526668Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.526670Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.526672Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.526954Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.526959Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6258501,
    events_root: None,
}
2023-01-26T10:21:29.526968Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T10:21:29.526972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Berlin::1
2023-01-26T10:21:29.526974Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.526979Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.526981Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.527114Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.527119Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2951831,
    events_root: None,
}
2023-01-26T10:21:29.527124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T10:21:29.527127Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Berlin::2
2023-01-26T10:21:29.527129Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.527131Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.527133Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.527228Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.527232Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.527237Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T10:21:29.527239Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Berlin::3
2023-01-26T10:21:29.527241Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.527243Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.527245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.527336Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.527339Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.527347Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-26T10:21:29.527350Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Berlin::4
2023-01-26T10:21:29.527353Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.527356Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.527358Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.527469Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.527473Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.527478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-26T10:21:29.527480Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Berlin::5
2023-01-26T10:21:29.527482Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.527485Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.527486Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.527578Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.527582Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.527587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-26T10:21:29.527591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Berlin::6
2023-01-26T10:21:29.527593Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.527596Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.527598Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.527688Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.527692Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.527697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-26T10:21:29.527699Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Berlin::7
2023-01-26T10:21:29.527701Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.527703Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.527705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.527795Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.527799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.527804Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-26T10:21:29.527806Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Berlin::8
2023-01-26T10:21:29.527808Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.527811Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.527812Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.527907Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.527911Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.527915Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:29.527918Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::London::0
2023-01-26T10:21:29.527920Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.527923Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.527924Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.528213Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.528218Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6258501,
    events_root: None,
}
2023-01-26T10:21:29.528226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T10:21:29.528228Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::London::1
2023-01-26T10:21:29.528230Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.528234Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.528235Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.528399Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.528404Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2951831,
    events_root: None,
}
2023-01-26T10:21:29.528411Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T10:21:29.528414Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::London::2
2023-01-26T10:21:29.528417Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.528420Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.528422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.528533Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.528537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.528542Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T10:21:29.528545Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::London::3
2023-01-26T10:21:29.528546Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.528549Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.528550Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.528644Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.528648Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.528653Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-26T10:21:29.528655Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::London::4
2023-01-26T10:21:29.528657Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.528660Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.528661Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.528752Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.528757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.528761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-26T10:21:29.528763Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::London::5
2023-01-26T10:21:29.528765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.528768Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.528769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.528858Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.528862Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.528867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-26T10:21:29.528869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::London::6
2023-01-26T10:21:29.528872Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.528874Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.528876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.528966Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.528970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.528975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-26T10:21:29.528977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::London::7
2023-01-26T10:21:29.528979Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.528981Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.528983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.529073Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.529077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.529081Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-26T10:21:29.529083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::London::8
2023-01-26T10:21:29.529086Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.529088Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.529090Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.529184Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.529189Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.529195Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:29.529197Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Merge::0
2023-01-26T10:21:29.529200Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.529203Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.529205Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.529506Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.529512Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6258501,
    events_root: None,
}
2023-01-26T10:21:29.529519Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T10:21:29.529522Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Merge::1
2023-01-26T10:21:29.529524Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.529526Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.529528Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.529655Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.529659Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2951831,
    events_root: None,
}
2023-01-26T10:21:29.529666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T10:21:29.529668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Merge::2
2023-01-26T10:21:29.529670Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.529673Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.529674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.529766Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.529770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.529775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T10:21:29.529777Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Merge::3
2023-01-26T10:21:29.529779Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.529782Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.529783Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.529875Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.529879Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.529884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-26T10:21:29.529886Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Merge::4
2023-01-26T10:21:29.529888Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.529890Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.529892Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.529983Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.529987Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.529992Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-26T10:21:29.529994Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Merge::5
2023-01-26T10:21:29.529996Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.529998Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.530000Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.530088Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.530093Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.530098Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-26T10:21:29.530100Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Merge::6
2023-01-26T10:21:29.530102Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.530105Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.530106Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.530195Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.530198Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.530203Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-26T10:21:29.530205Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Merge::7
2023-01-26T10:21:29.530207Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.530210Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.530211Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.530322Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.530327Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.530333Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-26T10:21:29.530338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashPrecompiles"::Merge::8
2023-01-26T10:21:29.530341Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashPrecompiles.json"
2023-01-26T10:21:29.530345Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T10:21:29.530347Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:29.530459Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashPrecompiles"
2023-01-26T10:21:29.530463Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1586558,
    events_root: None,
}
2023-01-26T10:21:29.532188Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:358.627607ms
2023-01-26T10:21:29.801939Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSTATICCALL.json", Total Files :: 1
2023-01-26T10:21:29.830509Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:29.830689Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:29.830693Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:29.830746Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:29.830749Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:29.830804Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:29.830807Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:29.830855Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:29.830858Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:29.830899Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:29.830972Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:29.830976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSTATICCALL"::Istanbul::0
2023-01-26T10:21:29.830979Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSTATICCALL.json"
2023-01-26T10:21:29.830982Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:29.830983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:30.212575Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSTATICCALL"
2023-01-26T10:21:30.212592Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1879339,
    events_root: None,
}
2023-01-26T10:21:30.212598Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=41): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:30.212615Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:30.212620Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSTATICCALL"::Berlin::0
2023-01-26T10:21:30.212621Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSTATICCALL.json"
2023-01-26T10:21:30.212626Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:30.212627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:30.212742Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSTATICCALL"
2023-01-26T10:21:30.212746Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1879339,
    events_root: None,
}
2023-01-26T10:21:30.212749Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=41): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:30.212761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:30.212764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSTATICCALL"::London::0
2023-01-26T10:21:30.212765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSTATICCALL.json"
2023-01-26T10:21:30.212768Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:30.212769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:30.212905Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSTATICCALL"
2023-01-26T10:21:30.212911Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1879339,
    events_root: None,
}
2023-01-26T10:21:30.212915Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=41): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:30.212931Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:30.212934Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSTATICCALL"::Merge::0
2023-01-26T10:21:30.212937Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSTATICCALL.json"
2023-01-26T10:21:30.212941Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:30.212943Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:30.213090Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSTATICCALL"
2023-01-26T10:21:30.213094Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1879339,
    events_root: None,
}
2023-01-26T10:21:30.213097Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=41): returndatacopy end 0 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:30.214580Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:382.60467ms
2023-01-26T10:21:30.496575Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSelf.json", Total Files :: 1
2023-01-26T10:21:30.525286Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:30.525490Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:30.525495Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:30.525545Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:30.525616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:30.525619Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSelf"::Istanbul::0
2023-01-26T10:21:30.525622Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSelf.json"
2023-01-26T10:21:30.525626Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:30.525627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:30.873773Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSelf"
2023-01-26T10:21:30.873789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6229480,
    events_root: None,
}
2023-01-26T10:21:30.873802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:30.873808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSelf"::Berlin::0
2023-01-26T10:21:30.873810Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSelf.json"
2023-01-26T10:21:30.873812Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:30.873814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:30.874067Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSelf"
2023-01-26T10:21:30.874071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4096387,
    events_root: None,
}
2023-01-26T10:21:30.874078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:30.874081Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSelf"::London::0
2023-01-26T10:21:30.874082Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSelf.json"
2023-01-26T10:21:30.874085Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:30.874086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:30.874326Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSelf"
2023-01-26T10:21:30.874331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4096387,
    events_root: None,
}
2023-01-26T10:21:30.874337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:30.874340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSelf"::Merge::0
2023-01-26T10:21:30.874342Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSelf.json"
2023-01-26T10:21:30.874344Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:30.874345Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:30.874603Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSelf"
2023-01-26T10:21:30.874608Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4096387,
    events_root: None,
}
2023-01-26T10:21:30.876185Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:349.334501ms
2023-01-26T10:21:31.153373Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSelfInInit.json", Total Files :: 1
2023-01-26T10:21:31.182431Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:31.182627Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:31.182631Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:31.182684Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:31.182783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:31.182789Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSelfInInit"::Istanbul::0
2023-01-26T10:21:31.182793Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSelfInInit.json"
2023-01-26T10:21:31.182797Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:31.182799Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [141, 84, 14, 42, 175, 152, 40, 113, 39, 73, 175, 237, 247, 197, 62, 208, 52, 166, 253, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T10:21:31.800279Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSelfInInit"
2023-01-26T10:21:31.800288Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17500501,
    events_root: None,
}
2023-01-26T10:21:31.800318Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:31.800324Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSelfInInit"::Berlin::0
2023-01-26T10:21:31.800326Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSelfInInit.json"
2023-01-26T10:21:31.800329Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:31.800331Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:31.800627Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSelfInInit"
2023-01-26T10:21:31.800632Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3852963,
    events_root: None,
}
2023-01-26T10:21:31.800640Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:31.800643Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSelfInInit"::London::0
2023-01-26T10:21:31.800644Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSelfInInit.json"
2023-01-26T10:21:31.800647Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:31.800648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:31.800871Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSelfInInit"
2023-01-26T10:21:31.800875Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3852963,
    events_root: None,
}
2023-01-26T10:21:31.800882Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:31.800885Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSelfInInit"::Merge::0
2023-01-26T10:21:31.800887Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSelfInInit.json"
2023-01-26T10:21:31.800889Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:31.800891Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:31.801116Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSelfInInit"
2023-01-26T10:21:31.801121Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3852963,
    events_root: None,
}
2023-01-26T10:21:31.802747Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:618.702984ms
2023-01-26T10:21:32.060636Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json", Total Files :: 1
2023-01-26T10:21:32.093008Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:32.093190Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.093194Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:32.093244Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.093246Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:32.093301Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.093303Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:32.093367Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.093371Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:32.093440Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.093444Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-26T10:21:32.093519Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.093521Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-26T10:21:32.093574Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.093576Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-26T10:21:32.093621Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.093623Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-26T10:21:32.093664Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.093666Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-26T10:21:32.093717Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.093787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:32.093790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Istanbul::0
2023-01-26T10:21:32.093793Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.093796Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.093798Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.450966Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.450980Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.450986Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.450999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T10:21:32.451004Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Istanbul::1
2023-01-26T10:21:32.451006Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.451009Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.451010Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.451127Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.451131Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.451134Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.451143Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-26T10:21:32.451145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Istanbul::2
2023-01-26T10:21:32.451147Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.451150Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.451151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.451237Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.451241Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.451244Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.451253Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-26T10:21:32.451256Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Istanbul::3
2023-01-26T10:21:32.451258Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.451261Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.451263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.451351Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.451355Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.451357Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.451365Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-26T10:21:32.451367Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Istanbul::4
2023-01-26T10:21:32.451369Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.451371Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.451373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.451455Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.451460Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.451463Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.451473Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-26T10:21:32.451476Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Istanbul::5
2023-01-26T10:21:32.451479Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.451482Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.451483Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.451592Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.451598Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.451602Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.451612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:32.451615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Berlin::0
2023-01-26T10:21:32.451618Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.451621Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.451622Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.451713Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.451717Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.451720Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.451728Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T10:21:32.451730Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Berlin::1
2023-01-26T10:21:32.451732Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.451735Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.451737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.451824Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.451828Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.451831Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.451838Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T10:21:32.451841Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Berlin::2
2023-01-26T10:21:32.451842Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.451846Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.451847Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.451930Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.451933Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.451936Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.451944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T10:21:32.451946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Berlin::3
2023-01-26T10:21:32.451948Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.451950Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.451951Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.452035Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.452039Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.452043Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.452053Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-26T10:21:32.452056Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Berlin::4
2023-01-26T10:21:32.452058Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.452062Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.452064Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.452161Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.452166Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.452168Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.452176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-26T10:21:32.452178Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Berlin::5
2023-01-26T10:21:32.452180Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.452183Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.452184Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.452268Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.452272Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.452274Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.452282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:32.452284Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::London::0
2023-01-26T10:21:32.452286Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.452289Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.452290Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.452371Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.452375Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.452377Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.452385Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T10:21:32.452387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::London::1
2023-01-26T10:21:32.452390Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.452393Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.452394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.452475Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.452479Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.452482Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.452490Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T10:21:32.452492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::London::2
2023-01-26T10:21:32.452494Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.452496Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.452497Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.452603Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.452608Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.452612Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.452622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T10:21:32.452625Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::London::3
2023-01-26T10:21:32.452627Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.452631Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.452633Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.452725Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.452729Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.452733Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.452741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-26T10:21:32.452743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::London::4
2023-01-26T10:21:32.452745Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.452747Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.452748Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.452843Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.452848Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.452850Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.452858Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-26T10:21:32.452860Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::London::5
2023-01-26T10:21:32.452862Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.452865Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.452866Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.452954Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.452958Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.452961Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.452969Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:32.452971Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Merge::0
2023-01-26T10:21:32.452973Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.452975Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.452977Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.453059Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.453062Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.453065Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.453073Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T10:21:32.453075Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Merge::1
2023-01-26T10:21:32.453077Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.453079Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.453080Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.453178Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.453183Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.453186Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.453197Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T10:21:32.453200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Merge::2
2023-01-26T10:21:32.453202Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.453206Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.453208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.453312Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.453316Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.453318Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.453326Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T10:21:32.453329Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Merge::3
2023-01-26T10:21:32.453330Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.453333Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.453334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.453429Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.453433Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.453435Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.453443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-26T10:21:32.453446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Merge::4
2023-01-26T10:21:32.453448Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.453450Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.453452Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.453534Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.453537Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.453540Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.453548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-26T10:21:32.453550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallOOG"::Merge::5
2023-01-26T10:21:32.453552Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallOOG.json"
2023-01-26T10:21:32.453555Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-26T10:21:32.453556Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:32.453640Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallOOG"
2023-01-26T10:21:32.453645Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552215,
    events_root: None,
}
2023-01-26T10:21:32.453648Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=17): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T10:21:32.455375Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:360.655645ms
2023-01-26T10:21:32.728079Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallSuicide.json", Total Files :: 1
2023-01-26T10:21:32.757529Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:32.757721Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.757725Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:32.757780Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.757782Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:32.757839Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.757841Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:32.757897Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:32.757971Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:32.757976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallSuicide"::Istanbul::0
2023-01-26T10:21:32.757979Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallSuicide.json"
2023-01-26T10:21:32.757982Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:32.757983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.172027Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallSuicide"
2023-01-26T10:21:33.172042Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19518195,
    events_root: None,
}
2023-01-26T10:21:33.172068Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:33.172074Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallSuicide"::Berlin::0
2023-01-26T10:21:33.172076Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallSuicide.json"
2023-01-26T10:21:33.172079Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:33.172081Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.172710Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallSuicide"
2023-01-26T10:21:33.172715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10605549,
    events_root: None,
}
2023-01-26T10:21:33.172732Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:33.172735Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallSuicide"::London::0
2023-01-26T10:21:33.172737Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallSuicide.json"
2023-01-26T10:21:33.172740Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:33.172741Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.173354Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallSuicide"
2023-01-26T10:21:33.173359Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10605549,
    events_root: None,
}
2023-01-26T10:21:33.173378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:33.173381Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extCodeHashSubcallSuicide"::Merge::0
2023-01-26T10:21:33.173383Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extCodeHashSubcallSuicide.json"
2023-01-26T10:21:33.173386Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T10:21:33.173387Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.173997Z  INFO evm_eth_compliance::statetest::runner: UC : "extCodeHashSubcallSuicide"
2023-01-26T10:21:33.174002Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10605549,
    events_root: None,
}
2023-01-26T10:21:33.175587Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:416.495038ms
2023-01-26T10:21:33.454958Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json", Total Files :: 1
2023-01-26T10:21:33.484390Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T10:21:33.484576Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.484579Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T10:21:33.484631Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.484633Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T10:21:33.484690Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.484692Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T10:21:33.484749Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.484752Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T10:21:33.484814Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.484817Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-26T10:21:33.484893Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.484896Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-26T10:21:33.484950Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.484952Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-26T10:21:33.484988Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.484990Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-26T10:21:33.485030Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.485032Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-26T10:21:33.485086Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.485088Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-26T10:21:33.485134Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.485136Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-26T10:21:33.485177Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T10:21:33.485249Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T10:21:33.485252Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Istanbul::0
2023-01-26T10:21:33.485255Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:33.485258Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:33.485259Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.835091Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:33.835106Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12518342,
    events_root: None,
}
2023-01-26T10:21:33.835128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T10:21:33.835134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Istanbul::1
2023-01-26T10:21:33.835136Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:33.835139Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:33.835140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.835714Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:33.835719Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10568639,
    events_root: None,
}
2023-01-26T10:21:33.835737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-26T10:21:33.835740Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Istanbul::2
2023-01-26T10:21:33.835742Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:33.835745Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:33.835746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.836289Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:33.836293Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:33.836310Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-26T10:21:33.836312Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Istanbul::3
2023-01-26T10:21:33.836314Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:33.836317Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:33.836318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.836863Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:33.836867Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:33.836884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-26T10:21:33.836886Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Istanbul::4
2023-01-26T10:21:33.836888Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:33.836891Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:33.836892Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.837444Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:33.837448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:33.837465Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-26T10:21:33.837467Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Istanbul::5
2023-01-26T10:21:33.837469Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:33.837472Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:33.837473Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.838065Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:33.838070Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10571486,
    events_root: None,
}
2023-01-26T10:21:33.838087Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-26T10:21:33.838089Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Istanbul::6
2023-01-26T10:21:33.838091Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:33.838094Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:33.838095Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.838735Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:33.838740Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16158591,
    events_root: None,
}
2023-01-26T10:21:33.838760Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-26T10:21:33.838762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Istanbul::7
2023-01-26T10:21:33.838764Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:33.838767Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:33.838768Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:33.839519Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:33.839524Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21040312,
    events_root: None,
}
2023-01-26T10:21:33.839546Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-26T10:21:33.839548Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Istanbul::8
2023-01-26T10:21:33.839550Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:33.839553Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:33.839554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [245, 50, 154, 231, 66, 248, 161, 212, 112, 93, 122, 138, 82, 13, 161, 114, 86, 107, 141, 170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 189, 137, 170, 161, 168, 98, 8, 218, 14, 105, 2, 242, 92, 44, 234, 2, 122, 233, 63]) }
2023-01-26T10:21:34.100000Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.100010Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 33086104,
    events_root: None,
}
2023-01-26T10:21:34.100054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-26T10:21:34.100059Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Istanbul::9
2023-01-26T10:21:34.100061Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.100064Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.100066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [180, 27, 69, 140, 234, 88, 132, 50, 206, 242, 73, 68, 84, 163, 96, 20, 48, 4, 152, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 221, 99, 117, 94, 25, 113, 14, 55, 217, 63, 213, 179, 235, 175, 240, 178, 120, 15, 225]) }
2023-01-26T10:21:34.101551Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.101558Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 33729321,
    events_root: None,
}
2023-01-26T10:21:34.101595Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T10:21:34.101600Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Berlin::0
2023-01-26T10:21:34.101602Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.101604Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.101606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.102349Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.102355Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17306975,
    events_root: None,
}
2023-01-26T10:21:34.102376Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T10:21:34.102380Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Berlin::1
2023-01-26T10:21:34.102382Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.102384Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.102386Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.103028Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.103033Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10568639,
    events_root: None,
}
2023-01-26T10:21:34.103051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-26T10:21:34.103054Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Berlin::2
2023-01-26T10:21:34.103056Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.103058Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.103060Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.103635Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.103640Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:34.103657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-26T10:21:34.103660Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Berlin::3
2023-01-26T10:21:34.103661Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.103664Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.103665Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.104233Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.104238Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:34.104255Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-26T10:21:34.104258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Berlin::4
2023-01-26T10:21:34.104260Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.104263Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.104264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.104834Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.104838Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:34.104856Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-26T10:21:34.104859Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Berlin::5
2023-01-26T10:21:34.104860Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.104863Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.104864Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.105463Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.105469Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10571486,
    events_root: None,
}
2023-01-26T10:21:34.105487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-26T10:21:34.105490Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Berlin::6
2023-01-26T10:21:34.105492Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.105494Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.105496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.106170Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.106174Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16158591,
    events_root: None,
}
2023-01-26T10:21:34.106196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-26T10:21:34.106199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Berlin::7
2023-01-26T10:21:34.106201Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.106203Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.106206Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.106848Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.106852Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14480929,
    events_root: None,
}
2023-01-26T10:21:34.106872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-26T10:21:34.106875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Berlin::8
2023-01-26T10:21:34.106877Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.106879Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.106881Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [13, 130, 170, 36, 5, 129, 37, 224, 210, 13, 145, 101, 140, 181, 175, 241, 195, 18, 247, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([164, 19, 188, 157, 123, 198, 227, 16, 99, 7, 112, 55, 126, 183, 242, 167, 190, 31, 240, 147]) }
2023-01-26T10:21:34.108192Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.108197Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 31428161,
    events_root: None,
}
2023-01-26T10:21:34.108229Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-26T10:21:34.108232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Berlin::9
2023-01-26T10:21:34.108234Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.108237Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.108238Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.109185Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.109191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 22874574,
    events_root: None,
}
2023-01-26T10:21:34.109217Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T10:21:34.109220Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::London::0
2023-01-26T10:21:34.109222Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.109225Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.109226Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.109927Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.109932Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17306975,
    events_root: None,
}
2023-01-26T10:21:34.109955Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T10:21:34.109958Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::London::1
2023-01-26T10:21:34.109960Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.109962Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.109964Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.110558Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.110562Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10568639,
    events_root: None,
}
2023-01-26T10:21:34.110581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-26T10:21:34.110583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::London::2
2023-01-26T10:21:34.110585Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.110588Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.110589Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.111156Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.111160Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:34.111177Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-26T10:21:34.111180Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::London::3
2023-01-26T10:21:34.111182Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.111185Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.111186Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.111755Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.111760Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:34.111777Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-26T10:21:34.111780Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::London::4
2023-01-26T10:21:34.111782Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.111785Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.111786Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.112349Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.112353Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:34.112371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-26T10:21:34.112374Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::London::5
2023-01-26T10:21:34.112376Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.112379Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.112380Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.112967Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.112973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10571486,
    events_root: None,
}
2023-01-26T10:21:34.112991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-26T10:21:34.112993Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::London::6
2023-01-26T10:21:34.112995Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.112997Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.112999Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.113697Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.113702Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16158591,
    events_root: None,
}
2023-01-26T10:21:34.113724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-26T10:21:34.113727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::London::7
2023-01-26T10:21:34.113729Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.113731Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.113733Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.114372Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.114377Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14480929,
    events_root: None,
}
2023-01-26T10:21:34.114396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-26T10:21:34.114400Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::London::8
2023-01-26T10:21:34.114401Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.114404Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.114405Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [199, 196, 71, 128, 83, 134, 141, 49, 16, 230, 231, 136, 147, 236, 247, 184, 73, 128, 202, 103, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([221, 202, 25, 212, 34, 2, 50, 123, 41, 75, 186, 155, 123, 166, 127, 9, 228, 237, 116, 209]) }
2023-01-26T10:21:34.115694Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.115699Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 31623963,
    events_root: None,
}
2023-01-26T10:21:34.115732Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-26T10:21:34.115735Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::London::9
2023-01-26T10:21:34.115737Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.115739Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.115742Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.116775Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.116780Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21608662,
    events_root: None,
}
2023-01-26T10:21:34.116806Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T10:21:34.116809Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Merge::0
2023-01-26T10:21:34.116811Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.116814Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.116815Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.117555Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.117560Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17306975,
    events_root: None,
}
2023-01-26T10:21:34.117582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T10:21:34.117585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Merge::1
2023-01-26T10:21:34.117587Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.117590Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.117591Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.118264Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.118270Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10568639,
    events_root: None,
}
2023-01-26T10:21:34.118292Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-26T10:21:34.118296Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Merge::2
2023-01-26T10:21:34.118298Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.118301Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.118303Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.118934Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.118939Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:34.118957Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-26T10:21:34.118961Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Merge::3
2023-01-26T10:21:34.118962Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.118965Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.118966Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.119535Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.119540Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:34.119558Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-26T10:21:34.119561Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Merge::4
2023-01-26T10:21:34.119563Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.119566Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.119568Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.120138Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.120143Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9041949,
    events_root: None,
}
2023-01-26T10:21:34.120160Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-26T10:21:34.120163Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Merge::5
2023-01-26T10:21:34.120165Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.120167Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.120169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.120752Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.120757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10571486,
    events_root: None,
}
2023-01-26T10:21:34.120775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-26T10:21:34.120778Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Merge::6
2023-01-26T10:21:34.120780Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.120782Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.120784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.121473Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.121478Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16158591,
    events_root: None,
}
2023-01-26T10:21:34.121499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-26T10:21:34.121502Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Merge::7
2023-01-26T10:21:34.121504Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.121506Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.121508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.122149Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.122154Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14480929,
    events_root: None,
}
2023-01-26T10:21:34.122173Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-26T10:21:34.122176Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Merge::8
2023-01-26T10:21:34.122178Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.122180Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.122182Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [61, 73, 142, 47, 208, 143, 199, 114, 131, 191, 48, 183, 26, 228, 67, 8, 223, 40, 157, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([144, 116, 102, 151, 109, 193, 228, 195, 140, 185, 216, 122, 95, 12, 114, 35, 109, 70, 64, 123]) }
2023-01-26T10:21:34.123566Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.123571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 31992141,
    events_root: None,
}
2023-01-26T10:21:34.123603Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-26T10:21:34.123606Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodehashEmpty"::Merge::9
2023-01-26T10:21:34.123608Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stExtCodeHash/extcodehashEmpty.json"
2023-01-26T10:21:34.123611Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-26T10:21:34.123612Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T10:21:34.124563Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodehashEmpty"
2023-01-26T10:21:34.124568Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21608662,
    events_root: None,
}
2023-01-26T10:21:34.126560Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:640.210418ms
```