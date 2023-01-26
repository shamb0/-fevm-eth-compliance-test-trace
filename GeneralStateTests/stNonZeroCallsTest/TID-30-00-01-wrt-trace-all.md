> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stNonZeroCallsTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stNonZeroCallsTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-case failed

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-30-05 | NonZeroValue_CALLCODE |


> Execution Trace

```
2023-01-26T02:37:28.545666Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL.json", Total Files :: 1
2023-01-26T02:37:28.575642Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:28.575838Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:28.575842Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:28.575895Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:28.575966Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:28.575969Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL"::Istanbul::0
2023-01-26T02:37:28.575972Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL.json"
2023-01-26T02:37:28.575976Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:28.575977Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:28.897990Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL"
2023-01-26T02:37:28.898007Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4658081,
    events_root: None,
}
2023-01-26T02:37:28.898018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:28.898024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL"::Berlin::0
2023-01-26T02:37:28.898026Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL.json"
2023-01-26T02:37:28.898029Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:28.898030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:28.898192Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL"
2023-01-26T02:37:28.898196Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784886,
    events_root: None,
}
2023-01-26T02:37:28.898202Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:28.898205Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL"::London::0
2023-01-26T02:37:28.898206Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL.json"
2023-01-26T02:37:28.898209Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:28.898211Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:28.898331Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL"
2023-01-26T02:37:28.898335Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2361015,
    events_root: None,
}
2023-01-26T02:37:28.898340Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:28.898342Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL"::Merge::0
2023-01-26T02:37:28.898344Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL.json"
2023-01-26T02:37:28.898346Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:28.898347Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:28.898464Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL"
2023-01-26T02:37:28.898468Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2361015,
    events_root: None,
}
2023-01-26T02:37:28.899876Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:322.836148ms
2023-01-26T02:37:29.156370Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE.json", Total Files :: 1
2023-01-26T02:37:29.185032Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:29.185228Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:29.185232Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:29.185286Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:29.185360Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:29.185364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE"::Istanbul::0
2023-01-26T02:37:29.185367Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE.json"
2023-01-26T02:37:29.185371Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:29.185374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:29.542629Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE"
2023-01-26T02:37:29.542646Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:29.542652Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:29.542666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:29.542672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE"::Berlin::0
2023-01-26T02:37:29.542676Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE.json"
2023-01-26T02:37:29.542679Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:29.542680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:29.542787Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE"
2023-01-26T02:37:29.542791Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:29.542794Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:29.542803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:29.542805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE"::London::0
2023-01-26T02:37:29.542807Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE.json"
2023-01-26T02:37:29.542810Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:29.542811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:29.542895Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE"
2023-01-26T02:37:29.542899Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:29.542902Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:29.542911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:29.542913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE"::Merge::0
2023-01-26T02:37:29.542915Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE.json"
2023-01-26T02:37:29.542917Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:29.542919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:29.543001Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE"
2023-01-26T02:37:29.543005Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:29.543008Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:29.544526Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.988615ms
2023-01-26T02:37:29.807425Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToEmpty.json", Total Files :: 1
2023-01-26T02:37:29.836382Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:29.836574Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:29.836578Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:29.836631Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:29.836633Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:29.836690Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:29.836761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:29.836764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToEmpty"::Istanbul::0
2023-01-26T02:37:29.836767Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToEmpty.json"
2023-01-26T02:37:29.836771Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:29.836773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:30.174060Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToEmpty"
2023-01-26T02:37:30.174076Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:30.174082Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:30.174096Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:30.174102Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToEmpty"::Berlin::0
2023-01-26T02:37:30.174104Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToEmpty.json"
2023-01-26T02:37:30.174107Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:30.174108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:30.174232Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToEmpty"
2023-01-26T02:37:30.174236Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:30.174239Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:30.174248Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:30.174250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToEmpty"::London::0
2023-01-26T02:37:30.174252Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToEmpty.json"
2023-01-26T02:37:30.174254Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:30.174257Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:30.174365Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToEmpty"
2023-01-26T02:37:30.174370Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:30.174372Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:30.174381Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:30.174383Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToEmpty"::Merge::0
2023-01-26T02:37:30.174385Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToEmpty.json"
2023-01-26T02:37:30.174388Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:30.174389Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:30.174477Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToEmpty"
2023-01-26T02:37:30.174480Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:30.174483Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:30.175980Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:338.115645ms
2023-01-26T02:37:30.431031Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToNonNonZeroBalance.json", Total Files :: 1
2023-01-26T02:37:30.459483Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:30.459669Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:30.459673Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:30.459724Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:30.459726Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:30.459782Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:30.459851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:30.459854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToNonNonZeroBalance"::Istanbul::0
2023-01-26T02:37:30.459857Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToNonNonZeroBalance.json"
2023-01-26T02:37:30.459861Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:30.459862Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:30.821193Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToNonNonZeroBalance"
2023-01-26T02:37:30.821210Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:30.821217Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:30.821232Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:30.821241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToNonNonZeroBalance"::Berlin::0
2023-01-26T02:37:30.821244Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToNonNonZeroBalance.json"
2023-01-26T02:37:30.821249Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:30.821251Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:30.821384Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToNonNonZeroBalance"
2023-01-26T02:37:30.821390Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:30.821394Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:30.821406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:30.821408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToNonNonZeroBalance"::London::0
2023-01-26T02:37:30.821411Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToNonNonZeroBalance.json"
2023-01-26T02:37:30.821415Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:30.821416Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:30.821519Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToNonNonZeroBalance"
2023-01-26T02:37:30.821523Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:30.821526Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:30.821536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:30.821538Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToNonNonZeroBalance"::Merge::0
2023-01-26T02:37:30.821541Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToNonNonZeroBalance.json"
2023-01-26T02:37:30.821544Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:30.821546Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:30.821639Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToNonNonZeroBalance"
2023-01-26T02:37:30.821643Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:30.821646Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:30.823382Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.178362ms
2023-01-26T02:37:31.078597Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToOneStorageKey.json", Total Files :: 1
2023-01-26T02:37:31.108205Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:31.108406Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:31.108410Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:31.108465Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:31.108467Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:31.108527Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:31.108600Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:31.108603Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToOneStorageKey"::Istanbul::0
2023-01-26T02:37:31.108606Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToOneStorageKey.json"
2023-01-26T02:37:31.108610Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:31.108611Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:31.446295Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToOneStorageKey"
2023-01-26T02:37:31.446312Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:31.446318Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:31.446331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:31.446337Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToOneStorageKey"::Berlin::0
2023-01-26T02:37:31.446339Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToOneStorageKey.json"
2023-01-26T02:37:31.446342Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:31.446344Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:31.446443Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToOneStorageKey"
2023-01-26T02:37:31.446447Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:31.446450Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:31.446458Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:31.446460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToOneStorageKey"::London::0
2023-01-26T02:37:31.446463Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToOneStorageKey.json"
2023-01-26T02:37:31.446465Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:31.446467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:31.446558Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToOneStorageKey"
2023-01-26T02:37:31.446563Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:31.446566Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:31.446576Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:31.446579Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALLCODE_ToOneStorageKey"::Merge::0
2023-01-26T02:37:31.446582Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALLCODE_ToOneStorageKey.json"
2023-01-26T02:37:31.446585Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:31.446587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:31.446696Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALLCODE_ToOneStorageKey"
2023-01-26T02:37:31.446702Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1562107,
    events_root: None,
}
2023-01-26T02:37:31.446704Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T02:37:31.448208Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:338.514014ms
2023-01-26T02:37:31.704364Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToEmpty.json", Total Files :: 1
2023-01-26T02:37:31.736476Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:31.736669Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:31.736672Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:31.736724Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:31.736726Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:31.736784Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:31.736865Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:31.736869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToEmpty"::Istanbul::0
2023-01-26T02:37:31.736872Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToEmpty.json"
2023-01-26T02:37:31.736875Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:31.736877Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:32.065321Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToEmpty"
2023-01-26T02:37:32.065339Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2742927,
    events_root: None,
}
2023-01-26T02:37:32.065351Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:32.065357Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToEmpty"::Berlin::0
2023-01-26T02:37:32.065359Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToEmpty.json"
2023-01-26T02:37:32.065362Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:32.065363Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:32.065540Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToEmpty"
2023-01-26T02:37:32.065545Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2760287,
    events_root: None,
}
2023-01-26T02:37:32.065551Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:32.065554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToEmpty"::London::0
2023-01-26T02:37:32.065557Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToEmpty.json"
2023-01-26T02:37:32.065560Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:32.065561Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:32.065679Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToEmpty"
2023-01-26T02:37:32.065684Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1841308,
    events_root: None,
}
2023-01-26T02:37:32.065689Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:32.065691Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToEmpty"::Merge::0
2023-01-26T02:37:32.065693Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToEmpty.json"
2023-01-26T02:37:32.065697Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:32.065698Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:32.065814Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToEmpty"
2023-01-26T02:37:32.065818Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1841308,
    events_root: None,
}
2023-01-26T02:37:32.067152Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:329.35276ms
2023-01-26T02:37:32.327943Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToNonNonZeroBalance.json", Total Files :: 1
2023-01-26T02:37:32.356667Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:32.356880Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:32.356885Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:32.356941Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:32.356944Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:32.357005Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:32.357078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:32.357083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToNonNonZeroBalance"::Istanbul::0
2023-01-26T02:37:32.357086Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:32.357091Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:32.357093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:32.686961Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToNonNonZeroBalance"
2023-01-26T02:37:32.686978Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2689373,
    events_root: None,
}
2023-01-26T02:37:32.686991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:32.686998Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToNonNonZeroBalance"::Berlin::0
2023-01-26T02:37:32.687001Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:32.687005Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:32.687007Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:32.687151Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToNonNonZeroBalance"
2023-01-26T02:37:32.687156Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2706734,
    events_root: None,
}
2023-01-26T02:37:32.687165Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:32.687169Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToNonNonZeroBalance"::London::0
2023-01-26T02:37:32.687172Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:32.687176Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:32.687177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:32.687290Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToNonNonZeroBalance"
2023-01-26T02:37:32.687295Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1787755,
    events_root: None,
}
2023-01-26T02:37:32.687302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:32.687305Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToNonNonZeroBalance"::Merge::0
2023-01-26T02:37:32.687308Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:32.687312Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:32.687314Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:32.687426Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToNonNonZeroBalance"
2023-01-26T02:37:32.687430Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1787755,
    events_root: None,
}
2023-01-26T02:37:32.688964Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:330.775708ms
2023-01-26T02:37:32.956668Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToOneStorageKey.json", Total Files :: 1
2023-01-26T02:37:32.985707Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:32.985927Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:32.985932Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:32.985991Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:32.985993Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:32.986053Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:32.986129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:32.986132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToOneStorageKey"::Istanbul::0
2023-01-26T02:37:32.986135Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToOneStorageKey.json"
2023-01-26T02:37:32.986138Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:32.986140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:33.320951Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToOneStorageKey"
2023-01-26T02:37:33.320968Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2742927,
    events_root: None,
}
2023-01-26T02:37:33.320981Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:33.320991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToOneStorageKey"::Berlin::0
2023-01-26T02:37:33.320994Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToOneStorageKey.json"
2023-01-26T02:37:33.320999Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:33.321001Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:33.321185Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToOneStorageKey"
2023-01-26T02:37:33.321190Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2760287,
    events_root: None,
}
2023-01-26T02:37:33.321197Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:33.321200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToOneStorageKey"::London::0
2023-01-26T02:37:33.321203Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToOneStorageKey.json"
2023-01-26T02:37:33.321206Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:33.321207Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:33.321347Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToOneStorageKey"
2023-01-26T02:37:33.321351Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1841308,
    events_root: None,
}
2023-01-26T02:37:33.321357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:33.321360Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_CALL_ToOneStorageKey"::Merge::0
2023-01-26T02:37:33.321362Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_CALL_ToOneStorageKey.json"
2023-01-26T02:37:33.321365Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:33.321366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:33.321486Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_CALL_ToOneStorageKey"
2023-01-26T02:37:33.321490Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1841308,
    events_root: None,
}
2023-01-26T02:37:33.323142Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:335.793945ms
2023-01-26T02:37:33.591748Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL.json", Total Files :: 1
2023-01-26T02:37:33.620376Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:33.620572Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:33.620576Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:33.620630Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:33.620701Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:33.620705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL"::Istanbul::0
2023-01-26T02:37:33.620707Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL.json"
2023-01-26T02:37:33.620711Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:33.620712Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:34.009482Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL"
2023-01-26T02:37:34.009496Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3169788,
    events_root: None,
}
2023-01-26T02:37:34.009506Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:34.009512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL"::Berlin::0
2023-01-26T02:37:34.009514Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL.json"
2023-01-26T02:37:34.009517Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:34.009518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:34.009701Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL"
2023-01-26T02:37:34.009706Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3464537,
    events_root: None,
}
2023-01-26T02:37:34.009711Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:34.009713Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL"::London::0
2023-01-26T02:37:34.009717Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL.json"
2023-01-26T02:37:34.009719Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:34.009721Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:34.009861Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL"
2023-01-26T02:37:34.009865Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3464548,
    events_root: None,
}
2023-01-26T02:37:34.009871Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:34.009874Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL"::Merge::0
2023-01-26T02:37:34.009876Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL.json"
2023-01-26T02:37:34.009878Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:34.009880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:34.010005Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL"
2023-01-26T02:37:34.010010Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2040677,
    events_root: None,
}
2023-01-26T02:37:34.011537Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:389.643527ms
2023-01-26T02:37:34.270849Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToEmpty.json", Total Files :: 1
2023-01-26T02:37:34.299917Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:34.300111Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:34.300114Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:34.300165Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:34.300167Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:34.300224Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:34.300295Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:34.300298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToEmpty"::Istanbul::0
2023-01-26T02:37:34.300301Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToEmpty.json"
2023-01-26T02:37:34.300304Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:34.300306Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:34.661733Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToEmpty"
2023-01-26T02:37:34.661749Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3623213,
    events_root: None,
}
2023-01-26T02:37:34.661763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:34.661772Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToEmpty"::Berlin::0
2023-01-26T02:37:34.661776Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToEmpty.json"
2023-01-26T02:37:34.661780Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:34.661782Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:34.662071Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToEmpty"
2023-01-26T02:37:34.662076Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3642294,
    events_root: None,
}
2023-01-26T02:37:34.662084Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:34.662087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToEmpty"::London::0
2023-01-26T02:37:34.662089Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToEmpty.json"
2023-01-26T02:37:34.662091Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:34.662093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:34.662280Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToEmpty"
2023-01-26T02:37:34.662284Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723315,
    events_root: None,
}
2023-01-26T02:37:34.662291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:34.662294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToEmpty"::Merge::0
2023-01-26T02:37:34.662296Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToEmpty.json"
2023-01-26T02:37:34.662299Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:34.662301Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:34.662525Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToEmpty"
2023-01-26T02:37:34.662530Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723315,
    events_root: None,
}
2023-01-26T02:37:34.664249Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.625938ms
2023-01-26T02:37:34.932491Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToNonNonZeroBalance.json", Total Files :: 1
2023-01-26T02:37:34.961721Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:34.961925Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:34.961929Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:34.961981Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:34.961983Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:34.962042Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:34.962114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:34.962117Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToNonNonZeroBalance"::Istanbul::0
2023-01-26T02:37:34.962120Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:34.962123Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:34.962125Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:35.286062Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToNonNonZeroBalance"
2023-01-26T02:37:35.286075Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3623213,
    events_root: None,
}
2023-01-26T02:37:35.286087Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:35.286094Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToNonNonZeroBalance"::Berlin::0
2023-01-26T02:37:35.286096Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:35.286099Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:35.286101Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:35.286306Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToNonNonZeroBalance"
2023-01-26T02:37:35.286311Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3642294,
    events_root: None,
}
2023-01-26T02:37:35.286318Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:35.286321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToNonNonZeroBalance"::London::0
2023-01-26T02:37:35.286324Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:35.286327Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:35.286328Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:35.286503Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToNonNonZeroBalance"
2023-01-26T02:37:35.286508Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723315,
    events_root: None,
}
2023-01-26T02:37:35.286514Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:35.286517Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToNonNonZeroBalance"::Merge::0
2023-01-26T02:37:35.286519Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:35.286522Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:35.286523Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:35.286692Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToNonNonZeroBalance"
2023-01-26T02:37:35.286697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723315,
    events_root: None,
}
2023-01-26T02:37:35.288253Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:324.987565ms
2023-01-26T02:37:35.549517Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToOneStorageKey.json", Total Files :: 1
2023-01-26T02:37:35.578371Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:35.578567Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:35.578571Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:35.578625Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:35.578627Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:35.578686Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:35.578759Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:35.578762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToOneStorageKey"::Istanbul::0
2023-01-26T02:37:35.578765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToOneStorageKey.json"
2023-01-26T02:37:35.578769Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:35.578770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:35.943819Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToOneStorageKey"
2023-01-26T02:37:35.943869Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3623213,
    events_root: None,
}
2023-01-26T02:37:35.943890Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:35.943904Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToOneStorageKey"::Berlin::0
2023-01-26T02:37:35.943912Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToOneStorageKey.json"
2023-01-26T02:37:35.943920Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:35.943927Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:35.944189Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToOneStorageKey"
2023-01-26T02:37:35.944205Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3642294,
    events_root: None,
}
2023-01-26T02:37:35.944222Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:35.944230Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToOneStorageKey"::London::0
2023-01-26T02:37:35.944237Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToOneStorageKey.json"
2023-01-26T02:37:35.944246Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:35.944252Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:35.944485Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToOneStorageKey"
2023-01-26T02:37:35.944500Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723315,
    events_root: None,
}
2023-01-26T02:37:35.944509Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:35.944513Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_DELEGATECALL_ToOneStorageKey"::Merge::0
2023-01-26T02:37:35.944515Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_DELEGATECALL_ToOneStorageKey.json"
2023-01-26T02:37:35.944527Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:35.944533Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:35.944765Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_DELEGATECALL_ToOneStorageKey"
2023-01-26T02:37:35.944781Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723315,
    events_root: None,
}
2023-01-26T02:37:35.946703Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.430169ms
2023-01-26T02:37:36.214853Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_SUICIDE.json", Total Files :: 1
2023-01-26T02:37:36.243067Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:36.243257Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:36.243260Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:36.243311Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:36.243380Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:36.243383Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE"', chain_spec: 'Istanbul', data_index: 0
2023-01-26T02:37:36.243386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:36.243388Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE"', chain_spec: 'Berlin', data_index: 0
2023-01-26T02:37:36.243390Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:36.243392Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE"', chain_spec: 'London', data_index: 0
2023-01-26T02:37:36.243394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:36.243395Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE"', chain_spec: 'Merge', data_index: 0
2023-01-26T02:37:36.244027Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:333.954s
2023-01-26T02:37:36.497299Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_SUICIDE_ToEmpty.json", Total Files :: 1
2023-01-26T02:37:36.527219Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:36.527409Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:36.527413Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:36.527464Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:36.527466Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:36.527523Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:36.527592Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:36.527596Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToEmpty"', chain_spec: 'Istanbul', data_index: 0
2023-01-26T02:37:36.527598Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:36.527600Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToEmpty"', chain_spec: 'Berlin', data_index: 0
2023-01-26T02:37:36.527602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:36.527603Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToEmpty"', chain_spec: 'London', data_index: 0
2023-01-26T02:37:36.527605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:36.527607Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToEmpty"', chain_spec: 'Merge', data_index: 0
2023-01-26T02:37:36.528264Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:394.22s
2023-01-26T02:37:36.787117Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_SUICIDE_ToNonNonZeroBalance.json", Total Files :: 1
2023-01-26T02:37:36.816031Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:36.816227Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:36.816231Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:36.816286Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:36.816288Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:36.816348Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:36.816419Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:36.816424Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToNonNonZeroBalance"', chain_spec: 'Istanbul', data_index: 0
2023-01-26T02:37:36.816427Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:36.816429Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToNonNonZeroBalance"', chain_spec: 'Berlin', data_index: 0
2023-01-26T02:37:36.816431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:36.816433Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToNonNonZeroBalance"', chain_spec: 'London', data_index: 0
2023-01-26T02:37:36.816435Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:36.816436Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToNonNonZeroBalance"', chain_spec: 'Merge', data_index: 0
2023-01-26T02:37:36.817125Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:411.824s
2023-01-26T02:37:37.090052Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_SUICIDE_ToOneStorageKey.json", Total Files :: 1
2023-01-26T02:37:37.118501Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:37.118691Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:37.118695Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:37.118747Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:37.118749Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T02:37:37.118807Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:37.118878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:37.118882Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToOneStorageKey"', chain_spec: 'Istanbul', data_index: 0
2023-01-26T02:37:37.118885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:37.118887Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToOneStorageKey"', chain_spec: 'Berlin', data_index: 0
2023-01-26T02:37:37.118889Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:37.118890Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToOneStorageKey"', chain_spec: 'London', data_index: 0
2023-01-26T02:37:37.118892Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:37.118894Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_SUICIDE_ToOneStorageKey"', chain_spec: 'Merge', data_index: 0
2023-01-26T02:37:37.119612Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:399.851s
2023-01-26T02:37:37.373198Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL.json", Total Files :: 1
2023-01-26T02:37:37.403033Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:37.403225Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:37.403296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:37.403300Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_TransactionCALL"', chain_spec: 'Istanbul', data_index: 0
2023-01-26T02:37:37.403303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:37.403305Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_TransactionCALL"', chain_spec: 'Berlin', data_index: 0
2023-01-26T02:37:37.403308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:37.403310Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_TransactionCALL"', chain_spec: 'London', data_index: 0
2023-01-26T02:37:37.403312Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:37.403313Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_TransactionCALL"', chain_spec: 'Merge', data_index: 0
2023-01-26T02:37:37.403925Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:287.515s
2023-01-26T02:37:37.656973Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToEmpty.json", Total Files :: 1
2023-01-26T02:37:37.694737Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:37.694947Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:37.694951Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:37.695003Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:37.695079Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:37.695083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToEmpty"::Istanbul::0
2023-01-26T02:37:37.695086Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToEmpty.json"
2023-01-26T02:37:37.695090Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:37.695091Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:38.062309Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToEmpty"
2023-01-26T02:37:38.062326Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:38.062339Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:38.062350Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToEmpty"::Berlin::0
2023-01-26T02:37:38.062353Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToEmpty.json"
2023-01-26T02:37:38.062358Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:38.062360Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:38.062510Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToEmpty"
2023-01-26T02:37:38.062516Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:38.062521Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:38.062524Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToEmpty"::London::0
2023-01-26T02:37:38.062525Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToEmpty.json"
2023-01-26T02:37:38.062528Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:38.062529Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:38.062611Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToEmpty"
2023-01-26T02:37:38.062615Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:38.062620Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:38.062622Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToEmpty"::Merge::0
2023-01-26T02:37:38.062625Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToEmpty.json"
2023-01-26T02:37:38.062628Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:38.062629Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:38.062701Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToEmpty"
2023-01-26T02:37:38.062705Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:38.064391Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.978458ms
2023-01-26T02:37:38.336133Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToNonNonZeroBalance.json", Total Files :: 1
2023-01-26T02:37:38.365830Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:38.366018Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:38.366022Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:38.366074Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:38.366143Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:38.366146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToNonNonZeroBalance"::Istanbul::0
2023-01-26T02:37:38.366149Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:38.366153Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:38.366154Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:38.694485Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToNonNonZeroBalance"
2023-01-26T02:37:38.694501Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:38.694513Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:38.694521Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToNonNonZeroBalance"::Berlin::0
2023-01-26T02:37:38.694524Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:38.694529Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:38.694530Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:38.694648Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToNonNonZeroBalance"
2023-01-26T02:37:38.694652Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:38.694658Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:38.694662Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToNonNonZeroBalance"::London::0
2023-01-26T02:37:38.694665Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:38.694669Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:38.694671Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:38.694750Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToNonNonZeroBalance"
2023-01-26T02:37:38.694755Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:38.694761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:38.694764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToNonNonZeroBalance"::Merge::0
2023-01-26T02:37:38.694767Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToNonNonZeroBalance.json"
2023-01-26T02:37:38.694771Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:38.694773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:38.694851Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToNonNonZeroBalance"
2023-01-26T02:37:38.694856Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:38.696505Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:329.036846ms
2023-01-26T02:37:38.968596Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToOneStorageKey.json", Total Files :: 1
2023-01-26T02:37:38.997551Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:38.997746Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:38.997750Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:38.997804Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:38.997875Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:38.997878Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToOneStorageKey"::Istanbul::0
2023-01-26T02:37:38.997881Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToOneStorageKey.json"
2023-01-26T02:37:38.997885Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:38.997886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:39.344480Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToOneStorageKey"
2023-01-26T02:37:39.344495Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:39.344505Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:39.344512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToOneStorageKey"::Berlin::0
2023-01-26T02:37:39.344514Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToOneStorageKey.json"
2023-01-26T02:37:39.344517Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:39.344519Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:39.344629Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToOneStorageKey"
2023-01-26T02:37:39.344633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:39.344638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:39.344641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToOneStorageKey"::London::0
2023-01-26T02:37:39.344643Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToOneStorageKey.json"
2023-01-26T02:37:39.344646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:39.344647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:39.344721Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToOneStorageKey"
2023-01-26T02:37:39.344725Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:39.344729Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:39.344731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALL_ToOneStorageKey"::Merge::0
2023-01-26T02:37:39.344733Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALL_ToOneStorageKey.json"
2023-01-26T02:37:39.344736Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T02:37:39.344737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:39.344819Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALL_ToOneStorageKey"
2023-01-26T02:37:39.344823Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1493151,
    events_root: None,
}
2023-01-26T02:37:39.346354Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:347.281673ms
2023-01-26T02:37:39.605421Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData.json", Total Files :: 1
2023-01-26T02:37:39.634243Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:39.634442Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:39.634519Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:39.634524Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_TransactionCALLwithData"', chain_spec: 'Istanbul', data_index: 0
2023-01-26T02:37:39.634528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:39.634531Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_TransactionCALLwithData"', chain_spec: 'Berlin', data_index: 0
2023-01-26T02:37:39.634534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:39.634536Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_TransactionCALLwithData"', chain_spec: 'London', data_index: 0
2023-01-26T02:37:39.634539Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:39.634542Z  WARN evm_eth_compliance::statetest::runner: Skipping Post Test test_name: '"NonZeroValue_TransactionCALLwithData"', chain_spec: 'Merge', data_index: 0
2023-01-26T02:37:39.635274Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:306.051s
2023-01-26T02:37:39.891161Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToEmpty.json", Total Files :: 1
2023-01-26T02:37:39.921500Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:39.921692Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:39.921695Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:39.921747Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:39.921817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:39.921820Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToEmpty"::Istanbul::0
2023-01-26T02:37:39.921823Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToEmpty.json"
2023-01-26T02:37:39.921827Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:39.921828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:40.329087Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToEmpty"
2023-01-26T02:37:40.329103Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:40.329113Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:40.329120Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToEmpty"::Berlin::0
2023-01-26T02:37:40.329122Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToEmpty.json"
2023-01-26T02:37:40.329125Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:40.329127Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:40.329236Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToEmpty"
2023-01-26T02:37:40.329240Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:40.329244Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:40.329247Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToEmpty"::London::0
2023-01-26T02:37:40.329250Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToEmpty.json"
2023-01-26T02:37:40.329253Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:40.329255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:40.329327Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToEmpty"
2023-01-26T02:37:40.329331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:40.329335Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:40.329338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToEmpty"::Merge::0
2023-01-26T02:37:40.329340Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToEmpty.json"
2023-01-26T02:37:40.329343Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:40.329344Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:40.329415Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToEmpty"
2023-01-26T02:37:40.329419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:40.331016Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:407.928599ms
2023-01-26T02:37:40.604554Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance.json", Total Files :: 1
2023-01-26T02:37:40.634478Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:40.634669Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:40.634673Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:40.634725Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:40.634795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:40.634799Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance"::Istanbul::0
2023-01-26T02:37:40.634803Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance.json"
2023-01-26T02:37:40.634807Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:40.634808Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:40.969601Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance"
2023-01-26T02:37:40.969615Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:40.969627Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:40.969635Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance"::Berlin::0
2023-01-26T02:37:40.969638Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance.json"
2023-01-26T02:37:40.969642Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:40.969644Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:40.969755Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance"
2023-01-26T02:37:40.969760Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:40.969766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:40.969769Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance"::London::0
2023-01-26T02:37:40.969773Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance.json"
2023-01-26T02:37:40.969777Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:40.969779Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:40.969858Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance"
2023-01-26T02:37:40.969863Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:40.969868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:40.969872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance"::Merge::0
2023-01-26T02:37:40.969875Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance.json"
2023-01-26T02:37:40.969879Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:40.969881Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:40.969959Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToNonNonZeroBalance"
2023-01-26T02:37:40.969964Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:40.971463Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:335.496739ms
2023-01-26T02:37:41.243575Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToOneStorageKey.json", Total Files :: 1
2023-01-26T02:37:41.272039Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T02:37:41.272230Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:41.272234Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T02:37:41.272286Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T02:37:41.272355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T02:37:41.272358Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToOneStorageKey"::Istanbul::0
2023-01-26T02:37:41.272362Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToOneStorageKey.json"
2023-01-26T02:37:41.272365Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:41.272366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:41.613204Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToOneStorageKey"
2023-01-26T02:37:41.613219Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:41.613231Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T02:37:41.613239Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToOneStorageKey"::Berlin::0
2023-01-26T02:37:41.613241Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToOneStorageKey.json"
2023-01-26T02:37:41.613244Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:41.613246Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:41.613354Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToOneStorageKey"
2023-01-26T02:37:41.613359Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:41.613363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T02:37:41.613365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToOneStorageKey"::London::0
2023-01-26T02:37:41.613367Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToOneStorageKey.json"
2023-01-26T02:37:41.613370Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:41.613373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:41.613446Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToOneStorageKey"
2023-01-26T02:37:41.613450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:41.613454Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T02:37:41.613457Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NonZeroValue_TransactionCALLwithData_ToOneStorageKey"::Merge::0
2023-01-26T02:37:41.613460Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stNonZeroCallsTest/NonZeroValue_TransactionCALLwithData_ToOneStorageKey.json"
2023-01-26T02:37:41.613462Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-26T02:37:41.613464Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T02:37:41.613535Z  INFO evm_eth_compliance::statetest::runner: UC : "NonZeroValue_TransactionCALLwithData_ToOneStorageKey"
2023-01-26T02:37:41.613539Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1494231,
    events_root: None,
}
2023-01-26T02:37:41.615110Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:341.50978ms
```
