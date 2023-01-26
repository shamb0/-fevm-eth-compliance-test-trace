> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallDelegateCodesHomestead

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead \
	cargo run --release \
	-- \
	statetest
```

> For Review

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-08-01 | callcallcallcode_001 |
| TID-08-02 | callcallcallcode_001_OOGE |
| TID-08-03 | callcallcallcode_001_OOGMAfter |
| TID-08-04 | callcallcallcode_001_OOGMBefore |
| TID-08-05 | callcallcallcode_001_SuicideEnd |
| TID-08-06 | callcallcallcode_001_SuicideMiddle |
| TID-08-07 | callcallcallcode_ABCB_RECURSIVE |
| TID-08-08 | callcallcode_01 |
| TID-08-09 | callcallcode_01_OOGE |
| TID-08-10 | callcallcode_01_SuicideEnd |
| TID-08-11 | callcallcodecall_010 |
| TID-08-12 | callcallcodecall_010_OOGE |
| TID-08-13 | callcallcodecall_010_OOGMAfter |
| TID-08-14 | callcallcodecall_010_OOGMBefore |
| TID-08-15 | callcallcodecall_010_SuicideEnd |
| TID-08-16 | callcallcodecall_010_SuicideMiddle |
| TID-08-17 | callcallcodecall_ABCB_RECURSIVE |
| TID-08-18 | callcallcodecallcode_011 |
| TID-08-19 | callcallcodecallcode_011_OOGE |
| TID-08-20 | callcallcodecallcode_011_OOGMAfter |
| TID-08-21 | callcallcodecallcode_011_OOGMBefore |
| TID-08-22 | callcallcodecallcode_011_SuicideEnd |
| TID-08-23 | callcallcodecallcode_011_SuicideMiddle |
| TID-08-24 | callcallcodecallcode_ABCB_RECURSIVE |

> Execution Trace

```
2023-01-26T16:12:19.745206Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001.json", Total Files :: 1
2023-01-26T16:12:20.121889Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:20.122026Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:20.122029Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:20.122080Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:20.122082Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:20.122138Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:20.122140Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:20.122194Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:20.122196Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:20.122248Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:20.122319Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:20.122322Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::Istanbul::0
2023-01-26T16:12:20.122324Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001.json"
2023-01-26T16:12:20.122328Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:20.122329Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:20.491769Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-26T16:12:20.491784Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:20.491791Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:20.491806Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:20.491810Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::Berlin::0
2023-01-26T16:12:20.491812Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001.json"
2023-01-26T16:12:20.491814Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:20.491816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:20.491925Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-26T16:12:20.491930Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:20.491933Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:20.491943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:20.491946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::London::0
2023-01-26T16:12:20.491948Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001.json"
2023-01-26T16:12:20.491951Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:20.491952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:20.492044Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-26T16:12:20.492049Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:20.492052Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:20.492060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:20.492062Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::Merge::0
2023-01-26T16:12:20.492064Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001.json"
2023-01-26T16:12:20.492067Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:20.492068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:20.492156Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-26T16:12:20.492160Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:20.492162Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:20.493698Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:370.287173ms
2023-01-26T16:12:20.769205Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGE.json", Total Files :: 1
2023-01-26T16:12:20.800217Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:20.800361Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:20.800365Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:20.800423Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:20.800425Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:20.800489Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:20.800491Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:20.800550Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:20.800553Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:20.800609Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:20.800684Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:20.800687Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::Istanbul::0
2023-01-26T16:12:20.800691Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGE.json"
2023-01-26T16:12:20.800696Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:20.800698Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:21.182382Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-26T16:12:21.182399Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:21.182407Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:21.182422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:21.182426Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::Berlin::0
2023-01-26T16:12:21.182428Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGE.json"
2023-01-26T16:12:21.182431Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:21.182434Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:21.182561Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-26T16:12:21.182565Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:21.182568Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:21.182578Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:21.182580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::London::0
2023-01-26T16:12:21.182582Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGE.json"
2023-01-26T16:12:21.182585Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:21.182587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:21.182677Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-26T16:12:21.182681Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:21.182684Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:21.182692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:21.182694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::Merge::0
2023-01-26T16:12:21.182696Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGE.json"
2023-01-26T16:12:21.182699Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:21.182701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:21.182790Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-26T16:12:21.182794Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:21.182797Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:21.184538Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:382.592572ms
2023-01-26T16:12:21.471433Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGMAfter.json", Total Files :: 1
2023-01-26T16:12:21.500799Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:21.500944Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:21.500948Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:21.501003Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:21.501005Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:21.501065Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:21.501068Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:21.501125Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:21.501127Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:21.501182Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:21.501255Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:21.501258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::Istanbul::0
2023-01-26T16:12:21.501262Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGMAfter.json"
2023-01-26T16:12:21.501267Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:21.501269Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:21.852821Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-26T16:12:21.852838Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:21.852844Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:21.852858Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:21.852862Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::Berlin::0
2023-01-26T16:12:21.852864Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGMAfter.json"
2023-01-26T16:12:21.852867Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:21.852868Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:21.852982Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-26T16:12:21.852986Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:21.852989Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:21.853000Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:21.853002Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::London::0
2023-01-26T16:12:21.853003Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGMAfter.json"
2023-01-26T16:12:21.853006Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:21.853008Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:21.853094Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-26T16:12:21.853098Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:21.853101Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:21.853109Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:21.853111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::Merge::0
2023-01-26T16:12:21.853113Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGMAfter.json"
2023-01-26T16:12:21.853116Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:21.853119Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:21.853203Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-26T16:12:21.853207Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:21.853210Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:21.854802Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.42294ms
2023-01-26T16:12:22.132888Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGMBefore.json", Total Files :: 1
2023-01-26T16:12:22.176673Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:22.176866Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:22.176872Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:22.176947Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:22.176951Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:22.177037Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:22.177042Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:22.177122Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:22.177127Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:22.177201Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:22.177311Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:22.177316Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::Istanbul::0
2023-01-26T16:12:22.177321Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGMBefore.json"
2023-01-26T16:12:22.177327Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:22.177329Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:22.539416Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-26T16:12:22.539433Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:22.539440Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:22.539454Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:22.539457Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::Berlin::0
2023-01-26T16:12:22.539459Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGMBefore.json"
2023-01-26T16:12:22.539464Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:22.539465Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:22.539575Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-26T16:12:22.539579Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:22.539582Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:22.539592Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:22.539594Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::London::0
2023-01-26T16:12:22.539596Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGMBefore.json"
2023-01-26T16:12:22.539599Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:22.539600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:22.539690Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-26T16:12:22.539694Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:22.539697Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:22.539705Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:22.539708Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::Merge::0
2023-01-26T16:12:22.539710Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_OOGMBefore.json"
2023-01-26T16:12:22.539713Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:22.539715Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:22.539816Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-26T16:12:22.539821Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:22.539824Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:22.541425Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:363.168878ms
2023-01-26T16:12:22.807826Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_SuicideEnd.json", Total Files :: 1
2023-01-26T16:12:22.838387Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:22.838522Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:22.838525Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:22.838577Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:22.838579Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:22.838637Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:22.838639Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:22.838694Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:22.838696Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:22.838747Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:22.838818Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:22.838820Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Istanbul::0
2023-01-26T16:12:22.838823Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_SuicideEnd.json"
2023-01-26T16:12:22.838827Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:22.838828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:23.210220Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-26T16:12:23.210274Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:23.210291Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:23.210320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:23.210331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Berlin::0
2023-01-26T16:12:23.210338Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_SuicideEnd.json"
2023-01-26T16:12:23.210347Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:23.210354Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:23.210489Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-26T16:12:23.210504Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:23.210515Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:23.210535Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:23.210542Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::London::0
2023-01-26T16:12:23.210551Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_SuicideEnd.json"
2023-01-26T16:12:23.210558Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:23.210565Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:23.210693Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-26T16:12:23.210707Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:23.210718Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:23.210744Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:23.210753Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Merge::0
2023-01-26T16:12:23.210760Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_SuicideEnd.json"
2023-01-26T16:12:23.210768Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:23.210774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:23.210900Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-26T16:12:23.210915Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:23.210926Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:23.213187Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.566051ms
2023-01-26T16:12:23.491407Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:12:23.530890Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:23.531073Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:23.531078Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:23.531153Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:23.531156Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:23.531239Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:23.531242Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:23.531311Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:23.531315Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:23.531384Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:23.531482Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:23.531487Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Istanbul::0
2023-01-26T16:12:23.531490Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_SuicideMiddle.json"
2023-01-26T16:12:23.531496Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:23.531498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:23.889016Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-26T16:12:23.889034Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:23.889041Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:23.889054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:23.889058Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Berlin::0
2023-01-26T16:12:23.889060Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_SuicideMiddle.json"
2023-01-26T16:12:23.889064Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:23.889065Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:23.889174Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-26T16:12:23.889178Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:23.889181Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:23.889190Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:23.889192Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::London::0
2023-01-26T16:12:23.889196Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_SuicideMiddle.json"
2023-01-26T16:12:23.889199Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:23.889201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:23.889293Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-26T16:12:23.889297Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:23.889300Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:23.889308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:23.889310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Merge::0
2023-01-26T16:12:23.889312Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_001_SuicideMiddle.json"
2023-01-26T16:12:23.889317Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:23.889318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:23.889424Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-26T16:12:23.889429Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:23.889432Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:23.891143Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:358.558852ms
2023-01-26T16:12:24.174685Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:12:24.205082Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:24.205219Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:24.205223Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:24.205276Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:24.205278Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:24.205337Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:24.205340Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:24.205395Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:24.205476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:24.205480Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:12:24.205483Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:24.205487Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:24.205489Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:24.609786Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-26T16:12:24.609802Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:24.609808Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:24.609822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:24.609826Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:12:24.609828Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:24.609832Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:24.609833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:24.609952Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-26T16:12:24.609956Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:24.609959Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:24.609968Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:24.609970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::London::0
2023-01-26T16:12:24.609972Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:24.609975Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:24.609976Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:24.610065Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-26T16:12:24.610069Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:24.610072Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:24.610080Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:24.610082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:12:24.610083Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:24.610086Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:24.610088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:24.610184Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-26T16:12:24.610188Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:24.610191Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:24.611906Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:405.125171ms
2023-01-26T16:12:24.888084Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01.json", Total Files :: 1
2023-01-26T16:12:24.925181Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:24.925321Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:24.925324Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:24.925383Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:24.925386Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:24.925445Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:24.925447Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:24.925510Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:24.925584Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:24.925586Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::Istanbul::0
2023-01-26T16:12:24.925589Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01.json"
2023-01-26T16:12:24.925593Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:24.925594Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:25.282120Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-26T16:12:25.282137Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:25.282144Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:25.282158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:25.282161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::Berlin::0
2023-01-26T16:12:25.282163Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01.json"
2023-01-26T16:12:25.282168Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:25.282169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:25.282276Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-26T16:12:25.282280Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:25.282283Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:25.282291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:25.282293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::London::0
2023-01-26T16:12:25.282295Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01.json"
2023-01-26T16:12:25.282298Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:25.282299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:25.282391Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-26T16:12:25.282395Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:25.282398Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:25.282406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:25.282409Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::Merge::0
2023-01-26T16:12:25.282411Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01.json"
2023-01-26T16:12:25.282415Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:25.282417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:25.282533Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-26T16:12:25.282538Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:25.282542Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:25.284197Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.377745ms
2023-01-26T16:12:25.565615Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01_OOGE.json", Total Files :: 1
2023-01-26T16:12:25.595296Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:25.595448Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:25.595452Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:25.595507Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:25.595510Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:25.595571Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:25.595573Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:25.595629Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:25.595704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:25.595707Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::Istanbul::0
2023-01-26T16:12:25.595710Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01_OOGE.json"
2023-01-26T16:12:25.595713Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:25.595715Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:25.956811Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-26T16:12:25.956829Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:25.956835Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:25.956850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:25.956854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::Berlin::0
2023-01-26T16:12:25.956856Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01_OOGE.json"
2023-01-26T16:12:25.956859Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:25.956861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:25.956988Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-26T16:12:25.956993Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:25.956996Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:25.957005Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:25.957007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::London::0
2023-01-26T16:12:25.957008Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01_OOGE.json"
2023-01-26T16:12:25.957011Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:25.957012Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:25.957101Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-26T16:12:25.957105Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:25.957108Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:25.957117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:25.957118Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::Merge::0
2023-01-26T16:12:25.957120Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01_OOGE.json"
2023-01-26T16:12:25.957123Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:25.957124Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:25.957216Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-26T16:12:25.957220Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:25.957224Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:25.958842Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.944377ms
2023-01-26T16:12:26.249721Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01_SuicideEnd.json", Total Files :: 1
2023-01-26T16:12:26.281026Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:26.281165Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:26.281169Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:26.281223Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:26.281225Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:26.281286Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:26.281288Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:26.281345Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:26.281418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:26.281421Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Istanbul::0
2023-01-26T16:12:26.281424Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01_SuicideEnd.json"
2023-01-26T16:12:26.281427Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:26.281429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:26.644568Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-26T16:12:26.644585Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:26.644592Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:26.644606Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:26.644610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Berlin::0
2023-01-26T16:12:26.644613Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01_SuicideEnd.json"
2023-01-26T16:12:26.644616Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:26.644617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:26.644720Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-26T16:12:26.644724Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:26.644727Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:26.644737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:26.644739Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::London::0
2023-01-26T16:12:26.644741Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01_SuicideEnd.json"
2023-01-26T16:12:26.644744Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:26.644745Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:26.644833Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-26T16:12:26.644837Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:26.644840Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:26.644849Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:26.644851Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Merge::0
2023-01-26T16:12:26.644852Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcode_01_SuicideEnd.json"
2023-01-26T16:12:26.644856Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:26.644857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:26.644944Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-26T16:12:26.644949Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:26.644952Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:26.646712Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:363.939059ms
2023-01-26T16:12:26.919549Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010.json", Total Files :: 1
2023-01-26T16:12:26.969967Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:26.970106Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:26.970110Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:26.970164Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:26.970167Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:26.970227Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:26.970230Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:26.970287Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:26.970289Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:26.970344Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:26.970417Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:26.970421Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::Istanbul::0
2023-01-26T16:12:26.970424Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010.json"
2023-01-26T16:12:26.970427Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:26.970429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:27.328371Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-26T16:12:27.328385Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:27.328392Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:27.328406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:27.328411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::Berlin::0
2023-01-26T16:12:27.328415Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010.json"
2023-01-26T16:12:27.328418Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:27.328419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:27.328545Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-26T16:12:27.328550Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:27.328553Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:27.328564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:27.328567Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::London::0
2023-01-26T16:12:27.328569Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010.json"
2023-01-26T16:12:27.328572Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:27.328574Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:27.328694Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-26T16:12:27.328700Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:27.328704Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:27.328715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:27.328718Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::Merge::0
2023-01-26T16:12:27.328720Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010.json"
2023-01-26T16:12:27.328724Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:27.328726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:27.328847Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-26T16:12:27.328854Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:27.328857Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:27.330657Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:358.907286ms
2023-01-26T16:12:27.625251Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGE.json", Total Files :: 1
2023-01-26T16:12:27.666568Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:27.666760Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:27.666765Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:27.666827Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:27.666830Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:27.666914Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:27.666918Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:27.666999Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:27.667003Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:27.667060Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:27.667147Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:27.667150Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::Istanbul::0
2023-01-26T16:12:27.667153Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGE.json"
2023-01-26T16:12:27.667156Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:27.667158Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:28.067336Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-26T16:12:28.067352Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:28.067359Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:28.067372Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:28.067377Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::Berlin::0
2023-01-26T16:12:28.067379Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGE.json"
2023-01-26T16:12:28.067382Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:28.067385Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:28.067522Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-26T16:12:28.067527Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:28.067530Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:28.067540Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:28.067542Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::London::0
2023-01-26T16:12:28.067545Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGE.json"
2023-01-26T16:12:28.067548Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:28.067550Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:28.067648Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-26T16:12:28.067652Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:28.067656Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:28.067665Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:28.067667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::Merge::0
2023-01-26T16:12:28.067669Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGE.json"
2023-01-26T16:12:28.067671Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:28.067673Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:28.067762Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-26T16:12:28.067766Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:28.067769Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:28.069368Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:401.216648ms
2023-01-26T16:12:28.328293Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGMAfter.json", Total Files :: 1
2023-01-26T16:12:28.358830Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:28.358982Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:28.358987Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:28.359042Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:28.359044Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:28.359105Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:28.359107Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:28.359163Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:28.359166Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:28.359217Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:28.359293Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:28.359296Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::Istanbul::0
2023-01-26T16:12:28.359299Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGMAfter.json"
2023-01-26T16:12:28.359303Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:28.359305Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:28.744157Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-26T16:12:28.744176Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:28.744183Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:28.744197Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:28.744200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::Berlin::0
2023-01-26T16:12:28.744202Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGMAfter.json"
2023-01-26T16:12:28.744207Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:28.744209Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:28.744319Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-26T16:12:28.744323Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:28.744326Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:28.744336Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:28.744338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::London::0
2023-01-26T16:12:28.744339Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGMAfter.json"
2023-01-26T16:12:28.744342Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:28.744343Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:28.744434Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-26T16:12:28.744438Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:28.744441Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:28.744450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:28.744452Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::Merge::0
2023-01-26T16:12:28.744455Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGMAfter.json"
2023-01-26T16:12:28.744459Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:28.744461Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:28.744554Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-26T16:12:28.744558Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:28.744561Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:28.746276Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:385.744329ms
2023-01-26T16:12:29.013902Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGMBefore.json", Total Files :: 1
2023-01-26T16:12:29.072480Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:29.072621Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:29.072625Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:29.072679Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:29.072681Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:29.072743Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:29.072745Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:29.072808Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:29.072811Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:29.072865Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:29.072939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:29.072942Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::Istanbul::0
2023-01-26T16:12:29.072945Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGMBefore.json"
2023-01-26T16:12:29.072949Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:29.072950Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:29.436972Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-26T16:12:29.436989Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:29.436997Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:29.437013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:29.437018Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::Berlin::0
2023-01-26T16:12:29.437020Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGMBefore.json"
2023-01-26T16:12:29.437026Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:29.437029Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:29.437155Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-26T16:12:29.437160Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:29.437164Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:29.437176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:29.437179Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::London::0
2023-01-26T16:12:29.437181Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGMBefore.json"
2023-01-26T16:12:29.437185Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:29.437187Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:29.437288Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-26T16:12:29.437293Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:29.437296Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:29.437308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:29.437311Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::Merge::0
2023-01-26T16:12:29.437313Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_OOGMBefore.json"
2023-01-26T16:12:29.437317Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:29.437319Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:29.437422Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-26T16:12:29.437428Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:29.437432Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:29.439068Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.968865ms
2023-01-26T16:12:29.723181Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_SuicideEnd.json", Total Files :: 1
2023-01-26T16:12:29.754999Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:29.755141Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:29.755144Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:29.755199Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:29.755201Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:29.755262Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:29.755264Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:29.755323Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:29.755326Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:29.755379Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:29.755453Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:29.755456Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::Istanbul::0
2023-01-26T16:12:29.755459Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_SuicideEnd.json"
2023-01-26T16:12:29.755462Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:29.755464Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:30.126731Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-26T16:12:30.126748Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:30.126756Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:30.126772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:30.126777Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::Berlin::0
2023-01-26T16:12:30.126780Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_SuicideEnd.json"
2023-01-26T16:12:30.126784Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:30.126788Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:30.126899Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-26T16:12:30.126904Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:30.126907Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:30.126918Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:30.126921Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::London::0
2023-01-26T16:12:30.126924Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_SuicideEnd.json"
2023-01-26T16:12:30.126928Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:30.126930Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:30.127023Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-26T16:12:30.127028Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:30.127031Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:30.127043Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:30.127045Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::Merge::0
2023-01-26T16:12:30.127048Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_SuicideEnd.json"
2023-01-26T16:12:30.127052Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:30.127054Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:30.127148Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-26T16:12:30.127153Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:30.127156Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:30.128826Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.174114ms
2023-01-26T16:12:30.385059Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:12:30.415976Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:30.416118Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:30.416122Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:30.416176Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:30.416179Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:30.416240Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:30.416242Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:30.416300Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:30.416302Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:30.416356Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:30.416429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:30.416432Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::Istanbul::0
2023-01-26T16:12:30.416435Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_SuicideMiddle.json"
2023-01-26T16:12:30.416440Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:30.416441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:30.799997Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-26T16:12:30.800015Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:30.800022Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:30.800035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:30.800040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::Berlin::0
2023-01-26T16:12:30.800042Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_SuicideMiddle.json"
2023-01-26T16:12:30.800046Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:30.800047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:30.800178Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-26T16:12:30.800182Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:30.800186Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:30.800195Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:30.800197Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::London::0
2023-01-26T16:12:30.800198Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_SuicideMiddle.json"
2023-01-26T16:12:30.800203Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:30.800204Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:30.800293Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-26T16:12:30.800297Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:30.800300Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:30.800310Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:30.800312Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::Merge::0
2023-01-26T16:12:30.800314Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_010_SuicideMiddle.json"
2023-01-26T16:12:30.800317Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:30.800318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:30.800406Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-26T16:12:30.800410Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:30.800413Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:30.802131Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:384.449546ms
2023-01-26T16:12:31.075358Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:12:31.106858Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:31.106999Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:31.107003Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:31.107056Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:31.107058Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:31.107117Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:31.107120Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:31.107183Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:31.107263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:31.107267Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:12:31.107272Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:12:31.107276Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:31.107278Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:31.460857Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-26T16:12:31.460872Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:31.460879Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:31.460894Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:31.460899Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:12:31.460901Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:12:31.460903Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:31.460905Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:31.461035Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-26T16:12:31.461039Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:31.461042Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:31.461051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:31.461053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::London::0
2023-01-26T16:12:31.461055Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:12:31.461058Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:31.461059Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:31.461155Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-26T16:12:31.461160Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:31.461163Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:31.461171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:31.461173Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:12:31.461175Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:12:31.461178Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:31.461179Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:31.461265Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-26T16:12:31.461269Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:31.461272Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:31.462920Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.428021ms
2023-01-26T16:12:31.748694Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011.json", Total Files :: 1
2023-01-26T16:12:31.780999Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:31.781144Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:31.781147Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:31.781201Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:31.781203Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:31.781262Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:31.781264Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:31.781322Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:31.781324Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:31.781376Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:31.781451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:31.781454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::Istanbul::0
2023-01-26T16:12:31.781456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011.json"
2023-01-26T16:12:31.781461Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:31.781462Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:32.142613Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-26T16:12:32.142629Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:32.142636Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:32.142649Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:32.142653Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::Berlin::0
2023-01-26T16:12:32.142655Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011.json"
2023-01-26T16:12:32.142658Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:32.142660Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:32.142783Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-26T16:12:32.142788Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:32.142792Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:32.142802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:32.142804Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::London::0
2023-01-26T16:12:32.142807Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011.json"
2023-01-26T16:12:32.142810Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:32.142812Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:32.142915Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-26T16:12:32.142919Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:32.142922Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:32.142931Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:32.142933Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::Merge::0
2023-01-26T16:12:32.142934Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011.json"
2023-01-26T16:12:32.142937Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:32.142938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:32.143026Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-26T16:12:32.143029Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:32.143032Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:32.144739Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.046982ms
2023-01-26T16:12:32.418738Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGE.json", Total Files :: 1
2023-01-26T16:12:32.449019Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:32.449179Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:32.449182Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:32.449239Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:32.449241Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:32.449302Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:32.449303Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:32.449361Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:32.449363Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:32.449417Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:32.449507Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:32.449510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::Istanbul::0
2023-01-26T16:12:32.449513Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGE.json"
2023-01-26T16:12:32.449516Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:32.449518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:32.794625Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-26T16:12:32.794679Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:32.795620Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:32.795654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:32.795665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::Berlin::0
2023-01-26T16:12:32.795672Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGE.json"
2023-01-26T16:12:32.795681Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:32.795688Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:32.795870Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-26T16:12:32.795885Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:32.795899Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:32.795920Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:32.795928Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::London::0
2023-01-26T16:12:32.795935Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGE.json"
2023-01-26T16:12:32.795944Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:32.795951Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:32.796080Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-26T16:12:32.796096Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:32.796108Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:32.796120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:32.796123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::Merge::0
2023-01-26T16:12:32.796125Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGE.json"
2023-01-26T16:12:32.796128Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:32.796130Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:32.796250Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-26T16:12:32.796268Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:32.796279Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:32.798596Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:347.283069ms
2023-01-26T16:12:33.074993Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGMAfter.json", Total Files :: 1
2023-01-26T16:12:33.115951Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:33.116091Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:33.116094Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:33.116147Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:33.116150Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:33.116208Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:33.116211Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:33.116272Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:33.116275Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:33.116326Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:33.116400Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:33.116403Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::Istanbul::0
2023-01-26T16:12:33.116406Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGMAfter.json"
2023-01-26T16:12:33.116409Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:33.116411Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:33.469853Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-26T16:12:33.469870Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:33.469877Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:33.469893Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:33.469897Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::Berlin::0
2023-01-26T16:12:33.469899Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGMAfter.json"
2023-01-26T16:12:33.469903Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:33.469905Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:33.470038Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-26T16:12:33.470043Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:33.470046Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:33.470055Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:33.470057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::London::0
2023-01-26T16:12:33.470059Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGMAfter.json"
2023-01-26T16:12:33.470062Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:33.470063Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:33.470154Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-26T16:12:33.470158Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:33.470161Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:33.470169Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:33.470171Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::Merge::0
2023-01-26T16:12:33.470173Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGMAfter.json"
2023-01-26T16:12:33.470176Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:33.470177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:33.470265Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-26T16:12:33.470270Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-26T16:12:33.470273Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:33.471866Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.335235ms
2023-01-26T16:12:33.747859Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGMBefore.json", Total Files :: 1
2023-01-26T16:12:33.777761Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:33.777902Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:33.777906Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:33.777959Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:33.777962Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:33.778021Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:33.778024Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:33.778082Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:33.778084Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:33.778137Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:33.778211Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:33.778214Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::Istanbul::0
2023-01-26T16:12:33.778217Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGMBefore.json"
2023-01-26T16:12:33.778221Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:33.778222Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:34.164346Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-26T16:12:34.164362Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:34.164368Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:34.164382Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:34.164386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::Berlin::0
2023-01-26T16:12:34.164389Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGMBefore.json"
2023-01-26T16:12:34.164393Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:34.164394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:34.164498Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-26T16:12:34.164503Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:34.164506Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:34.164515Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:34.164517Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::London::0
2023-01-26T16:12:34.164518Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGMBefore.json"
2023-01-26T16:12:34.164521Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:34.164523Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:34.164609Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-26T16:12:34.164613Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:34.164616Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:34.164624Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:34.164626Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::Merge::0
2023-01-26T16:12:34.164628Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_OOGMBefore.json"
2023-01-26T16:12:34.164631Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:34.164633Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:34.164716Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-26T16:12:34.164720Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:34.164722Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:34.166313Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:386.97469ms
2023-01-26T16:12:34.433027Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_SuicideEnd.json", Total Files :: 1
2023-01-26T16:12:34.487849Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:34.487986Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:34.487989Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:34.488042Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:34.488044Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:34.488103Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:34.488105Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:34.488161Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:34.488163Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:34.488230Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:34.488341Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:34.488345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::Istanbul::0
2023-01-26T16:12:34.488348Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_SuicideEnd.json"
2023-01-26T16:12:34.488355Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:34.488357Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:34.862325Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-26T16:12:34.862342Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:34.862349Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:34.862364Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:34.862368Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::Berlin::0
2023-01-26T16:12:34.862369Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_SuicideEnd.json"
2023-01-26T16:12:34.862373Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:34.862374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:34.862481Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-26T16:12:34.862487Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:34.862490Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:34.862499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:34.862501Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::London::0
2023-01-26T16:12:34.862503Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_SuicideEnd.json"
2023-01-26T16:12:34.862506Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:34.862507Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:34.862596Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-26T16:12:34.862600Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:34.862603Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:34.862612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:34.862614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::Merge::0
2023-01-26T16:12:34.862616Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_SuicideEnd.json"
2023-01-26T16:12:34.862619Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:34.862620Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:34.862707Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-26T16:12:34.862711Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:34.862715Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:34.864457Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.878514ms
2023-01-26T16:12:35.146847Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:12:35.177316Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:35.177461Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:35.177465Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:35.177529Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:35.177532Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:35.177598Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:35.177601Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:35.177663Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:35.177666Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:35.177723Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:35.177799Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:35.177803Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::Istanbul::0
2023-01-26T16:12:35.177807Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-26T16:12:35.177812Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:35.177814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:35.534584Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-26T16:12:35.534601Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:35.534608Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:35.534622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:35.534626Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::Berlin::0
2023-01-26T16:12:35.534628Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-26T16:12:35.534632Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:35.534633Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:35.534764Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-26T16:12:35.534769Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:35.534772Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:35.534781Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:35.534783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::London::0
2023-01-26T16:12:35.534786Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-26T16:12:35.534789Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:35.534790Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:35.534880Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-26T16:12:35.534884Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:35.534886Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:35.534894Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:35.534896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::Merge::0
2023-01-26T16:12:35.534898Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-26T16:12:35.534901Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:35.534903Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:35.534988Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-26T16:12:35.534993Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-26T16:12:35.534996Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-26T16:12:35.536631Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.69316ms
2023-01-26T16:12:35.823995Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:12:35.854165Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:35.854302Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:35.854305Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:35.854371Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:35.854374Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:35.854443Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:35.854446Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:35.854502Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:35.854573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:35.854575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:12:35.854578Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:35.854582Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:35.854584Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:36.252182Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:12:36.252199Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:36.252205Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:36.252220Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:36.252224Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:12:36.252226Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:36.252229Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:36.252230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:36.252351Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:12:36.252355Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:36.252358Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:36.252367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:36.252369Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::London::0
2023-01-26T16:12:36.252370Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:36.252373Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:36.252375Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:36.252464Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:12:36.252468Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:36.252471Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:36.252479Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:36.252481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:12:36.252483Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:36.252486Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:36.252487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:36.252575Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:12:36.252581Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-26T16:12:36.252583Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:12:36.254264Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:398.431681ms
2023-01-26T16:12:36.515164Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10.json", Total Files :: 1
2023-01-26T16:12:36.553798Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:36.553936Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:36.553939Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:36.553992Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:36.553995Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:36.554054Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:36.554056Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:36.554113Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:36.554184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:36.554187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::Istanbul::0
2023-01-26T16:12:36.554189Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10.json"
2023-01-26T16:12:36.554193Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:36.554194Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:36.914544Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-26T16:12:36.914558Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:36.914570Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:36.914574Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::Berlin::0
2023-01-26T16:12:36.914576Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10.json"
2023-01-26T16:12:36.914579Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:36.914580Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:36.914766Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-26T16:12:36.914770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:36.914778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:36.914781Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::London::0
2023-01-26T16:12:36.914783Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10.json"
2023-01-26T16:12:36.914786Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:36.914787Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:36.914961Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-26T16:12:36.914966Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:36.914972Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:36.914975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::Merge::0
2023-01-26T16:12:36.914976Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10.json"
2023-01-26T16:12:36.914979Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:36.914980Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:36.915154Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-26T16:12:36.915159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:36.917001Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.37152ms
2023-01-26T16:12:37.206858Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_OOGE.json", Total Files :: 1
2023-01-26T16:12:37.244824Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:37.244969Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:37.244972Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:37.245026Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:37.245029Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:37.245089Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:37.245091Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:37.245147Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:37.245221Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:37.245224Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::Istanbul::0
2023-01-26T16:12:37.245227Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_OOGE.json"
2023-01-26T16:12:37.245230Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:37.245232Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:37.609350Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-26T16:12:37.609367Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:37.609382Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:37.609386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::Berlin::0
2023-01-26T16:12:37.609388Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_OOGE.json"
2023-01-26T16:12:37.609391Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:37.609392Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:37.609645Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-26T16:12:37.609650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:37.609659Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:37.609661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::London::0
2023-01-26T16:12:37.609663Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_OOGE.json"
2023-01-26T16:12:37.609666Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:37.609667Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:37.609895Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-26T16:12:37.609899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:37.609909Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:37.609911Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::Merge::0
2023-01-26T16:12:37.609913Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_OOGE.json"
2023-01-26T16:12:37.609916Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:37.609917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:37.610143Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-26T16:12:37.610147Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:37.612000Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:365.338053ms
2023-01-26T16:12:37.882816Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json", Total Files :: 1
2023-01-26T16:12:37.913019Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:37.913162Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:37.913166Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:37.913220Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:37.913222Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:37.913282Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:37.913285Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:37.913341Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:37.913412Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:37.913415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Istanbul::0
2023-01-26T16:12:37.913418Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json"
2023-01-26T16:12:37.913422Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:37.913423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:38.301844Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-26T16:12:38.301860Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:38.301873Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:38.301877Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Berlin::0
2023-01-26T16:12:38.301879Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json"
2023-01-26T16:12:38.301883Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:38.301885Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:38.302080Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-26T16:12:38.302085Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:38.302092Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:38.302098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::London::0
2023-01-26T16:12:38.302100Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json"
2023-01-26T16:12:38.302103Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:38.302104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:38.302293Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-26T16:12:38.302299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:38.302307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:38.302309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Merge::0
2023-01-26T16:12:38.302313Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json"
2023-01-26T16:12:38.302317Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:38.302319Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:38.302508Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-26T16:12:38.302513Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:38.304255Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:389.50623ms
2023-01-26T16:12:38.563887Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100.json", Total Files :: 1
2023-01-26T16:12:38.594972Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:38.595204Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:38.595210Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:38.595287Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:38.595292Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:38.595381Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:38.595386Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:38.595473Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:38.595477Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:38.595559Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:38.595673Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:38.595678Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::Istanbul::0
2023-01-26T16:12:38.595681Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100.json"
2023-01-26T16:12:38.595686Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:38.595688Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:38.980619Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-26T16:12:38.980636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:38.980649Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:38.980653Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::Berlin::0
2023-01-26T16:12:38.980655Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100.json"
2023-01-26T16:12:38.980658Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:38.980660Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:38.980857Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-26T16:12:38.980862Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:38.980868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:38.980871Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::London::0
2023-01-26T16:12:38.980873Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100.json"
2023-01-26T16:12:38.980875Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:38.980877Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:38.981057Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-26T16:12:38.981062Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:38.981068Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:38.981071Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::Merge::0
2023-01-26T16:12:38.981073Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100.json"
2023-01-26T16:12:38.981076Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:38.981077Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:38.981252Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-26T16:12:38.981257Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:38.982812Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:386.29756ms
2023-01-26T16:12:39.270337Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGE.json", Total Files :: 1
2023-01-26T16:12:39.300082Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:39.300222Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:39.300225Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:39.300276Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:39.300278Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:39.300338Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:39.300339Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:39.300394Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:39.300396Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:39.300448Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:39.300520Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:39.300523Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::Istanbul::0
2023-01-26T16:12:39.300526Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGE.json"
2023-01-26T16:12:39.300529Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:39.300531Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:39.669656Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-26T16:12:39.669673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:39.669692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:39.669698Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::Berlin::0
2023-01-26T16:12:39.669701Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGE.json"
2023-01-26T16:12:39.669705Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:39.669707Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:39.669942Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-26T16:12:39.669948Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:39.669960Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:39.669963Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::London::0
2023-01-26T16:12:39.669966Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGE.json"
2023-01-26T16:12:39.669970Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:39.669972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:39.670201Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-26T16:12:39.670207Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:39.670219Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:39.670221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::Merge::0
2023-01-26T16:12:39.670225Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGE.json"
2023-01-26T16:12:39.670229Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:39.670231Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:39.670498Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-26T16:12:39.670505Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:39.672233Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:370.439045ms
2023-01-26T16:12:39.934078Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGMAfter.json", Total Files :: 1
2023-01-26T16:12:39.964043Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:39.964182Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:39.964185Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:39.964239Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:39.964241Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:39.964300Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:39.964302Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:39.964360Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:39.964363Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:39.964416Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:39.964490Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:39.964492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::Istanbul::0
2023-01-26T16:12:39.964496Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGMAfter.json"
2023-01-26T16:12:39.964500Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:39.964501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:40.374911Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-26T16:12:40.374928Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4331310,
    events_root: None,
}
2023-01-26T16:12:40.374941Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:40.374945Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::Berlin::0
2023-01-26T16:12:40.374947Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGMAfter.json"
2023-01-26T16:12:40.374950Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:40.374952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:40.375195Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-26T16:12:40.375199Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:40.375206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:40.375208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::London::0
2023-01-26T16:12:40.375210Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGMAfter.json"
2023-01-26T16:12:40.375214Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:40.375215Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:40.375443Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-26T16:12:40.375447Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:40.375454Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:40.375456Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::Merge::0
2023-01-26T16:12:40.375458Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGMAfter.json"
2023-01-26T16:12:40.375461Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:40.375463Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:40.375690Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-26T16:12:40.375694Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:40.377275Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:411.662949ms
2023-01-26T16:12:40.656277Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGMBefore.json", Total Files :: 1
2023-01-26T16:12:40.692353Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:40.692495Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:40.692499Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:40.692553Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:40.692556Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:40.692616Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:40.692618Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:40.692676Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:40.692679Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:40.692733Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:40.692806Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:40.692809Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::Istanbul::0
2023-01-26T16:12:40.692812Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGMBefore.json"
2023-01-26T16:12:40.692816Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:40.692817Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:41.035709Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-26T16:12:41.035725Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:41.035742Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:41.035745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::Berlin::0
2023-01-26T16:12:41.035747Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGMBefore.json"
2023-01-26T16:12:41.035751Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:41.035752Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:41.036005Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-26T16:12:41.036010Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:41.036019Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:41.036021Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::London::0
2023-01-26T16:12:41.036024Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGMBefore.json"
2023-01-26T16:12:41.036026Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:41.036028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:41.036252Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-26T16:12:41.036258Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:41.036268Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:41.036271Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::Merge::0
2023-01-26T16:12:41.036273Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_OOGMBefore.json"
2023-01-26T16:12:41.036276Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:41.036277Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:41.036498Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-26T16:12:41.036503Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:41.038409Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:344.164194ms
2023-01-26T16:12:41.318742Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_SuicideEnd.json", Total Files :: 1
2023-01-26T16:12:41.355070Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:41.355233Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:41.355237Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:41.355291Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:41.355294Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:41.355354Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:41.355356Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:41.355412Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:41.355414Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:41.355469Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:41.355541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:41.355544Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::Istanbul::0
2023-01-26T16:12:41.355546Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_SuicideEnd.json"
2023-01-26T16:12:41.355550Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:41.355551Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:41.709393Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-26T16:12:41.709407Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:41.709419Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:41.709423Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::Berlin::0
2023-01-26T16:12:41.709424Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_SuicideEnd.json"
2023-01-26T16:12:41.709428Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:41.709429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:41.709626Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-26T16:12:41.709631Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:41.709637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:41.709640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::London::0
2023-01-26T16:12:41.709642Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_SuicideEnd.json"
2023-01-26T16:12:41.709646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:41.709647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:41.709819Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-26T16:12:41.709823Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:41.709830Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:41.709832Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::Merge::0
2023-01-26T16:12:41.709835Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_SuicideEnd.json"
2023-01-26T16:12:41.709838Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:41.709839Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:41.710026Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-26T16:12:41.710031Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:41.711701Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.974727ms
2023-01-26T16:12:41.976859Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:12:42.023065Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:42.023194Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:42.023198Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:42.023248Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:42.023250Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:42.023308Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:42.023310Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:42.023363Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:42.023365Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:42.023416Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:42.023486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:42.023488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::Istanbul::0
2023-01-26T16:12:42.023492Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_SuicideMiddle.json"
2023-01-26T16:12:42.023495Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:42.023497Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:42.367978Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-26T16:12:42.367995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:42.368007Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:42.368011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::Berlin::0
2023-01-26T16:12:42.368013Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_SuicideMiddle.json"
2023-01-26T16:12:42.368016Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:42.368018Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:42.368206Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-26T16:12:42.368211Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:42.368217Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:42.368220Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::London::0
2023-01-26T16:12:42.368223Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_SuicideMiddle.json"
2023-01-26T16:12:42.368226Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:42.368227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:42.368409Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-26T16:12:42.368413Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:42.368422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:42.368424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::Merge::0
2023-01-26T16:12:42.368426Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_100_SuicideMiddle.json"
2023-01-26T16:12:42.368429Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:42.368430Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:42.368603Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-26T16:12:42.368609Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:42.370858Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:345.556029ms
2023-01-26T16:12:42.654948Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:12:42.684615Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:42.684763Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:42.684767Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:42.684824Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:42.684826Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:42.684890Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:42.684893Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:42.684951Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:42.685025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:42.685029Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:12:42.685033Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-26T16:12:42.685038Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:42.685040Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:43.035129Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-26T16:12:43.035145Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3970598,
    events_root: None,
}
2023-01-26T16:12:43.035162Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:43.035165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:12:43.035167Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-26T16:12:43.035170Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:43.035172Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:43.035442Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-26T16:12:43.035447Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3970598,
    events_root: None,
}
2023-01-26T16:12:43.035454Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:43.035457Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::London::0
2023-01-26T16:12:43.035458Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-26T16:12:43.035461Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:43.035463Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:43.035717Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-26T16:12:43.035721Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3970598,
    events_root: None,
}
2023-01-26T16:12:43.035729Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:43.035731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:12:43.035733Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-26T16:12:43.035736Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:43.035737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:43.035989Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-26T16:12:43.035994Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3970598,
    events_root: None,
}
2023-01-26T16:12:43.037573Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:351.390405ms
2023-01-26T16:12:43.301434Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101.json", Total Files :: 1
2023-01-26T16:12:43.332485Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:43.332630Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:43.332634Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:43.332689Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:43.332691Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:43.332753Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:43.332755Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:43.332812Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:43.332814Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:43.332867Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:43.332943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:43.332946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::Istanbul::0
2023-01-26T16:12:43.332949Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101.json"
2023-01-26T16:12:43.332953Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:43.332954Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:43.717486Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-26T16:12:43.717501Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:43.717512Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:43.717516Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::Berlin::0
2023-01-26T16:12:43.717518Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101.json"
2023-01-26T16:12:43.717521Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:43.717523Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:43.717714Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-26T16:12:43.717720Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:43.717727Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:43.717729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::London::0
2023-01-26T16:12:43.717731Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101.json"
2023-01-26T16:12:43.717734Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:43.717735Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:43.717912Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-26T16:12:43.717917Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:43.717923Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:43.717925Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::Merge::0
2023-01-26T16:12:43.717927Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101.json"
2023-01-26T16:12:43.717930Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:43.717931Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:43.718107Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-26T16:12:43.718111Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:43.719741Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:385.638507ms
2023-01-26T16:12:44.001374Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGE.json", Total Files :: 1
2023-01-26T16:12:44.049135Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:44.049269Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:44.049273Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:44.049323Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:44.049325Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:44.049382Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:44.049384Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:44.049437Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:44.049439Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:44.049497Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:44.049568Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:44.049570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::Istanbul::0
2023-01-26T16:12:44.049573Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGE.json"
2023-01-26T16:12:44.049577Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:44.049578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:44.413527Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-26T16:12:44.413544Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:44.413557Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:44.413561Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::Berlin::0
2023-01-26T16:12:44.413562Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGE.json"
2023-01-26T16:12:44.413566Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:44.413567Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:44.413809Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-26T16:12:44.413813Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:44.413820Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:44.413823Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::London::0
2023-01-26T16:12:44.413824Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGE.json"
2023-01-26T16:12:44.413827Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:44.413829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:44.414061Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-26T16:12:44.414066Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:44.414074Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:44.414077Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::Merge::0
2023-01-26T16:12:44.414080Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGE.json"
2023-01-26T16:12:44.414083Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:44.414085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:44.414326Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-26T16:12:44.414331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:44.415903Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:365.210021ms
2023-01-26T16:12:44.701488Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGMAfter.json", Total Files :: 1
2023-01-26T16:12:44.732533Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:44.732675Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:44.732679Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:44.732735Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:44.732737Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:44.732800Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:44.732802Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:44.732859Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:44.732861Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:44.732914Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:44.732988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:44.732991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::Istanbul::0
2023-01-26T16:12:44.732994Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGMAfter.json"
2023-01-26T16:12:44.732999Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:44.733000Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:45.087412Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-26T16:12:45.087427Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4331310,
    events_root: None,
}
2023-01-26T16:12:45.087440Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:45.087444Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::Berlin::0
2023-01-26T16:12:45.087446Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGMAfter.json"
2023-01-26T16:12:45.087450Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:45.087452Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:45.087700Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-26T16:12:45.087705Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:45.087712Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:45.087714Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::London::0
2023-01-26T16:12:45.087716Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGMAfter.json"
2023-01-26T16:12:45.087719Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:45.087720Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:45.087954Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-26T16:12:45.087958Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:45.087965Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:45.087967Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::Merge::0
2023-01-26T16:12:45.087969Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGMAfter.json"
2023-01-26T16:12:45.087972Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:45.087973Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:45.088269Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-26T16:12:45.088274Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:45.090069Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.752008ms
2023-01-26T16:12:45.379827Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGMBefore.json", Total Files :: 1
2023-01-26T16:12:45.410704Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:45.410886Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:45.410892Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:45.410961Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:45.410964Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:45.411045Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:45.411049Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:45.411127Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:45.411131Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:45.411188Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:45.411265Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:45.411268Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::Istanbul::0
2023-01-26T16:12:45.411271Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGMBefore.json"
2023-01-26T16:12:45.411275Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:45.411277Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:45.791661Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-26T16:12:45.791677Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:45.791692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:45.791697Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::Berlin::0
2023-01-26T16:12:45.791700Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGMBefore.json"
2023-01-26T16:12:45.791705Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:45.791706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:45.791939Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-26T16:12:45.791945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:45.791952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:45.791954Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::London::0
2023-01-26T16:12:45.791957Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGMBefore.json"
2023-01-26T16:12:45.791961Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:45.791962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:45.792184Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-26T16:12:45.792190Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:45.792197Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:45.792199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::Merge::0
2023-01-26T16:12:45.792201Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_OOGMBefore.json"
2023-01-26T16:12:45.792204Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:45.792206Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:45.792427Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-26T16:12:45.792433Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:45.794099Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:381.741414ms
2023-01-26T16:12:46.067120Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_SuicideEnd.json", Total Files :: 1
2023-01-26T16:12:46.122352Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:46.122489Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:46.122492Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:46.122546Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:46.122548Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:46.122607Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:46.122609Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:46.122666Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:46.122669Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:46.122723Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:46.122796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:46.122799Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Istanbul::0
2023-01-26T16:12:46.122802Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-26T16:12:46.122806Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:46.122808Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:46.491080Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-26T16:12:46.491098Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:46.491110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:46.491114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Berlin::0
2023-01-26T16:12:46.491116Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-26T16:12:46.491120Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:46.491122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:46.491305Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-26T16:12:46.491310Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:46.491317Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:46.491320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::London::0
2023-01-26T16:12:46.491322Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-26T16:12:46.491324Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:46.491326Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:46.491497Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-26T16:12:46.491502Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:46.491508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:46.491511Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Merge::0
2023-01-26T16:12:46.491512Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-26T16:12:46.491515Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:46.491517Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:46.491688Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-26T16:12:46.491694Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:46.493351Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:369.353079ms
2023-01-26T16:12:46.786884Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:12:46.816649Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:46.816790Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:46.816793Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:46.816847Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:46.816849Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:46.816908Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:46.816910Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:46.816967Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:46.816970Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:46.817023Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:46.817095Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:46.817098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::Istanbul::0
2023-01-26T16:12:46.817101Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-26T16:12:46.817105Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:46.817107Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:47.215166Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-26T16:12:47.215181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:47.215195Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:47.215199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::Berlin::0
2023-01-26T16:12:47.215201Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-26T16:12:47.215205Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:47.215206Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:47.215416Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-26T16:12:47.215422Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:47.215431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:47.215434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::London::0
2023-01-26T16:12:47.215436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-26T16:12:47.215440Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:47.215442Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:47.215635Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-26T16:12:47.215640Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:47.215647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:47.215651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::Merge::0
2023-01-26T16:12:47.215652Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-26T16:12:47.215655Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:47.215657Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:47.215832Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-26T16:12:47.215836Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:47.217518Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:399.19806ms
2023-01-26T16:12:47.483058Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:12:47.529183Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:47.529327Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:47.529330Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:47.529385Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:47.529388Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:47.529448Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:47.529450Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:47.529516Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:47.529598Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:47.529602Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:12:47.529605Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:47.529609Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:47.529610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:47.897006Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-26T16:12:47.897026Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3970598,
    events_root: None,
}
2023-01-26T16:12:47.897041Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:47.897046Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:12:47.897049Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:47.897053Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:47.897055Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:47.897408Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-26T16:12:47.897414Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3970598,
    events_root: None,
}
2023-01-26T16:12:47.897423Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:47.897426Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::London::0
2023-01-26T16:12:47.897431Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:47.897435Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:47.897437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:47.897758Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-26T16:12:47.897764Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3970598,
    events_root: None,
}
2023-01-26T16:12:47.897772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:47.897774Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:12:47.897776Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:47.897779Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:47.897780Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:47.898027Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-26T16:12:47.898032Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3970598,
    events_root: None,
}
2023-01-26T16:12:47.899895Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.865796ms
2023-01-26T16:12:48.179485Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11.json", Total Files :: 1
2023-01-26T16:12:48.215825Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:48.215966Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:48.215970Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:48.216021Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:48.216024Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:48.216082Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:48.216085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:48.216139Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:48.216216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:48.216219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::Istanbul::0
2023-01-26T16:12:48.216222Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11.json"
2023-01-26T16:12:48.216226Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:48.216227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:48.572257Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-26T16:12:48.572271Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:48.572284Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:48.572288Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::Berlin::0
2023-01-26T16:12:48.572290Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11.json"
2023-01-26T16:12:48.572293Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:48.572295Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:48.572480Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-26T16:12:48.572484Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:48.572492Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:48.572494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::London::0
2023-01-26T16:12:48.572496Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11.json"
2023-01-26T16:12:48.572500Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:48.572502Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:48.572679Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-26T16:12:48.572683Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:48.572689Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:48.572691Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::Merge::0
2023-01-26T16:12:48.572693Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11.json"
2023-01-26T16:12:48.572696Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:48.572698Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:48.572873Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-26T16:12:48.572878Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:48.574822Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.065885ms
2023-01-26T16:12:48.868661Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_OOGE.json", Total Files :: 1
2023-01-26T16:12:48.898855Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:48.898993Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:48.898997Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:48.899051Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:48.899053Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:48.899111Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:48.899113Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:48.899171Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:48.899243Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:48.899246Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::Istanbul::0
2023-01-26T16:12:48.899249Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_OOGE.json"
2023-01-26T16:12:48.899252Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:48.899254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:49.270078Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-26T16:12:49.270093Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:49.270108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:49.270113Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::Berlin::0
2023-01-26T16:12:49.270116Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_OOGE.json"
2023-01-26T16:12:49.270120Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:49.270122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:49.270375Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-26T16:12:49.270380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:49.270392Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:49.270395Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::London::0
2023-01-26T16:12:49.270398Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_OOGE.json"
2023-01-26T16:12:49.270401Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:49.270403Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:49.270689Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-26T16:12:49.270695Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:49.270706Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:49.270709Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::Merge::0
2023-01-26T16:12:49.270713Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_OOGE.json"
2023-01-26T16:12:49.270716Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:49.270718Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:49.270962Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-26T16:12:49.270968Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:49.272907Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.12632ms
2023-01-26T16:12:49.551172Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json", Total Files :: 1
2023-01-26T16:12:49.599582Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:49.599719Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:49.599723Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:49.599774Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:49.599776Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:49.599833Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:49.599835Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:49.599890Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:49.599961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:49.599964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Istanbul::0
2023-01-26T16:12:49.599966Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-26T16:12:49.599970Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:49.599972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:49.982733Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-26T16:12:49.982748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:49.982761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:49.982766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Berlin::0
2023-01-26T16:12:49.982768Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-26T16:12:49.982772Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:49.982773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:49.982992Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-26T16:12:49.982998Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:49.983005Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:49.983007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::London::0
2023-01-26T16:12:49.983010Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-26T16:12:49.983013Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:49.983015Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:49.983185Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-26T16:12:49.983191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:49.983197Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:49.983200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Merge::0
2023-01-26T16:12:49.983201Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-26T16:12:49.983204Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:49.983206Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:49.983374Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-26T16:12:49.983379Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:49.984996Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:383.80662ms
2023-01-26T16:12:50.245302Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110.json", Total Files :: 1
2023-01-26T16:12:50.276133Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:50.276275Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:50.276279Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:50.276337Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:50.276340Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:50.276399Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:50.276401Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:50.276474Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:50.276478Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:50.276534Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:50.276608Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:50.276610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::Istanbul::0
2023-01-26T16:12:50.276613Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110.json"
2023-01-26T16:12:50.276617Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:50.276618Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:50.638664Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-26T16:12:50.638679Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:50.638690Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:50.638694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::Berlin::0
2023-01-26T16:12:50.638696Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110.json"
2023-01-26T16:12:50.638699Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:50.638700Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:50.638885Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-26T16:12:50.638889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:50.638898Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:50.638902Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::London::0
2023-01-26T16:12:50.638904Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110.json"
2023-01-26T16:12:50.638908Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:50.638910Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:50.639099Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-26T16:12:50.639105Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:50.639113Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:50.639116Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::Merge::0
2023-01-26T16:12:50.639118Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110.json"
2023-01-26T16:12:50.639122Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:50.639123Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:50.639303Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-26T16:12:50.639308Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:50.640966Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:363.185323ms
2023-01-26T16:12:50.908900Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGE.json", Total Files :: 1
2023-01-26T16:12:50.956891Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:50.957028Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:50.957032Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:50.957085Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:50.957088Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:50.957148Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:50.957149Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:50.957204Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:50.957207Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:50.957259Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:50.957330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:50.957333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::Istanbul::0
2023-01-26T16:12:50.957336Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGE.json"
2023-01-26T16:12:50.957340Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:50.957341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:51.340022Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-26T16:12:51.340040Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:51.340056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:51.340061Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::Berlin::0
2023-01-26T16:12:51.340063Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGE.json"
2023-01-26T16:12:51.340068Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:51.340070Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:51.340374Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-26T16:12:51.340381Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:51.340389Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:51.340392Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::London::0
2023-01-26T16:12:51.340394Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGE.json"
2023-01-26T16:12:51.340398Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:51.340400Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:51.340648Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-26T16:12:51.340654Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:51.340661Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:51.340663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::Merge::0
2023-01-26T16:12:51.340665Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGE.json"
2023-01-26T16:12:51.340668Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:51.340670Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:51.340901Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-26T16:12:51.340907Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:51.342696Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:384.028814ms
2023-01-26T16:12:51.602417Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGMAfter.json", Total Files :: 1
2023-01-26T16:12:51.638416Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:51.638562Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:51.638567Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:51.638623Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:51.638625Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:51.638689Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:51.638692Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:51.638751Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:51.638755Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:51.638821Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:51.638900Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:51.638903Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::Istanbul::0
2023-01-26T16:12:51.638907Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGMAfter.json"
2023-01-26T16:12:51.638913Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:51.638915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:52.009574Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-26T16:12:52.009589Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4331310,
    events_root: None,
}
2023-01-26T16:12:52.009604Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:52.009608Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::Berlin::0
2023-01-26T16:12:52.009610Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGMAfter.json"
2023-01-26T16:12:52.009613Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:52.009614Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:52.009867Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-26T16:12:52.009872Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:52.009881Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:52.009884Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::London::0
2023-01-26T16:12:52.009886Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGMAfter.json"
2023-01-26T16:12:52.009889Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:52.009890Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:52.010118Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-26T16:12:52.010122Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:52.010131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:52.010134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::Merge::0
2023-01-26T16:12:52.010136Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGMAfter.json"
2023-01-26T16:12:52.010138Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:52.010140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:52.010374Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-26T16:12:52.010379Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:52.012324Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.976955ms
2023-01-26T16:12:52.286871Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGMBefore.json", Total Files :: 1
2023-01-26T16:12:52.317376Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:52.317525Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:52.317529Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:52.317582Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:52.317584Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:52.317644Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:52.317646Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:52.317710Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:52.317714Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:52.317782Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:52.317871Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:52.317875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::Istanbul::0
2023-01-26T16:12:52.317878Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGMBefore.json"
2023-01-26T16:12:52.317882Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:52.317884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:52.671667Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-26T16:12:52.671684Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:52.671696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:52.671700Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::Berlin::0
2023-01-26T16:12:52.671702Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGMBefore.json"
2023-01-26T16:12:52.671706Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:52.671708Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:52.671944Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-26T16:12:52.671950Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:52.671957Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:52.671959Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::London::0
2023-01-26T16:12:52.671961Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGMBefore.json"
2023-01-26T16:12:52.671964Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:52.671966Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:52.672192Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-26T16:12:52.672197Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:52.672204Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:52.672206Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::Merge::0
2023-01-26T16:12:52.672208Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_OOGMBefore.json"
2023-01-26T16:12:52.672211Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:52.672212Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:52.672439Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-26T16:12:52.672444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:52.674087Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.079459ms
2023-01-26T16:12:52.953056Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json", Total Files :: 1
2023-01-26T16:12:52.998414Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:52.998560Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:52.998565Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:52.998618Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:52.998621Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:52.998681Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:52.998683Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:52.998740Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:52.998743Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:52.998795Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:52.998869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:52.998872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Istanbul::0
2023-01-26T16:12:52.998875Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-26T16:12:52.998879Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:52.998880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:53.351498Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-26T16:12:53.351514Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:53.351525Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:53.351529Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Berlin::0
2023-01-26T16:12:53.351531Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-26T16:12:53.351534Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:53.351536Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:53.351735Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-26T16:12:53.351739Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:53.351746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:53.351748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::London::0
2023-01-26T16:12:53.351750Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-26T16:12:53.351753Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:53.351755Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:53.351935Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-26T16:12:53.351940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:53.351946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:53.351948Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Merge::0
2023-01-26T16:12:53.351950Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-26T16:12:53.351953Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:53.351955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:53.352130Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-26T16:12:53.352135Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:53.353818Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:353.733535ms
2023-01-26T16:12:53.625722Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:12:53.656979Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:53.657120Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:53.657124Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:53.657177Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:53.657179Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:53.657240Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:53.657242Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:53.657299Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:53.657301Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:53.657354Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:53.657430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:53.657433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Istanbul::0
2023-01-26T16:12:53.657436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-26T16:12:53.657440Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:53.657442Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:54.010660Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-26T16:12:54.010678Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:54.010693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:54.010697Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Berlin::0
2023-01-26T16:12:54.010699Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-26T16:12:54.010703Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:54.010704Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:54.010918Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-26T16:12:54.010922Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:54.010930Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:54.010932Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::London::0
2023-01-26T16:12:54.010934Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-26T16:12:54.010938Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:54.010939Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:54.011137Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-26T16:12:54.011142Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:54.011150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:54.011153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Merge::0
2023-01-26T16:12:54.011155Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-26T16:12:54.011159Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:54.011161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:54.011342Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-26T16:12:54.011347Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:54.013030Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.379665ms
2023-01-26T16:12:54.289868Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:12:54.327939Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:54.328078Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:54.328082Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:54.328135Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:54.328137Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:54.328195Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:54.328197Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:54.328253Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:54.328326Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:54.328329Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:12:54.328332Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:12:54.328336Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:54.328337Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:54.670838Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-26T16:12:54.670852Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6985160,
    events_root: None,
}
2023-01-26T16:12:54.670871Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:54.670876Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:12:54.670877Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:12:54.670882Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:54.670883Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:54.671288Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-26T16:12:54.671293Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:12:54.671305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:54.671308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::London::0
2023-01-26T16:12:54.671310Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:12:54.671313Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:54.671314Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:54.671705Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-26T16:12:54.671710Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:12:54.671720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:54.671722Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:12:54.671725Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:12:54.671728Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:54.671729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:54.672134Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-26T16:12:54.672140Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:12:54.673909Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:344.218445ms
2023-01-26T16:12:54.952906Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111.json", Total Files :: 1
2023-01-26T16:12:54.986936Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:54.987080Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:54.987084Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:54.987141Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:54.987143Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:54.987206Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:54.987209Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:54.987268Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:54.987271Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:54.987327Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:54.987403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:54.987407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::Istanbul::0
2023-01-26T16:12:54.987411Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111.json"
2023-01-26T16:12:54.987416Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:54.987418Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:55.391889Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-26T16:12:55.391905Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:55.391918Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:55.391922Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::Berlin::0
2023-01-26T16:12:55.391924Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111.json"
2023-01-26T16:12:55.391927Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:55.391928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:55.392110Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-26T16:12:55.392115Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:55.392121Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:55.392124Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::London::0
2023-01-26T16:12:55.392126Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111.json"
2023-01-26T16:12:55.392129Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:55.392130Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:55.392302Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-26T16:12:55.392307Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:55.392313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:55.392315Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::Merge::0
2023-01-26T16:12:55.392317Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111.json"
2023-01-26T16:12:55.392320Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:55.392322Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:55.392498Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-26T16:12:55.392503Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:12:55.394185Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:405.579444ms
2023-01-26T16:12:55.678506Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGE.json", Total Files :: 1
2023-01-26T16:12:55.719337Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:55.719472Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:55.719476Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:55.719528Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:55.719530Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:55.719589Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:55.719591Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:55.719648Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:55.719650Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:55.719701Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:55.719773Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:55.719775Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::Istanbul::0
2023-01-26T16:12:55.719778Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGE.json"
2023-01-26T16:12:55.719782Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:55.719784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:56.086497Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-26T16:12:56.086512Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:56.086525Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:56.086529Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::Berlin::0
2023-01-26T16:12:56.086532Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGE.json"
2023-01-26T16:12:56.086535Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:56.086537Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:56.086782Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-26T16:12:56.086787Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:56.086794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:56.086796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::London::0
2023-01-26T16:12:56.086798Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGE.json"
2023-01-26T16:12:56.086801Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:56.086804Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:56.087032Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-26T16:12:56.087036Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:56.087043Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:56.087046Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::Merge::0
2023-01-26T16:12:56.087048Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGE.json"
2023-01-26T16:12:56.087051Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:56.087052Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:56.087279Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-26T16:12:56.087284Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:56.089134Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.958665ms
2023-01-26T16:12:56.371938Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGMAfter.json", Total Files :: 1
2023-01-26T16:12:56.402172Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:56.402312Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:56.402317Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:56.402374Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:56.402376Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:56.402436Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:56.402438Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:56.402496Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:56.402498Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:56.402552Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:56.402625Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:56.402628Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::Istanbul::0
2023-01-26T16:12:56.402631Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-26T16:12:56.402635Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:56.402636Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:56.755993Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-26T16:12:56.756008Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4331310,
    events_root: None,
}
2023-01-26T16:12:56.756024Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:56.756028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::Berlin::0
2023-01-26T16:12:56.756030Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-26T16:12:56.756034Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:56.756035Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:56.756347Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-26T16:12:56.756352Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:56.756361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:56.756363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::London::0
2023-01-26T16:12:56.756365Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-26T16:12:56.756368Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:56.756369Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:56.756605Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-26T16:12:56.756610Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:56.756619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:56.756621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::Merge::0
2023-01-26T16:12:56.756623Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-26T16:12:56.756627Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:56.756628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:56.756860Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-26T16:12:56.756866Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:12:56.758578Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.709519ms
2023-01-26T16:12:57.044189Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGMBefore.json", Total Files :: 1
2023-01-26T16:12:57.095557Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:57.095696Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:57.095700Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:57.095753Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:57.095755Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:57.095817Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:57.095819Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:57.095878Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:57.095881Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:57.095934Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:57.096008Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:57.096011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::Istanbul::0
2023-01-26T16:12:57.096014Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-26T16:12:57.096018Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:57.096019Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:57.469836Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-26T16:12:57.469851Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:57.469863Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:57.469867Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::Berlin::0
2023-01-26T16:12:57.469869Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-26T16:12:57.469873Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:57.469874Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:57.470101Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-26T16:12:57.470106Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:57.470113Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:57.470115Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::London::0
2023-01-26T16:12:57.470117Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-26T16:12:57.470120Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:57.470121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:57.470359Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-26T16:12:57.470364Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:57.470371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:57.470373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::Merge::0
2023-01-26T16:12:57.470376Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-26T16:12:57.470379Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:57.470380Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:57.470605Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-26T16:12:57.470610Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:12:57.472170Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:375.063566ms
2023-01-26T16:12:57.755633Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_SuicideEnd.json", Total Files :: 1
2023-01-26T16:12:57.812139Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:57.812290Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:57.812294Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:57.812349Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:57.812352Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:57.812414Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:57.812416Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:57.812476Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:57.812479Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:57.812533Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:57.812612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:57.812615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::Istanbul::0
2023-01-26T16:12:57.812618Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-26T16:12:57.812622Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:57.812623Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:58.177104Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-26T16:12:58.177120Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:58.177132Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:58.177136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::Berlin::0
2023-01-26T16:12:58.177138Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-26T16:12:58.177141Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:58.177143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:58.177324Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-26T16:12:58.177329Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:58.177335Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:58.177338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::London::0
2023-01-26T16:12:58.177340Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-26T16:12:58.177343Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:58.177344Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:58.177563Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-26T16:12:58.177569Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:58.177575Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:58.177577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::Merge::0
2023-01-26T16:12:58.177579Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-26T16:12:58.177582Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:58.177584Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:58.177748Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-26T16:12:58.177753Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:58.179360Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:365.625691ms
2023-01-26T16:12:58.462093Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:12:58.493206Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:58.493408Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:58.493414Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:58.493495Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:58.493499Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:58.493580Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:58.493586Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:58.493658Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:58.493661Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:12:58.493716Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:58.493802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:58.493805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::Istanbul::0
2023-01-26T16:12:58.493808Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-26T16:12:58.493813Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:58.493814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:58.855311Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-26T16:12:58.855327Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:58.855341Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:58.855345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::Berlin::0
2023-01-26T16:12:58.855347Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-26T16:12:58.855351Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:58.855352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:58.855546Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-26T16:12:58.855551Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:58.855558Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:58.855560Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::London::0
2023-01-26T16:12:58.855562Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-26T16:12:58.855565Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:58.855567Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:58.855745Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-26T16:12:58.855750Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:58.855756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:58.855759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::Merge::0
2023-01-26T16:12:58.855762Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-26T16:12:58.855766Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:58.855767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:58.855946Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-26T16:12:58.855952Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:12:58.857547Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.757648ms
2023-01-26T16:12:59.131098Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:12:59.162200Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:12:59.162344Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:59.162348Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:12:59.162403Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:59.162405Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:12:59.162466Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:59.162468Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:12:59.162525Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:12:59.162597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:12:59.162600Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:12:59.162604Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:59.162608Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:59.162610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:59.568477Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:12:59.568492Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6985160,
    events_root: None,
}
2023-01-26T16:12:59.568511Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:12:59.568515Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:12:59.568517Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:59.568521Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:59.568523Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:59.568920Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:12:59.568925Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:12:59.568939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:12:59.568942Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::London::0
2023-01-26T16:12:59.568944Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:59.568947Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:59.568949Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:59.569335Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:12:59.569340Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:12:59.569353Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:12:59.569356Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:12:59.569358Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:12:59.569361Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:12:59.569362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:12:59.569751Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:12:59.569757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:12:59.571719Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:407.576899ms
```
