> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stMemExpandingEIP150Calls

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-case failed

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-27-01 | CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls |
| TID-27-08 | NewGasPriceForCodesWithMemExpandingCalls |

> Execution Trace

```
2023-01-26T07:17:19.309950Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls.json", Total Files :: 1
2023-01-26T07:17:19.360225Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:17:19.360425Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:19.360429Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:17:19.360484Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:19.360487Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:17:19.360545Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:19.360617Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:17:19.360621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls"::Istanbul::0
2023-01-26T07:17:19.360624Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:19.360628Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:19.360629Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:19.697723Z  INFO evm_eth_compliance::statetest::runner: UC : "CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:19.697739Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3305289,
    events_root: None,
}
2023-01-26T07:17:19.697745Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=78): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T07:17:19.697763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:17:19.697770Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls"::Berlin::0
2023-01-26T07:17:19.697773Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:19.697776Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:19.697777Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:19.697982Z  INFO evm_eth_compliance::statetest::runner: UC : "CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:19.697987Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3305289,
    events_root: None,
}
2023-01-26T07:17:19.697990Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=78): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T07:17:19.698004Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:17:19.698006Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls"::London::0
2023-01-26T07:17:19.698009Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:19.698013Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:19.698014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:19.698200Z  INFO evm_eth_compliance::statetest::runner: UC : "CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:19.698205Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3305289,
    events_root: None,
}
2023-01-26T07:17:19.698208Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=78): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T07:17:19.698221Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:17:19.698224Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls"::Merge::0
2023-01-26T07:17:19.698226Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:19.698230Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:19.698231Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:19.698416Z  INFO evm_eth_compliance::statetest::runner: UC : "CallAndCallcodeConsumeMoreGasThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:19.698421Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 3305289,
    events_root: None,
}
2023-01-26T07:17:19.698424Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=78): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T07:17:19.699959Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:338.215645ms
2023-01-26T07:17:19.973846Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls.json", Total Files :: 1
2023-01-26T07:17:20.004722Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:17:20.004930Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:20.004935Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:17:20.004998Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:20.005001Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:17:20.005066Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:20.005069Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T07:17:20.005132Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:20.005209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:17:20.005213Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls"::Istanbul::0
2023-01-26T07:17:20.005217Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:20.005222Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:20.005224Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:20.360193Z  INFO evm_eth_compliance::statetest::runner: UC : "CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:20.360208Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2885342,
    events_root: None,
}
2023-01-26T07:17:20.360219Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:17:20.360227Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls"::Berlin::0
2023-01-26T07:17:20.360229Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:20.360232Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:20.360234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:20.360385Z  INFO evm_eth_compliance::statetest::runner: UC : "CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:20.360390Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2903006,
    events_root: None,
}
2023-01-26T07:17:20.360396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:17:20.360399Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls"::London::0
2023-01-26T07:17:20.360402Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:20.360405Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:20.360406Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:20.360525Z  INFO evm_eth_compliance::statetest::runner: UC : "CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:20.360530Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1974775,
    events_root: None,
}
2023-01-26T07:17:20.360536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:17:20.360538Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls"::Merge::0
2023-01-26T07:17:20.360541Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:20.360544Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:20.360545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:20.360676Z  INFO evm_eth_compliance::statetest::runner: UC : "CallAskMoreGasOnDepth2ThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:20.360681Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1974775,
    events_root: None,
}
2023-01-26T07:17:20.362218Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.969279ms
2023-01-26T07:17:20.635721Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevel2WithMemExpandingCalls.json", Total Files :: 1
2023-01-26T07:17:20.665061Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:17:20.665265Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:20.665270Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:17:20.665326Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:20.665328Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:17:20.665389Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:20.665392Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T07:17:20.665446Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:20.665525Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:17:20.665528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallGoesOOGOnSecondLevel2WithMemExpandingCalls"::Istanbul::0
2023-01-26T07:17:20.665531Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevel2WithMemExpandingCalls.json"
2023-01-26T07:17:20.665535Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:20.665536Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:21.009328Z  INFO evm_eth_compliance::statetest::runner: UC : "CallGoesOOGOnSecondLevel2WithMemExpandingCalls"
2023-01-26T07:17:21.009343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3285342,
    events_root: None,
}
2023-01-26T07:17:21.009355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:17:21.009362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallGoesOOGOnSecondLevel2WithMemExpandingCalls"::Berlin::0
2023-01-26T07:17:21.009364Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevel2WithMemExpandingCalls.json"
2023-01-26T07:17:21.009368Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:21.009369Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:21.009568Z  INFO evm_eth_compliance::statetest::runner: UC : "CallGoesOOGOnSecondLevel2WithMemExpandingCalls"
2023-01-26T07:17:21.009573Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3303006,
    events_root: None,
}
2023-01-26T07:17:21.009579Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:17:21.009583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallGoesOOGOnSecondLevel2WithMemExpandingCalls"::London::0
2023-01-26T07:17:21.009585Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevel2WithMemExpandingCalls.json"
2023-01-26T07:17:21.009588Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:21.009589Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:21.009764Z  INFO evm_eth_compliance::statetest::runner: UC : "CallGoesOOGOnSecondLevel2WithMemExpandingCalls"
2023-01-26T07:17:21.009770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2374775,
    events_root: None,
}
2023-01-26T07:17:21.009775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:17:21.009778Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallGoesOOGOnSecondLevel2WithMemExpandingCalls"::Merge::0
2023-01-26T07:17:21.009780Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevel2WithMemExpandingCalls.json"
2023-01-26T07:17:21.009783Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:21.009784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:21.009952Z  INFO evm_eth_compliance::statetest::runner: UC : "CallGoesOOGOnSecondLevel2WithMemExpandingCalls"
2023-01-26T07:17:21.009956Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2374775,
    events_root: None,
}
2023-01-26T07:17:21.011522Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:344.906658ms
2023-01-26T07:17:21.295564Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevelWithMemExpandingCalls.json", Total Files :: 1
2023-01-26T07:17:21.325873Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:17:21.326061Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:21.326065Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:17:21.326122Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:21.326125Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:17:21.326187Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:21.326189Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T07:17:21.326245Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:21.326317Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:17:21.326320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallGoesOOGOnSecondLevelWithMemExpandingCalls"::Istanbul::0
2023-01-26T07:17:21.326324Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevelWithMemExpandingCalls.json"
2023-01-26T07:17:21.326327Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:21.326329Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:21.662982Z  INFO evm_eth_compliance::statetest::runner: UC : "CallGoesOOGOnSecondLevelWithMemExpandingCalls"
2023-01-26T07:17:21.662998Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3285342,
    events_root: None,
}
2023-01-26T07:17:21.663010Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:17:21.663016Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallGoesOOGOnSecondLevelWithMemExpandingCalls"::Berlin::0
2023-01-26T07:17:21.663018Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevelWithMemExpandingCalls.json"
2023-01-26T07:17:21.663022Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:21.663024Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:21.663214Z  INFO evm_eth_compliance::statetest::runner: UC : "CallGoesOOGOnSecondLevelWithMemExpandingCalls"
2023-01-26T07:17:21.663219Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3303006,
    events_root: None,
}
2023-01-26T07:17:21.663226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:17:21.663229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallGoesOOGOnSecondLevelWithMemExpandingCalls"::London::0
2023-01-26T07:17:21.663231Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevelWithMemExpandingCalls.json"
2023-01-26T07:17:21.663234Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:21.663235Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:21.663402Z  INFO evm_eth_compliance::statetest::runner: UC : "CallGoesOOGOnSecondLevelWithMemExpandingCalls"
2023-01-26T07:17:21.663407Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2374775,
    events_root: None,
}
2023-01-26T07:17:21.663413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:17:21.663416Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallGoesOOGOnSecondLevelWithMemExpandingCalls"::Merge::0
2023-01-26T07:17:21.663418Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CallGoesOOGOnSecondLevelWithMemExpandingCalls.json"
2023-01-26T07:17:21.663422Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:21.663423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:21.663586Z  INFO evm_eth_compliance::statetest::runner: UC : "CallGoesOOGOnSecondLevelWithMemExpandingCalls"
2023-01-26T07:17:21.663590Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2374775,
    events_root: None,
}
2023-01-26T07:17:21.665117Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:337.727613ms
2023-01-26T07:17:21.929866Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CreateAndGasInsideCreateWithMemExpandingCalls.json", Total Files :: 1
2023-01-26T07:17:21.960865Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:17:21.961063Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:21.961067Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:17:21.961119Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:21.961189Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:17:21.961192Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAndGasInsideCreateWithMemExpandingCalls"::Istanbul::0
2023-01-26T07:17:21.961195Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CreateAndGasInsideCreateWithMemExpandingCalls.json"
2023-01-26T07:17:21.961199Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:21.961200Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [241, 236, 249, 132, 137, 250, 158, 214, 10, 102, 79, 196, 153, 141, 182, 153, 207, 163, 157, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T07:17:22.603878Z  INFO evm_eth_compliance::statetest::runner: UC : "CreateAndGasInsideCreateWithMemExpandingCalls"
2023-01-26T07:17:22.603888Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16367475,
    events_root: None,
}
2023-01-26T07:17:22.603914Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:17:22.603921Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAndGasInsideCreateWithMemExpandingCalls"::Berlin::0
2023-01-26T07:17:22.603923Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CreateAndGasInsideCreateWithMemExpandingCalls.json"
2023-01-26T07:17:22.603926Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:22.603928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [48, 199, 204, 13, 24, 18, 59, 68, 92, 38, 54, 255, 144, 105, 239, 40, 192, 220, 50, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-26T07:17:22.604622Z  INFO evm_eth_compliance::statetest::runner: UC : "CreateAndGasInsideCreateWithMemExpandingCalls"
2023-01-26T07:17:22.604628Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17679133,
    events_root: None,
}
2023-01-26T07:17:22.604646Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:17:22.604650Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAndGasInsideCreateWithMemExpandingCalls"::London::0
2023-01-26T07:17:22.604653Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CreateAndGasInsideCreateWithMemExpandingCalls.json"
2023-01-26T07:17:22.604656Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:22.604658Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [255, 21, 28, 98, 28, 208, 17, 227, 83, 250, 27, 226, 175, 63, 240, 37, 110, 106, 80, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-26T07:17:22.605380Z  INFO evm_eth_compliance::statetest::runner: UC : "CreateAndGasInsideCreateWithMemExpandingCalls"
2023-01-26T07:17:22.605386Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15923096,
    events_root: None,
}
2023-01-26T07:17:22.605408Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:17:22.605412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAndGasInsideCreateWithMemExpandingCalls"::Merge::0
2023-01-26T07:17:22.605415Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/CreateAndGasInsideCreateWithMemExpandingCalls.json"
2023-01-26T07:17:22.605420Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:22.605422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [193, 57, 143, 218, 62, 130, 66, 171, 177, 232, 76, 26, 147, 222, 134, 195, 94, 69, 115, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-26T07:17:22.606235Z  INFO evm_eth_compliance::statetest::runner: UC : "CreateAndGasInsideCreateWithMemExpandingCalls"
2023-01-26T07:17:22.606241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16217248,
    events_root: None,
}
2023-01-26T07:17:22.608036Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:645.398532ms
2023-01-26T07:17:22.877247Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/DelegateCallOnEIPWithMemExpandingCalls.json", Total Files :: 1
2023-01-26T07:17:22.930044Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:17:22.930244Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:22.930247Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:17:22.930302Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:22.930304Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:17:22.930361Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:22.930432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:17:22.930435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegateCallOnEIPWithMemExpandingCalls"::Istanbul::0
2023-01-26T07:17:22.930439Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/DelegateCallOnEIPWithMemExpandingCalls.json"
2023-01-26T07:17:22.930442Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:22.930443Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:23.335719Z  INFO evm_eth_compliance::statetest::runner: UC : "DelegateCallOnEIPWithMemExpandingCalls"
2023-01-26T07:17:23.335736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4161612,
    events_root: None,
}
2023-01-26T07:17:23.335749Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:17:23.335757Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegateCallOnEIPWithMemExpandingCalls"::Berlin::0
2023-01-26T07:17:23.335759Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/DelegateCallOnEIPWithMemExpandingCalls.json"
2023-01-26T07:17:23.335763Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:23.335765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:23.336027Z  INFO evm_eth_compliance::statetest::runner: UC : "DelegateCallOnEIPWithMemExpandingCalls"
2023-01-26T07:17:23.336032Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4180996,
    events_root: None,
}
2023-01-26T07:17:23.336042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:17:23.336045Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegateCallOnEIPWithMemExpandingCalls"::London::0
2023-01-26T07:17:23.336048Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/DelegateCallOnEIPWithMemExpandingCalls.json"
2023-01-26T07:17:23.336052Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:23.336054Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:23.336287Z  INFO evm_eth_compliance::statetest::runner: UC : "DelegateCallOnEIPWithMemExpandingCalls"
2023-01-26T07:17:23.336292Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3252766,
    events_root: None,
}
2023-01-26T07:17:23.336300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:17:23.336304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "DelegateCallOnEIPWithMemExpandingCalls"::Merge::0
2023-01-26T07:17:23.336306Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/DelegateCallOnEIPWithMemExpandingCalls.json"
2023-01-26T07:17:23.336310Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:23.336313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:23.336547Z  INFO evm_eth_compliance::statetest::runner: UC : "DelegateCallOnEIPWithMemExpandingCalls"
2023-01-26T07:17:23.336553Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3252766,
    events_root: None,
}
2023-01-26T07:17:23.338140Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:406.523412ms
2023-01-26T07:17:23.613348Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls.json", Total Files :: 1
2023-01-26T07:17:23.643157Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:17:23.643358Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:23.643362Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:17:23.643417Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:23.643420Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:17:23.643478Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:23.643551Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:17:23.643554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls"::Istanbul::0
2023-01-26T07:17:23.643557Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:23.643562Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:23.643563Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:23.986480Z  INFO evm_eth_compliance::statetest::runner: UC : "ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:23.986497Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2325230,
    events_root: None,
}
2023-01-26T07:17:23.986508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:17:23.986514Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls"::Berlin::0
2023-01-26T07:17:23.986516Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:23.986520Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:23.986521Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:23.986697Z  INFO evm_eth_compliance::statetest::runner: UC : "ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:23.986702Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2325230,
    events_root: None,
}
2023-01-26T07:17:23.986708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:17:23.986712Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls"::London::0
2023-01-26T07:17:23.986715Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:23.986719Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:23.986720Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:23.986882Z  INFO evm_eth_compliance::statetest::runner: UC : "ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:23.986887Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2325230,
    events_root: None,
}
2023-01-26T07:17:23.986893Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:17:23.986896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls"::Merge::0
2023-01-26T07:17:23.986898Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls.json"
2023-01-26T07:17:23.986901Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:23.986903Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:23.987061Z  INFO evm_eth_compliance::statetest::runner: UC : "ExecuteCallThatAskMoreGasThenTransactionHasWithMemExpandingCalls"
2023-01-26T07:17:23.987066Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2325230,
    events_root: None,
}
2023-01-26T07:17:23.988787Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:343.919716ms
2023-01-26T07:17:24.246241Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/NewGasPriceForCodesWithMemExpandingCalls.json", Total Files :: 1
2023-01-26T07:17:24.286410Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:17:24.286605Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:24.286609Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:17:24.286659Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:24.286662Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:17:24.286721Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:24.286723Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T07:17:24.286776Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:24.286846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:17:24.286849Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NewGasPriceForCodesWithMemExpandingCalls"::Istanbul::0
2023-01-26T07:17:24.286852Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/NewGasPriceForCodesWithMemExpandingCalls.json"
2023-01-26T07:17:24.286855Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:24.286857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:24.624413Z  INFO evm_eth_compliance::statetest::runner: UC : "NewGasPriceForCodesWithMemExpandingCalls"
2023-01-26T07:17:24.624430Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 6888526,
    events_root: None,
}
2023-01-26T07:17:24.624437Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=137): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T07:17:24.624460Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:17:24.624468Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NewGasPriceForCodesWithMemExpandingCalls"::Berlin::0
2023-01-26T07:17:24.624471Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/NewGasPriceForCodesWithMemExpandingCalls.json"
2023-01-26T07:17:24.624476Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:24.624478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:24.624805Z  INFO evm_eth_compliance::statetest::runner: UC : "NewGasPriceForCodesWithMemExpandingCalls"
2023-01-26T07:17:24.624812Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 6888526,
    events_root: None,
}
2023-01-26T07:17:24.624816Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=137): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T07:17:24.624833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:17:24.624837Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NewGasPriceForCodesWithMemExpandingCalls"::London::0
2023-01-26T07:17:24.624841Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/NewGasPriceForCodesWithMemExpandingCalls.json"
2023-01-26T07:17:24.624845Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:24.624847Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:24.625175Z  INFO evm_eth_compliance::statetest::runner: UC : "NewGasPriceForCodesWithMemExpandingCalls"
2023-01-26T07:17:24.625180Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 6888526,
    events_root: None,
}
2023-01-26T07:17:24.625184Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=137): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T07:17:24.625201Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:17:24.625205Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "NewGasPriceForCodesWithMemExpandingCalls"::Merge::0
2023-01-26T07:17:24.625208Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/NewGasPriceForCodesWithMemExpandingCalls.json"
2023-01-26T07:17:24.625212Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:17:24.625214Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:24.625534Z  INFO evm_eth_compliance::statetest::runner: UC : "NewGasPriceForCodesWithMemExpandingCalls"
2023-01-26T07:17:24.625540Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 6888526,
    events_root: None,
}
2023-01-26T07:17:24.625544Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=137): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T07:17:24.627070Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:339.155959ms
2023-01-26T07:17:24.892296Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json", Total Files :: 1
2023-01-26T07:17:24.940171Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:17:24.940370Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:24.940374Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:17:24.940430Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:24.940432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:17:24.940491Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:24.940493Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T07:17:24.940548Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:17:24.940618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-26T07:17:24.940621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::Istanbul::2
2023-01-26T07:17:24.940624Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:24.940628Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:24.940629Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.303303Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.303321Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2673248,
    events_root: None,
}
2023-01-26T07:17:25.303334Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-26T07:17:25.303340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::Istanbul::3
2023-01-26T07:17:25.303342Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.303345Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.303346Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.303478Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.303483Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773874,
    events_root: None,
}
2023-01-26T07:17:25.303488Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-26T07:17:25.303491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::Istanbul::4
2023-01-26T07:17:25.303493Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.303496Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.303497Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.303627Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.303631Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773853,
    events_root: None,
}
2023-01-26T07:17:25.303637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-26T07:17:25.303639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::Istanbul::5
2023-01-26T07:17:25.303641Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.303643Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.303645Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.303760Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.303765Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773853,
    events_root: None,
}
2023-01-26T07:17:25.303770Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:17:25.303772Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::Istanbul::0
2023-01-26T07:17:25.303774Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.303777Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.303778Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.303892Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.303896Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773891,
    events_root: None,
}
2023-01-26T07:17:25.303901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T07:17:25.303903Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::Istanbul::1
2023-01-26T07:17:25.303905Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.303908Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.303909Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.304022Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.304026Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773891,
    events_root: None,
}
2023-01-26T07:17:25.304033Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:17:25.304036Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::Berlin::0
2023-01-26T07:17:25.304037Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.304040Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.304041Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.304155Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.304159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773891,
    events_root: None,
}
2023-01-26T07:17:25.304164Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T07:17:25.304167Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::Berlin::1
2023-01-26T07:17:25.304168Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.304171Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.304172Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.304285Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.304289Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773891,
    events_root: None,
}
2023-01-26T07:17:25.304295Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:17:25.304297Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::London::0
2023-01-26T07:17:25.304299Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.304301Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.304303Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.304415Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.304420Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773891,
    events_root: None,
}
2023-01-26T07:17:25.304424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T07:17:25.304427Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::London::1
2023-01-26T07:17:25.304429Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.304431Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.304433Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.304547Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.304552Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773891,
    events_root: None,
}
2023-01-26T07:17:25.304557Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:17:25.304560Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::Merge::0
2023-01-26T07:17:25.304562Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.304564Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.304566Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.304682Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.304686Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773891,
    events_root: None,
}
2023-01-26T07:17:25.304691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T07:17:25.304694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "OOGinReturn"::Merge::1
2023-01-26T07:17:25.304695Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stMemExpandingEIP150Calls/OOGinReturn.json"
2023-01-26T07:17:25.304698Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-26T07:17:25.304699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:17:25.304812Z  INFO evm_eth_compliance::statetest::runner: UC : "OOGinReturn"
2023-01-26T07:17:25.304816Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1773891,
    events_root: None,
}
2023-01-26T07:17:25.306393Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.65561ms
```