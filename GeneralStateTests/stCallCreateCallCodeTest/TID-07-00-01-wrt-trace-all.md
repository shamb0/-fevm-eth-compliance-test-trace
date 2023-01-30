> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-cases are failed

- Following use-cases are skipped due to `transaction.to` is empty

| Test ID | Use-Case |
| --- | --- |
| TID-07-27 | contractCreationMakeCallThatAskMoreGasThenTransactionProvided |
| TID-07-38 | createJS_ExampleContract |
| TID-07-39 | createJS_NoCollision |
| TID-07-41 | createNameRegistratorPerTxs |
| TID-07-42 | createNameRegistratorPerTxsNotEnoughGas |

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-07-04 | Callcode1024BalanceTooLow |
| TID-07-05 | Callcode1024OOG |
| TID-07-06 | CallcodeLoseGasOOG |
| TID-07-07 | callcodeOutput1 |
| TID-07-08 | callcodeOutput2 |
| TID-07-09 | callcodeOutput3 |
| TID-07-10 | callcodeOutput3Fail |
| TID-07-11 | callcodeOutput3partial |
| TID-07-12 | callcodeOutput3partialFail |
| TID-07-13 | callcodeWithHighValue |
| TID-07-14 | callcodeWithHighValueAndGasOOG |

> Execution Trace

```
2023-01-26T16:35:01.564633Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024BalanceTooLow.json", Total Files :: 1
2023-01-26T16:35:01.859707Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:01.859852Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:01.859856Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:01.859909Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:01.859912Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:01.859971Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:01.860047Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:01.860051Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024BalanceTooLow"::Istanbul::0
2023-01-26T16:35:01.860055Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024BalanceTooLow.json"
2023-01-26T16:35:01.860060Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:01.860062Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:02.385495Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024BalanceTooLow"
2023-01-26T16:35:02.385511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2511743549,
    events_root: None,
}
2023-01-26T16:35:02.389415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:02.389428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024BalanceTooLow"::Berlin::0
2023-01-26T16:35:02.389430Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024BalanceTooLow.json"
2023-01-26T16:35:02.389434Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:02.389435Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:02.445502Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024BalanceTooLow"
2023-01-26T16:35:02.445516Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1323894643,
    events_root: None,
}
2023-01-26T16:35:02.447368Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:02.447376Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024BalanceTooLow"::London::0
2023-01-26T16:35:02.447378Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024BalanceTooLow.json"
2023-01-26T16:35:02.447382Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:02.447383Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:02.447717Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024BalanceTooLow"
2023-01-26T16:35:02.447722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4656501,
    events_root: None,
}
2023-01-26T16:35:02.447732Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:02.447734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024BalanceTooLow"::Merge::0
2023-01-26T16:35:02.447736Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024BalanceTooLow.json"
2023-01-26T16:35:02.447739Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:02.447740Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:02.447869Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024BalanceTooLow"
2023-01-26T16:35:02.447873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2685702,
    events_root: None,
}
2023-01-26T16:35:02.458136Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:588.179222ms
2023-01-26T16:35:02.721312Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json", Total Files :: 1
2023-01-26T16:35:02.783828Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:02.783971Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:02.783974Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:02.784023Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:02.784025Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:02.784080Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:02.784151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:02.784153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Istanbul::0
2023-01-26T16:35:02.784156Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:02.784160Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:02.784161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.324072Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.324089Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3820495154,
    events_root: None,
}
2023-01-26T16:35:03.329669Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:03.329684Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Istanbul::0
2023-01-26T16:35:03.329687Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.329691Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.329692Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.333339Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.333349Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6054983,
    events_root: None,
}
2023-01-26T16:35:03.333364Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:03.333367Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Istanbul::0
2023-01-26T16:35:03.333370Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.333373Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.333374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.333577Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.333582Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.333589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:03.333591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Istanbul::0
2023-01-26T16:35:03.333593Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.333596Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.333597Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.333778Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.333783Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.333789Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:03.333791Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Berlin::0
2023-01-26T16:35:03.333793Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.333796Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.333797Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.333975Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.333980Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.333986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:03.333989Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Berlin::0
2023-01-26T16:35:03.333990Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.333993Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.333994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.334173Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.334178Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.334184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:03.334186Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Berlin::0
2023-01-26T16:35:03.334188Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.334191Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.334192Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.334376Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.334380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.334386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:03.334388Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Berlin::0
2023-01-26T16:35:03.334390Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.334392Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.334394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.334572Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.334576Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.334582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:03.334585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::London::0
2023-01-26T16:35:03.334586Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.334589Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.334590Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.334790Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.334795Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.334802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:03.334805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::London::0
2023-01-26T16:35:03.334807Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.334811Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.334813Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.335096Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.335102Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.335111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:03.335114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::London::0
2023-01-26T16:35:03.335117Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.335121Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.335123Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.335358Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.335363Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.335370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:03.335372Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::London::0
2023-01-26T16:35:03.335373Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.335376Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.335377Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.335568Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.335572Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.335579Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:03.335581Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Merge::0
2023-01-26T16:35:03.335582Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.335585Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.335586Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.335766Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.335771Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.335778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:03.335780Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Merge::0
2023-01-26T16:35:03.335781Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.335784Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.335785Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.335963Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.335967Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.335974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:03.335976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Merge::0
2023-01-26T16:35:03.335977Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.335980Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.335981Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.336159Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.336163Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.336170Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:03.336172Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Merge::0
2023-01-26T16:35:03.336174Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-26T16:35:03.336176Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.336177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:03.336356Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024OOG"
2023-01-26T16:35:03.336360Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5323711,
    events_root: None,
}
2023-01-26T16:35:03.348590Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:552.545881ms
2023-01-26T16:35:03.627110Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024PreCalls.json", Total Files :: 1
2023-01-26T16:35:03.661368Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:03.661522Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:03.661526Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:03.661577Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:03.661579Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:03.661631Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:03.661703Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:03.661705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Istanbul::0
2023-01-26T16:35:03.661708Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024PreCalls.json"
2023-01-26T16:35:03.661712Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:03.661714Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:04.152090Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T16:35:04.152104Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2813490204,
    events_root: None,
}
2023-01-26T16:35:04.156616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:04.156629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Istanbul::0
2023-01-26T16:35:04.156631Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024PreCalls.json"
2023-01-26T16:35:04.156635Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:04.156637Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:04.311738Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T16:35:04.311754Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510725835,
    events_root: None,
}
2023-01-26T16:35:04.318155Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:04.318167Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Berlin::0
2023-01-26T16:35:04.318169Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024PreCalls.json"
2023-01-26T16:35:04.318173Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:04.318174Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:04.461433Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T16:35:04.461447Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510725467,
    events_root: None,
}
2023-01-26T16:35:04.468246Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:04.468258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Berlin::0
2023-01-26T16:35:04.468260Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024PreCalls.json"
2023-01-26T16:35:04.468264Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:04.468265Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:04.617030Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T16:35:04.617045Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510725467,
    events_root: None,
}
2023-01-26T16:35:04.624133Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:04.624146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::London::0
2023-01-26T16:35:04.624149Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024PreCalls.json"
2023-01-26T16:35:04.624152Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:04.624154Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:04.776069Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T16:35:04.776084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510725559,
    events_root: None,
}
2023-01-26T16:35:04.783215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:04.783227Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::London::0
2023-01-26T16:35:04.783229Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024PreCalls.json"
2023-01-26T16:35:04.783233Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:04.783234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:04.933740Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T16:35:04.933759Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510725559,
    events_root: None,
}
2023-01-26T16:35:04.941792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:04.941810Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Merge::0
2023-01-26T16:35:04.941814Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024PreCalls.json"
2023-01-26T16:35:04.941817Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:04.941818Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:05.105304Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T16:35:05.105319Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510725559,
    events_root: None,
}
2023-01-26T16:35:05.113328Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:05.113343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024PreCalls"::Merge::0
2023-01-26T16:35:05.113345Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024PreCalls.json"
2023-01-26T16:35:05.113350Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:05.113352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:05.280130Z  INFO evm_eth_compliance::statetest::runner: UC : "Call1024PreCalls"
2023-01-26T16:35:05.280151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3510725375,
    events_root: None,
}
2023-01-26T16:35:05.312178Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:1.631784153s
2023-01-26T16:35:05.569733Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json", Total Files :: 1
2023-01-26T16:35:05.600160Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:05.600301Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:05.600305Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:05.600354Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:05.600357Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:05.600413Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:05.600486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:05.600489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::Istanbul::0
2023-01-26T16:35:05.600491Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json"
2023-01-26T16:35:05.600495Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:05.600496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:05.958102Z  INFO evm_eth_compliance::statetest::runner: UC : "CallLoseGasOOG"
2023-01-26T16:35:05.958120Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4332487,
    events_root: None,
}
2023-01-26T16:35:05.958132Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:05.958137Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::Berlin::0
2023-01-26T16:35:05.958138Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json"
2023-01-26T16:35:05.958142Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:05.958143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:05.958397Z  INFO evm_eth_compliance::statetest::runner: UC : "CallLoseGasOOG"
2023-01-26T16:35:05.958402Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5497943,
    events_root: None,
}
2023-01-26T16:35:05.958411Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:05.958413Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::London::0
2023-01-26T16:35:05.958414Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json"
2023-01-26T16:35:05.958418Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:05.958419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:05.958616Z  INFO evm_eth_compliance::statetest::runner: UC : "CallLoseGasOOG"
2023-01-26T16:35:05.958621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5597943,
    events_root: None,
}
2023-01-26T16:35:05.958629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:05.958632Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::Merge::0
2023-01-26T16:35:05.958634Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json"
2023-01-26T16:35:05.958637Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:05.958639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:05.958841Z  INFO evm_eth_compliance::statetest::runner: UC : "CallLoseGasOOG"
2023-01-26T16:35:05.958846Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5697943,
    events_root: None,
}
2023-01-26T16:35:05.960526Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:358.697279ms
2023-01-26T16:35:06.250583Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallRecursiveBombPreCall.json", Total Files :: 1
2023-01-26T16:35:06.308981Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:06.309132Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:06.309136Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:06.309192Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:06.309195Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:06.309256Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:06.309328Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:06.309331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombPreCall"::Istanbul::0
2023-01-26T16:35:06.309333Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallRecursiveBombPreCall.json"
2023-01-26T16:35:06.309337Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:06.309338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:06.802115Z  INFO evm_eth_compliance::statetest::runner: UC : "CallRecursiveBombPreCall"
2023-01-26T16:35:06.802134Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368042823,
    events_root: None,
}
2023-01-26T16:35:06.807688Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:06.807705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombPreCall"::Berlin::0
2023-01-26T16:35:06.807707Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallRecursiveBombPreCall.json"
2023-01-26T16:35:06.807711Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:06.807712Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:06.991802Z  INFO evm_eth_compliance::statetest::runner: UC : "CallRecursiveBombPreCall"
2023-01-26T16:35:06.991816Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4303857684,
    events_root: None,
}
2023-01-26T16:35:06.997994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:06.998011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombPreCall"::London::0
2023-01-26T16:35:06.998014Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallRecursiveBombPreCall.json"
2023-01-26T16:35:06.998017Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:06.998018Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:07.187205Z  INFO evm_eth_compliance::statetest::runner: UC : "CallRecursiveBombPreCall"
2023-01-26T16:35:07.187220Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4303857500,
    events_root: None,
}
2023-01-26T16:35:07.196424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:07.196437Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombPreCall"::Merge::0
2023-01-26T16:35:07.196439Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallRecursiveBombPreCall.json"
2023-01-26T16:35:07.196442Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:07.196444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:07.359405Z  INFO evm_eth_compliance::statetest::runner: UC : "CallRecursiveBombPreCall"
2023-01-26T16:35:07.359418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4303857592,
    events_root: None,
}
2023-01-26T16:35:07.383676Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:1.059768745s
2023-01-26T16:35:07.652000Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024BalanceTooLow.json", Total Files :: 1
2023-01-26T16:35:07.680875Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:07.681020Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:07.681024Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:07.681072Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:07.681074Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:07.681130Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:07.681204Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:07.681207Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024BalanceTooLow"::Istanbul::0
2023-01-26T16:35:07.681210Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024BalanceTooLow.json"
2023-01-26T16:35:07.681213Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:07.681214Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.026287Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024BalanceTooLow"
2023-01-26T16:35:08.026304Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1569591,
    events_root: None,
}
2023-01-26T16:35:08.026310Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=48): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.026324Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:08.026328Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024BalanceTooLow"::Berlin::0
2023-01-26T16:35:08.026330Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024BalanceTooLow.json"
2023-01-26T16:35:08.026334Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.026335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.026469Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024BalanceTooLow"
2023-01-26T16:35:08.026474Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1569591,
    events_root: None,
}
2023-01-26T16:35:08.026477Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=48): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.026486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:08.026488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024BalanceTooLow"::London::0
2023-01-26T16:35:08.026490Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024BalanceTooLow.json"
2023-01-26T16:35:08.026493Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.026494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.026598Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024BalanceTooLow"
2023-01-26T16:35:08.026602Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1569591,
    events_root: None,
}
2023-01-26T16:35:08.026605Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=48): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.026614Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:08.026617Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024BalanceTooLow"::Merge::0
2023-01-26T16:35:08.026618Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024BalanceTooLow.json"
2023-01-26T16:35:08.026621Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.026622Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.026712Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024BalanceTooLow"
2023-01-26T16:35:08.026716Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1569591,
    events_root: None,
}
2023-01-26T16:35:08.026719Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=48): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.028195Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:345.857013ms
2023-01-26T16:35:08.312316Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024OOG.json", Total Files :: 1
2023-01-26T16:35:08.371601Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:08.371746Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:08.371751Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:08.371802Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:08.371803Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:08.371863Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:08.371938Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:08.371940Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024OOG"::Istanbul::0
2023-01-26T16:35:08.371944Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024OOG.json"
2023-01-26T16:35:08.371948Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.371949Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.728083Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024OOG"
2023-01-26T16:35:08.728101Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1594281,
    events_root: None,
}
2023-01-26T16:35:08.728108Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=56): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.728122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:08.728126Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024OOG"::Istanbul::0
2023-01-26T16:35:08.728128Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024OOG.json"
2023-01-26T16:35:08.728131Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.728132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.728270Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024OOG"
2023-01-26T16:35:08.728275Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1594281,
    events_root: None,
}
2023-01-26T16:35:08.728278Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=56): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.728291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:08.728294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024OOG"::Berlin::0
2023-01-26T16:35:08.728296Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024OOG.json"
2023-01-26T16:35:08.728300Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.728302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.728415Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024OOG"
2023-01-26T16:35:08.728419Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1594281,
    events_root: None,
}
2023-01-26T16:35:08.728422Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=56): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.728431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:08.728433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024OOG"::Berlin::0
2023-01-26T16:35:08.728435Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024OOG.json"
2023-01-26T16:35:08.728437Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.728439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.728531Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024OOG"
2023-01-26T16:35:08.728536Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1594281,
    events_root: None,
}
2023-01-26T16:35:08.728540Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=56): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.728549Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:08.728551Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024OOG"::London::0
2023-01-26T16:35:08.728553Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024OOG.json"
2023-01-26T16:35:08.728555Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.728556Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.728647Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024OOG"
2023-01-26T16:35:08.728653Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1594281,
    events_root: None,
}
2023-01-26T16:35:08.728656Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=56): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.728664Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:08.728666Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024OOG"::London::0
2023-01-26T16:35:08.728668Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024OOG.json"
2023-01-26T16:35:08.728670Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.728671Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.728761Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024OOG"
2023-01-26T16:35:08.728765Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1594281,
    events_root: None,
}
2023-01-26T16:35:08.728768Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=56): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.728777Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:08.728779Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024OOG"::Merge::0
2023-01-26T16:35:08.728781Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024OOG.json"
2023-01-26T16:35:08.728783Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.728784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.728884Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024OOG"
2023-01-26T16:35:08.728889Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1594281,
    events_root: None,
}
2023-01-26T16:35:08.728894Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=56): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.728905Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:08.728907Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Callcode1024OOG"::Merge::0
2023-01-26T16:35:08.728909Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Callcode1024OOG.json"
2023-01-26T16:35:08.728913Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:08.728915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:08.729010Z  INFO evm_eth_compliance::statetest::runner: UC : "Callcode1024OOG"
2023-01-26T16:35:08.729014Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1594281,
    events_root: None,
}
2023-01-26T16:35:08.729018Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=56): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:08.730656Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.430319ms
2023-01-26T16:35:08.990837Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallcodeLoseGasOOG.json", Total Files :: 1
2023-01-26T16:35:09.021809Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:09.021986Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:09.021992Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:09.022059Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:09.022063Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:09.022134Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:09.022228Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:09.022232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Istanbul::0
2023-01-26T16:35:09.022236Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallcodeLoseGasOOG.json"
2023-01-26T16:35:09.022240Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:09.022242Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:09.404885Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T16:35:09.404902Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1576281,
    events_root: None,
}
2023-01-26T16:35:09.404909Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=51): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:09.404922Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:09.404926Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Istanbul::0
2023-01-26T16:35:09.404928Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallcodeLoseGasOOG.json"
2023-01-26T16:35:09.404931Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:09.404932Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:09.405077Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T16:35:09.405082Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1576281,
    events_root: None,
}
2023-01-26T16:35:09.405085Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=51): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:09.405094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:09.405096Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Berlin::0
2023-01-26T16:35:09.405098Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallcodeLoseGasOOG.json"
2023-01-26T16:35:09.405100Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:09.405101Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:09.405210Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T16:35:09.405217Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1576281,
    events_root: None,
}
2023-01-26T16:35:09.405220Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=51): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:09.405233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:09.405235Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Berlin::0
2023-01-26T16:35:09.405237Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallcodeLoseGasOOG.json"
2023-01-26T16:35:09.405240Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:09.405242Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:09.405356Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T16:35:09.405361Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1576281,
    events_root: None,
}
2023-01-26T16:35:09.405364Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=51): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:09.405372Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:09.405374Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::London::0
2023-01-26T16:35:09.405376Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallcodeLoseGasOOG.json"
2023-01-26T16:35:09.405379Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:09.405381Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:09.405487Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T16:35:09.405492Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1576281,
    events_root: None,
}
2023-01-26T16:35:09.405494Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=51): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:09.405503Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:09.405505Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::London::0
2023-01-26T16:35:09.405507Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallcodeLoseGasOOG.json"
2023-01-26T16:35:09.405511Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:09.405512Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:09.405606Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T16:35:09.405610Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1576281,
    events_root: None,
}
2023-01-26T16:35:09.405613Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=51): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:09.405621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:09.405624Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Merge::0
2023-01-26T16:35:09.405626Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallcodeLoseGasOOG.json"
2023-01-26T16:35:09.405628Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:09.405631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:09.405723Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T16:35:09.405727Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1576281,
    events_root: None,
}
2023-01-26T16:35:09.405730Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=51): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:09.405738Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:09.405740Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Merge::0
2023-01-26T16:35:09.405741Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallcodeLoseGasOOG.json"
2023-01-26T16:35:09.405744Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:09.405746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:09.405854Z  INFO evm_eth_compliance::statetest::runner: UC : "CallcodeLoseGasOOG"
2023-01-26T16:35:09.405858Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1576281,
    events_root: None,
}
2023-01-26T16:35:09.405861Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=51): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:09.407423Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:384.067924ms
2023-01-26T16:35:09.683404Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput1.json", Total Files :: 1
2023-01-26T16:35:09.759923Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:09.760063Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:09.760067Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:09.760123Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:09.760125Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:09.760185Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:09.760258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:09.760261Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput1"::Istanbul::0
2023-01-26T16:35:09.760264Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput1.json"
2023-01-26T16:35:09.760267Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:09.760268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:10.110055Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput1"
2023-01-26T16:35:10.110068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2835941,
    events_root: None,
}
2023-01-26T16:35:10.110080Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:10.110085Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput1"::Berlin::0
2023-01-26T16:35:10.110087Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput1.json"
2023-01-26T16:35:10.110091Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:10.110093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:10.110230Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput1"
2023-01-26T16:35:10.110235Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1894331,
    events_root: None,
}
2023-01-26T16:35:10.110241Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:10.110244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput1"::London::0
2023-01-26T16:35:10.110247Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput1.json"
2023-01-26T16:35:10.110250Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:10.110252Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:10.110374Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput1"
2023-01-26T16:35:10.110378Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1894331,
    events_root: None,
}
2023-01-26T16:35:10.110385Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:10.110388Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput1"::Merge::0
2023-01-26T16:35:10.110391Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput1.json"
2023-01-26T16:35:10.110394Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:10.110396Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:10.110539Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput1"
2023-01-26T16:35:10.110543Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1894331,
    events_root: None,
}
2023-01-26T16:35:10.112202Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:350.632084ms
2023-01-26T16:35:10.375868Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput2.json", Total Files :: 1
2023-01-26T16:35:10.439509Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:10.439650Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:10.439654Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:10.439726Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:10.439730Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:10.439812Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:10.439925Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:10.439928Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput2"::Istanbul::0
2023-01-26T16:35:10.439931Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput2.json"
2023-01-26T16:35:10.439934Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:10.439935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:10.769450Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput2"
2023-01-26T16:35:10.769465Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2852786,
    events_root: None,
}
2023-01-26T16:35:10.769483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:10.769487Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput2"::Berlin::0
2023-01-26T16:35:10.769489Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput2.json"
2023-01-26T16:35:10.769492Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:10.769493Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:10.769623Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput2"
2023-01-26T16:35:10.769628Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1910139,
    events_root: None,
}
2023-01-26T16:35:10.769633Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:10.769635Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput2"::London::0
2023-01-26T16:35:10.769637Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput2.json"
2023-01-26T16:35:10.769640Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:10.769641Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:10.769750Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput2"
2023-01-26T16:35:10.769754Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1910139,
    events_root: None,
}
2023-01-26T16:35:10.769759Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:10.769761Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput2"::Merge::0
2023-01-26T16:35:10.769763Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput2.json"
2023-01-26T16:35:10.769765Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:10.769767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:10.769897Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput2"
2023-01-26T16:35:10.769901Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1910139,
    events_root: None,
}
2023-01-26T16:35:10.771503Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:330.402703ms
2023-01-26T16:35:11.039823Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3.json", Total Files :: 1
2023-01-26T16:35:11.080647Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:11.080786Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:11.080790Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:11.080843Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:11.080845Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:11.080902Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:11.080974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:11.080977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3"::Istanbul::0
2023-01-26T16:35:11.080980Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3.json"
2023-01-26T16:35:11.080984Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:11.080985Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:11.440916Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3"
2023-01-26T16:35:11.440933Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2836325,
    events_root: None,
}
2023-01-26T16:35:11.440947Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:11.440951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3"::Berlin::0
2023-01-26T16:35:11.440953Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3.json"
2023-01-26T16:35:11.440957Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:11.440959Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:11.441121Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3"
2023-01-26T16:35:11.441127Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1894715,
    events_root: None,
}
2023-01-26T16:35:11.441134Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:11.441137Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3"::London::0
2023-01-26T16:35:11.441139Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3.json"
2023-01-26T16:35:11.441142Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:11.441144Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:11.441294Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3"
2023-01-26T16:35:11.441300Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1894715,
    events_root: None,
}
2023-01-26T16:35:11.441306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:11.441309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3"::Merge::0
2023-01-26T16:35:11.441311Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3.json"
2023-01-26T16:35:11.441314Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:11.441316Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:11.441500Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3"
2023-01-26T16:35:11.441517Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1894715,
    events_root: None,
}
2023-01-26T16:35:11.443356Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:360.890118ms
2023-01-26T16:35:11.710591Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3Fail.json", Total Files :: 1
2023-01-26T16:35:11.740692Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:11.740829Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:11.740832Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:11.740886Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:11.740889Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:11.740946Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:11.741017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:11.741020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3Fail"::Istanbul::0
2023-01-26T16:35:11.741023Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3Fail.json"
2023-01-26T16:35:11.741027Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:11.741028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:12.085875Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3Fail"
2023-01-26T16:35:12.085893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2736391,
    events_root: None,
}
2023-01-26T16:35:12.085905Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:12.085910Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3Fail"::Berlin::0
2023-01-26T16:35:12.085911Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3Fail.json"
2023-01-26T16:35:12.085915Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:12.085916Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:12.086053Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3Fail"
2023-01-26T16:35:12.086058Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1794780,
    events_root: None,
}
2023-01-26T16:35:12.086063Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:12.086065Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3Fail"::London::0
2023-01-26T16:35:12.086067Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3Fail.json"
2023-01-26T16:35:12.086070Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:12.086071Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:12.086187Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3Fail"
2023-01-26T16:35:12.086191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1794780,
    events_root: None,
}
2023-01-26T16:35:12.086196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:12.086198Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3Fail"::Merge::0
2023-01-26T16:35:12.086200Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3Fail.json"
2023-01-26T16:35:12.086203Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:12.086204Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:12.086319Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3Fail"
2023-01-26T16:35:12.086323Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1794780,
    events_root: None,
}
2023-01-26T16:35:12.088012Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:345.641516ms
2023-01-26T16:35:12.365520Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3partial.json", Total Files :: 1
2023-01-26T16:35:12.396625Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:12.396766Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:12.396770Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:12.396824Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:12.396826Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:12.396886Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:12.396960Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:12.396964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partial"::Istanbul::0
2023-01-26T16:35:12.396967Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3partial.json"
2023-01-26T16:35:12.396970Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:12.396972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:12.763412Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partial"
2023-01-26T16:35:12.763428Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2836325,
    events_root: None,
}
2023-01-26T16:35:12.763439Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:12.763443Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partial"::Berlin::0
2023-01-26T16:35:12.763445Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3partial.json"
2023-01-26T16:35:12.763449Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:12.763451Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:12.763584Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partial"
2023-01-26T16:35:12.763588Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1894715,
    events_root: None,
}
2023-01-26T16:35:12.763594Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:12.763596Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partial"::London::0
2023-01-26T16:35:12.763598Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3partial.json"
2023-01-26T16:35:12.763600Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:12.763602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:12.763719Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partial"
2023-01-26T16:35:12.763723Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1894715,
    events_root: None,
}
2023-01-26T16:35:12.763730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:12.763732Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partial"::Merge::0
2023-01-26T16:35:12.763734Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3partial.json"
2023-01-26T16:35:12.763737Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:12.763738Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:12.763858Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partial"
2023-01-26T16:35:12.763862Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1894715,
    events_root: None,
}
2023-01-26T16:35:12.765345Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.247597ms
2023-01-26T16:35:13.049679Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3partialFail.json", Total Files :: 1
2023-01-26T16:35:13.086689Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:13.086832Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:13.086837Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:13.086892Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:13.086896Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:13.086957Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:13.087032Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:13.087035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partialFail"::Istanbul::0
2023-01-26T16:35:13.087037Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3partialFail.json"
2023-01-26T16:35:13.087041Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:13.087043Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:13.438879Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partialFail"
2023-01-26T16:35:13.438893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2736391,
    events_root: None,
}
2023-01-26T16:35:13.438904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:13.438908Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partialFail"::Berlin::0
2023-01-26T16:35:13.438910Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3partialFail.json"
2023-01-26T16:35:13.438913Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:13.438914Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:13.439044Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partialFail"
2023-01-26T16:35:13.439049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1794780,
    events_root: None,
}
2023-01-26T16:35:13.439054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:13.439056Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partialFail"::London::0
2023-01-26T16:35:13.439058Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3partialFail.json"
2023-01-26T16:35:13.439061Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:13.439063Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:13.439172Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partialFail"
2023-01-26T16:35:13.439176Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1794780,
    events_root: None,
}
2023-01-26T16:35:13.439181Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:13.439183Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callOutput3partialFail"::Merge::0
2023-01-26T16:35:13.439185Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callOutput3partialFail.json"
2023-01-26T16:35:13.439188Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:13.439189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:13.439301Z  INFO evm_eth_compliance::statetest::runner: UC : "callOutput3partialFail"
2023-01-26T16:35:13.439305Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1794780,
    events_root: None,
}
2023-01-26T16:35:13.440736Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.626962ms
2023-01-26T16:35:13.711327Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValue.json", Total Files :: 1
2023-01-26T16:35:13.752312Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:13.752485Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:13.752490Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:13.752559Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:13.752563Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:13.752633Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:13.752715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:13.752719Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValue"::Istanbul::0
2023-01-26T16:35:13.752722Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValue.json"
2023-01-26T16:35:13.752727Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:13.752729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.109443Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValue"
2023-01-26T16:35:14.109462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1732458,
    events_root: None,
}
2023-01-26T16:35:14.109486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:14.109491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValue"::Berlin::0
2023-01-26T16:35:14.109493Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValue.json"
2023-01-26T16:35:14.109498Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.109500Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.109629Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValue"
2023-01-26T16:35:14.109634Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1732458,
    events_root: None,
}
2023-01-26T16:35:14.109640Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:14.109643Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValue"::London::0
2023-01-26T16:35:14.109644Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValue.json"
2023-01-26T16:35:14.109647Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.109648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.109803Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValue"
2023-01-26T16:35:14.109808Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1732458,
    events_root: None,
}
2023-01-26T16:35:14.109814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:14.109816Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValue"::Merge::0
2023-01-26T16:35:14.109818Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValue.json"
2023-01-26T16:35:14.109820Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.109821Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.109934Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValue"
2023-01-26T16:35:14.109957Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1732458,
    events_root: None,
}
2023-01-26T16:35:14.111795Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.658879ms
2023-01-26T16:35:14.387579Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndGasOOG.json", Total Files :: 1
2023-01-26T16:35:14.429328Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:14.429478Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:14.429482Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:14.429537Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:14.429539Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:14.429601Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:14.429676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:14.429679Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::Istanbul::0
2023-01-26T16:35:14.429682Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndGasOOG.json"
2023-01-26T16:35:14.429686Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.429687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.806755Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T16:35:14.806771Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723425,
    events_root: None,
}
2023-01-26T16:35:14.806783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:14.806787Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::Istanbul::0
2023-01-26T16:35:14.806788Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndGasOOG.json"
2023-01-26T16:35:14.806792Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.806793Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.806923Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T16:35:14.806928Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778894,
    events_root: None,
}
2023-01-26T16:35:14.806933Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:14.806936Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::Berlin::0
2023-01-26T16:35:14.806938Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndGasOOG.json"
2023-01-26T16:35:14.806941Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.806942Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.807055Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T16:35:14.807059Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778894,
    events_root: None,
}
2023-01-26T16:35:14.807064Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:14.807066Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::Berlin::0
2023-01-26T16:35:14.807068Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndGasOOG.json"
2023-01-26T16:35:14.807071Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.807072Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.807184Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T16:35:14.807188Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778894,
    events_root: None,
}
2023-01-26T16:35:14.807193Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:14.807195Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::London::0
2023-01-26T16:35:14.807197Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndGasOOG.json"
2023-01-26T16:35:14.807200Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.807201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.807312Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T16:35:14.807316Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778894,
    events_root: None,
}
2023-01-26T16:35:14.807321Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:14.807324Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::London::0
2023-01-26T16:35:14.807326Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndGasOOG.json"
2023-01-26T16:35:14.807329Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.807330Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.807439Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T16:35:14.807443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778894,
    events_root: None,
}
2023-01-26T16:35:14.807450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:14.807453Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::Merge::0
2023-01-26T16:35:14.807455Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndGasOOG.json"
2023-01-26T16:35:14.807459Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.807460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.807593Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T16:35:14.807598Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778894,
    events_root: None,
}
2023-01-26T16:35:14.807604Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:14.807606Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndGasOOG"::Merge::0
2023-01-26T16:35:14.807608Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndGasOOG.json"
2023-01-26T16:35:14.807610Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:14.807612Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:14.807724Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndGasOOG"
2023-01-26T16:35:14.807728Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778894,
    events_root: None,
}
2023-01-26T16:35:14.809365Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:378.409691ms
2023-01-26T16:35:15.081938Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndOOGatTxLevel.json", Total Files :: 1
2023-01-26T16:35:15.111907Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:15.112043Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:15.112047Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:15.112101Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:15.112103Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:15.112163Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:15.112236Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:15.112239Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndOOGatTxLevel"::Istanbul::0
2023-01-26T16:35:15.112242Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndOOGatTxLevel.json"
2023-01-26T16:35:15.112247Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:15.112248Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:15.496892Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndOOGatTxLevel"
2023-01-26T16:35:15.496907Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1716791,
    events_root: None,
}
2023-01-26T16:35:15.496920Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:15.496926Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndOOGatTxLevel"::Istanbul::0
2023-01-26T16:35:15.496928Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndOOGatTxLevel.json"
2023-01-26T16:35:15.496933Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:15.496935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:15.497072Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndOOGatTxLevel"
2023-01-26T16:35:15.497077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1716791,
    events_root: None,
}
2023-01-26T16:35:15.497084Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:15.497087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndOOGatTxLevel"::Berlin::0
2023-01-26T16:35:15.497090Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndOOGatTxLevel.json"
2023-01-26T16:35:15.497094Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:15.497096Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:15.497204Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndOOGatTxLevel"
2023-01-26T16:35:15.497209Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1716791,
    events_root: None,
}
2023-01-26T16:35:15.497216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:15.497219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndOOGatTxLevel"::Berlin::0
2023-01-26T16:35:15.497221Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndOOGatTxLevel.json"
2023-01-26T16:35:15.497225Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:15.497226Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:15.497341Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndOOGatTxLevel"
2023-01-26T16:35:15.497346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1716791,
    events_root: None,
}
2023-01-26T16:35:15.497353Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:15.497356Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndOOGatTxLevel"::London::0
2023-01-26T16:35:15.497360Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndOOGatTxLevel.json"
2023-01-26T16:35:15.497365Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:15.497367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:15.497500Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndOOGatTxLevel"
2023-01-26T16:35:15.497505Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1716791,
    events_root: None,
}
2023-01-26T16:35:15.497512Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:15.497516Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndOOGatTxLevel"::London::0
2023-01-26T16:35:15.497519Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndOOGatTxLevel.json"
2023-01-26T16:35:15.497523Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:15.497525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:15.497633Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndOOGatTxLevel"
2023-01-26T16:35:15.497638Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1716791,
    events_root: None,
}
2023-01-26T16:35:15.497644Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:15.497647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndOOGatTxLevel"::Merge::0
2023-01-26T16:35:15.497650Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndOOGatTxLevel.json"
2023-01-26T16:35:15.497653Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:15.497655Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:15.497764Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndOOGatTxLevel"
2023-01-26T16:35:15.497769Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1716791,
    events_root: None,
}
2023-01-26T16:35:15.497775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:15.497778Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueAndOOGatTxLevel"::Merge::0
2023-01-26T16:35:15.497781Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueAndOOGatTxLevel.json"
2023-01-26T16:35:15.497787Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:15.497789Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:15.497894Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueAndOOGatTxLevel"
2023-01-26T16:35:15.497899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1716791,
    events_root: None,
}
2023-01-26T16:35:15.499475Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:386.005228ms
2023-01-26T16:35:15.776101Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueOOGinCall.json", Total Files :: 1
2023-01-26T16:35:15.806317Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:15.806462Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:15.806466Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:15.806518Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:15.806521Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:15.806585Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:15.806659Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:15.806661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueOOGinCall"::Istanbul::0
2023-01-26T16:35:15.806664Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueOOGinCall.json"
2023-01-26T16:35:15.806667Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:15.806669Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:16.174262Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueOOGinCall"
2023-01-26T16:35:16.174276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2648640,
    events_root: None,
}
2023-01-26T16:35:16.174288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:16.174292Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueOOGinCall"::Berlin::0
2023-01-26T16:35:16.174293Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueOOGinCall.json"
2023-01-26T16:35:16.174297Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:16.174298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:16.174474Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueOOGinCall"
2023-01-26T16:35:16.174481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1748861,
    events_root: None,
}
2023-01-26T16:35:16.174488Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:16.174491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueOOGinCall"::London::0
2023-01-26T16:35:16.174494Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueOOGinCall.json"
2023-01-26T16:35:16.174498Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:16.174500Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:16.174633Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueOOGinCall"
2023-01-26T16:35:16.174637Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1748861,
    events_root: None,
}
2023-01-26T16:35:16.174642Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:16.174644Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callWithHighValueOOGinCall"::Merge::0
2023-01-26T16:35:16.174646Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callWithHighValueOOGinCall.json"
2023-01-26T16:35:16.174649Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:16.174650Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:16.174760Z  INFO evm_eth_compliance::statetest::runner: UC : "callWithHighValueOOGinCall"
2023-01-26T16:35:16.174764Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1748861,
    events_root: None,
}
2023-01-26T16:35:16.176390Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.457166ms
2023-01-26T16:35:16.458551Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput1.json", Total Files :: 1
2023-01-26T16:35:16.500974Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:16.501114Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:16.501118Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:16.501174Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:16.501176Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:16.501236Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:16.501309Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:16.501312Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput1"::Istanbul::0
2023-01-26T16:35:16.501315Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput1.json"
2023-01-26T16:35:16.501318Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:16.501320Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:16.930471Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput1"
2023-01-26T16:35:16.930485Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:16.930491Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:16.930505Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:16.930509Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput1"::Berlin::0
2023-01-26T16:35:16.930511Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput1.json"
2023-01-26T16:35:16.930516Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:16.930517Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:16.930624Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput1"
2023-01-26T16:35:16.930627Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:16.930630Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:16.930639Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:16.930641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput1"::London::0
2023-01-26T16:35:16.930643Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput1.json"
2023-01-26T16:35:16.930645Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:16.930647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:16.930767Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput1"
2023-01-26T16:35:16.930773Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:16.930777Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:16.930789Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:16.930791Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput1"::Merge::0
2023-01-26T16:35:16.930794Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput1.json"
2023-01-26T16:35:16.930798Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:16.930800Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:16.930917Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput1"
2023-01-26T16:35:16.930921Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:16.930924Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:16.932409Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:429.963104ms
2023-01-26T16:35:17.215035Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput2.json", Total Files :: 1
2023-01-26T16:35:17.251979Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:17.252139Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:17.252144Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:17.252211Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:17.252214Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:17.252289Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:17.252381Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:17.252385Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput2"::Istanbul::0
2023-01-26T16:35:17.252388Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput2.json"
2023-01-26T16:35:17.252393Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:17.252394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:17.619673Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput2"
2023-01-26T16:35:17.619728Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:17.619736Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:17.619753Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:17.619759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput2"::Berlin::0
2023-01-26T16:35:17.619761Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput2.json"
2023-01-26T16:35:17.619765Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:17.619767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:17.619881Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput2"
2023-01-26T16:35:17.619886Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:17.619889Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:17.619901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:17.619904Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput2"::London::0
2023-01-26T16:35:17.619907Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput2.json"
2023-01-26T16:35:17.619910Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:17.619912Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:17.620033Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput2"
2023-01-26T16:35:17.620050Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:17.620061Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:17.620084Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:17.620091Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput2"::Merge::0
2023-01-26T16:35:17.620099Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput2.json"
2023-01-26T16:35:17.620107Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:17.620114Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:17.620240Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput2"
2023-01-26T16:35:17.620255Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:17.620266Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:17.622463Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.315114ms
2023-01-26T16:35:17.902486Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3.json", Total Files :: 1
2023-01-26T16:35:17.932121Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:17.932263Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:17.932267Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:17.932322Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:17.932324Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:17.932383Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:17.932455Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:17.932458Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3"::Istanbul::0
2023-01-26T16:35:17.932461Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3.json"
2023-01-26T16:35:17.932464Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:17.932466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:18.278918Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3"
2023-01-26T16:35:18.278935Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:18.278943Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:18.278958Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:18.278962Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3"::Berlin::0
2023-01-26T16:35:18.278963Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3.json"
2023-01-26T16:35:18.278967Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:18.278969Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:18.279099Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3"
2023-01-26T16:35:18.279103Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:18.279106Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:18.279115Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:18.279117Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3"::London::0
2023-01-26T16:35:18.279119Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3.json"
2023-01-26T16:35:18.279121Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:18.279123Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:18.279215Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3"
2023-01-26T16:35:18.279219Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:18.279223Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:18.279232Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:18.279234Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3"::Merge::0
2023-01-26T16:35:18.279236Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3.json"
2023-01-26T16:35:18.279238Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:18.279241Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:18.279328Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3"
2023-01-26T16:35:18.279332Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:18.279336Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:18.281068Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:347.227719ms
2023-01-26T16:35:18.548823Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3Fail.json", Total Files :: 1
2023-01-26T16:35:18.582507Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:18.582644Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:18.582648Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:18.582702Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:18.582704Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:18.582762Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:18.582837Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:18.582840Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3Fail"::Istanbul::0
2023-01-26T16:35:18.582843Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3Fail.json"
2023-01-26T16:35:18.582847Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:18.582848Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:18.979085Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3Fail"
2023-01-26T16:35:18.979102Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:18.979109Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:18.979123Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:18.979127Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3Fail"::Berlin::0
2023-01-26T16:35:18.979128Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3Fail.json"
2023-01-26T16:35:18.979132Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:18.979133Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:18.979237Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3Fail"
2023-01-26T16:35:18.979240Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:18.979243Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:18.979253Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:18.979255Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3Fail"::London::0
2023-01-26T16:35:18.979257Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3Fail.json"
2023-01-26T16:35:18.979260Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:18.979262Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:18.979348Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3Fail"
2023-01-26T16:35:18.979352Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:18.979355Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:18.979363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:18.979365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3Fail"::Merge::0
2023-01-26T16:35:18.979367Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3Fail.json"
2023-01-26T16:35:18.979370Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:18.979371Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:18.979484Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3Fail"
2023-01-26T16:35:18.979490Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:18.979495Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:18.981583Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:397.005362ms
2023-01-26T16:35:19.250095Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3partial.json", Total Files :: 1
2023-01-26T16:35:19.285484Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:19.285623Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:19.285627Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:19.285682Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:19.285684Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:19.285742Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:19.285814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:19.285817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3partial"::Istanbul::0
2023-01-26T16:35:19.285820Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3partial.json"
2023-01-26T16:35:19.285825Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:19.285826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:19.636413Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3partial"
2023-01-26T16:35:19.636433Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:19.636441Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:19.636461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:19.636468Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3partial"::Berlin::0
2023-01-26T16:35:19.636471Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3partial.json"
2023-01-26T16:35:19.636474Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:19.636479Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:19.636628Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3partial"
2023-01-26T16:35:19.636633Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:19.636636Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:19.636648Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:19.636651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3partial"::London::0
2023-01-26T16:35:19.636653Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3partial.json"
2023-01-26T16:35:19.636656Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:19.636658Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:19.636783Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3partial"
2023-01-26T16:35:19.636790Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:19.636793Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:19.636803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:19.636806Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3partial"::Merge::0
2023-01-26T16:35:19.636808Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3partial.json"
2023-01-26T16:35:19.636811Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:19.636813Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:19.636927Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3partial"
2023-01-26T16:35:19.636946Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549028,
    events_root: None,
}
2023-01-26T16:35:19.636957Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=71): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:19.639034Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:351.497681ms
2023-01-26T16:35:19.930613Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3partialFail.json", Total Files :: 1
2023-01-26T16:35:19.964303Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:19.964445Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:19.964450Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:19.964505Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:19.964507Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:19.964569Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:19.964657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:19.964663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3partialFail"::Istanbul::0
2023-01-26T16:35:19.964667Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3partialFail.json"
2023-01-26T16:35:19.964672Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:19.964674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:20.349092Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3partialFail"
2023-01-26T16:35:20.349107Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:20.349114Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:20.349129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:20.349133Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3partialFail"::Berlin::0
2023-01-26T16:35:20.349135Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3partialFail.json"
2023-01-26T16:35:20.349139Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:20.349141Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:20.349247Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3partialFail"
2023-01-26T16:35:20.349251Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:20.349254Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:20.349264Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:20.349266Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3partialFail"::London::0
2023-01-26T16:35:20.349267Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3partialFail.json"
2023-01-26T16:35:20.349270Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:20.349271Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:20.349359Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3partialFail"
2023-01-26T16:35:20.349363Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:20.349368Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:20.349376Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:20.349378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeOutput3partialFail"::Merge::0
2023-01-26T16:35:20.349380Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeOutput3partialFail.json"
2023-01-26T16:35:20.349382Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:20.349384Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:20.349478Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeOutput3partialFail"
2023-01-26T16:35:20.349484Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1549094,
    events_root: None,
}
2023-01-26T16:35:20.349487Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=70): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:20.350994Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:385.199487ms
2023-01-26T16:35:20.629635Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeWithHighValue.json", Total Files :: 1
2023-01-26T16:35:20.686895Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:20.687027Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:20.687030Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:20.687083Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:20.687085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:20.687144Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:20.687214Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:20.687216Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValue"::Istanbul::0
2023-01-26T16:35:20.687219Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeWithHighValue.json"
2023-01-26T16:35:20.687223Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:20.687224Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:21.032404Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValue"
2023-01-26T16:35:21.032423Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543806,
    events_root: None,
}
2023-01-26T16:35:21.032432Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=41): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:21.032451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:21.032456Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValue"::Berlin::0
2023-01-26T16:35:21.032458Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeWithHighValue.json"
2023-01-26T16:35:21.032464Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:21.032466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:21.032618Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValue"
2023-01-26T16:35:21.032623Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543806,
    events_root: None,
}
2023-01-26T16:35:21.032627Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=41): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:21.032638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:21.032640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValue"::London::0
2023-01-26T16:35:21.032642Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeWithHighValue.json"
2023-01-26T16:35:21.032646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:21.032648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:21.032764Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValue"
2023-01-26T16:35:21.032769Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543806,
    events_root: None,
}
2023-01-26T16:35:21.032773Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=41): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:21.032783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:21.032786Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValue"::Merge::0
2023-01-26T16:35:21.032788Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeWithHighValue.json"
2023-01-26T16:35:21.032791Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:21.032793Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:21.032903Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValue"
2023-01-26T16:35:21.032922Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543806,
    events_root: None,
}
2023-01-26T16:35:21.032933Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=41): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:21.034937Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.063297ms
2023-01-26T16:35:21.302096Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeWithHighValueAndGasOOG.json", Total Files :: 1
2023-01-26T16:35:21.331056Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:21.331203Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:21.331207Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:21.331259Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:21.331261Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:21.331319Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:21.331392Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:21.331395Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValueAndGasOOG"::Istanbul::0
2023-01-26T16:35:21.331398Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeWithHighValueAndGasOOG.json"
2023-01-26T16:35:21.331402Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:21.331403Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:21.703574Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValueAndGasOOG"
2023-01-26T16:35:21.703591Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552379,
    events_root: None,
}
2023-01-26T16:35:21.703598Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=124): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:21.703612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:21.703616Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValueAndGasOOG"::Berlin::0
2023-01-26T16:35:21.703618Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeWithHighValueAndGasOOG.json"
2023-01-26T16:35:21.703622Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:21.703623Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:21.703734Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValueAndGasOOG"
2023-01-26T16:35:21.703738Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552379,
    events_root: None,
}
2023-01-26T16:35:21.703741Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=124): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:21.703750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:21.703752Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValueAndGasOOG"::London::0
2023-01-26T16:35:21.703754Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeWithHighValueAndGasOOG.json"
2023-01-26T16:35:21.703756Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:21.703758Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:21.703848Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValueAndGasOOG"
2023-01-26T16:35:21.703852Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552379,
    events_root: None,
}
2023-01-26T16:35:21.703855Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=124): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:21.703863Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:21.703865Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeWithHighValueAndGasOOG"::Merge::0
2023-01-26T16:35:21.703866Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/callcodeWithHighValueAndGasOOG.json"
2023-01-26T16:35:21.703869Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:21.703871Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:21.703958Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeWithHighValueAndGasOOG"
2023-01-26T16:35:21.703961Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1552379,
    events_root: None,
}
2023-01-26T16:35:21.703964Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=124): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-26T16:35:21.705571Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.921895ms
2023-01-26T16:35:21.973803Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/contractCreationMakeCallThatAskMoreGasThenTransactionProvided.json", Total Files :: 1
2023-01-26T16:35:22.008363Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:22.008500Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:22.008504Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:22.008559Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:22.008562Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:22.008623Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:22.008696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:22.008699Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "contractCreationMakeCallThatAskMoreGasThenTransactionProvided"::Istanbul::0
2023-01-26T16:35:22.008702Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/contractCreationMakeCallThatAskMoreGasThenTransactionProvided.json"
2023-01-26T16:35:22.008706Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T16:35:22.008708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:22.008709Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "contractCreationMakeCallThatAskMoreGasThenTransactionProvided"::Istanbul::0
2023-01-26T16:35:22.008712Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/contractCreationMakeCallThatAskMoreGasThenTransactionProvided.json"
2023-01-26T16:35:22.008715Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T16:35:22.008716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:22.008717Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "contractCreationMakeCallThatAskMoreGasThenTransactionProvided"::Berlin::0
2023-01-26T16:35:22.008720Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/contractCreationMakeCallThatAskMoreGasThenTransactionProvided.json"
2023-01-26T16:35:22.008723Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T16:35:22.008724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:22.008725Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "contractCreationMakeCallThatAskMoreGasThenTransactionProvided"::Berlin::0
2023-01-26T16:35:22.008727Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/contractCreationMakeCallThatAskMoreGasThenTransactionProvided.json"
2023-01-26T16:35:22.008731Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T16:35:22.008732Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:22.008734Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "contractCreationMakeCallThatAskMoreGasThenTransactionProvided"::London::0
2023-01-26T16:35:22.008736Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/contractCreationMakeCallThatAskMoreGasThenTransactionProvided.json"
2023-01-26T16:35:22.008739Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T16:35:22.008741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:22.008743Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "contractCreationMakeCallThatAskMoreGasThenTransactionProvided"::London::0
2023-01-26T16:35:22.008745Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/contractCreationMakeCallThatAskMoreGasThenTransactionProvided.json"
2023-01-26T16:35:22.008749Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T16:35:22.008750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:22.008752Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "contractCreationMakeCallThatAskMoreGasThenTransactionProvided"::Merge::0
2023-01-26T16:35:22.008754Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/contractCreationMakeCallThatAskMoreGasThenTransactionProvided.json"
2023-01-26T16:35:22.008757Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T16:35:22.008758Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:22.008760Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "contractCreationMakeCallThatAskMoreGasThenTransactionProvided"::Merge::0
2023-01-26T16:35:22.008762Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/contractCreationMakeCallThatAskMoreGasThenTransactionProvided.json"
2023-01-26T16:35:22.008765Z  WARN evm_eth_compliance::statetest::runner: TX len : 35
2023-01-26T16:35:22.009603Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:408.448s
2023-01-26T16:35:22.280252Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json", Total Files :: 1
2023-01-26T16:35:22.310804Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:22.310947Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:22.310951Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:22.311008Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:22.311083Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:22.311086Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Istanbul::0
2023-01-26T16:35:22.311090Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-26T16:35:22.311094Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:22.311095Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:22.662550Z  INFO evm_eth_compliance::statetest::runner: UC : "createFailBalanceTooLow"
2023-01-26T16:35:22.662564Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3585372,
    events_root: None,
}
2023-01-26T16:35:22.662575Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:22.662579Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Istanbul::0
2023-01-26T16:35:22.662580Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-26T16:35:22.662584Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:22.662586Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:22.662679Z  INFO evm_eth_compliance::statetest::runner: UC : "createFailBalanceTooLow"
2023-01-26T16:35:22.662683Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:22.662688Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:22.662690Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Berlin::0
2023-01-26T16:35:22.662692Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-26T16:35:22.662694Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:22.662696Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:22.662764Z  INFO evm_eth_compliance::statetest::runner: UC : "createFailBalanceTooLow"
2023-01-26T16:35:22.662768Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:22.662773Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:22.662775Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Berlin::0
2023-01-26T16:35:22.662776Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-26T16:35:22.662779Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:22.662780Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:22.662846Z  INFO evm_eth_compliance::statetest::runner: UC : "createFailBalanceTooLow"
2023-01-26T16:35:22.662849Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:22.662853Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:22.662856Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::London::0
2023-01-26T16:35:22.662857Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-26T16:35:22.662860Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:22.662861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:22.662927Z  INFO evm_eth_compliance::statetest::runner: UC : "createFailBalanceTooLow"
2023-01-26T16:35:22.662930Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:22.662935Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:22.662937Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::London::0
2023-01-26T16:35:22.662939Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-26T16:35:22.662941Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:22.662943Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:22.663009Z  INFO evm_eth_compliance::statetest::runner: UC : "createFailBalanceTooLow"
2023-01-26T16:35:22.663013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:22.663017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:22.663019Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Merge::0
2023-01-26T16:35:22.663021Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-26T16:35:22.663023Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:22.663024Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:22.663091Z  INFO evm_eth_compliance::statetest::runner: UC : "createFailBalanceTooLow"
2023-01-26T16:35:22.663095Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:22.663099Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:22.663102Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Merge::0
2023-01-26T16:35:22.663104Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-26T16:35:22.663108Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:22.663109Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:22.663182Z  INFO evm_eth_compliance::statetest::runner: UC : "createFailBalanceTooLow"
2023-01-26T16:35:22.663187Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:22.664802Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.393056ms
2023-01-26T16:35:22.938498Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json", Total Files :: 1
2023-01-26T16:35:23.013718Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:23.013856Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:23.013860Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:23.013915Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:23.013988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:23.013991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination"::Istanbul::0
2023-01-26T16:35:23.013994Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json"
2023-01-26T16:35:23.013998Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:23.013999Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T16:35:23.700662Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailBadJumpDestination"
2023-01-26T16:35:23.700672Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14368910,
    events_root: None,
}
2023-01-26T16:35:23.700699Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:23.700703Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination"::Berlin::0
2023-01-26T16:35:23.700705Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json"
2023-01-26T16:35:23.700708Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:23.700710Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:23.700808Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailBadJumpDestination"
2023-01-26T16:35:23.700811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:23.700816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:23.700818Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination"::London::0
2023-01-26T16:35:23.700820Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json"
2023-01-26T16:35:23.700822Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:23.700824Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:23.700891Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailBadJumpDestination"
2023-01-26T16:35:23.700895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:23.700899Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:23.700901Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination"::Merge::0
2023-01-26T16:35:23.700903Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json"
2023-01-26T16:35:23.700906Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:23.700907Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:23.700974Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailBadJumpDestination"
2023-01-26T16:35:23.700977Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:23.702752Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:687.268367ms
2023-01-26T16:35:23.982644Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json", Total Files :: 1
2023-01-26T16:35:24.013094Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:24.013237Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:24.013241Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:24.013299Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:24.013373Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:24.013376Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination2"::Istanbul::0
2023-01-26T16:35:24.013379Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json"
2023-01-26T16:35:24.013383Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:24.013384Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T16:35:24.741449Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailBadJumpDestination2"
2023-01-26T16:35:24.741459Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14375991,
    events_root: None,
}
2023-01-26T16:35:24.741496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:24.741500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination2"::Berlin::0
2023-01-26T16:35:24.741502Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json"
2023-01-26T16:35:24.741506Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:24.741507Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:24.741610Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailBadJumpDestination2"
2023-01-26T16:35:24.741614Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:24.741618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:24.741620Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination2"::London::0
2023-01-26T16:35:24.741622Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json"
2023-01-26T16:35:24.741625Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:24.741627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:24.741693Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailBadJumpDestination2"
2023-01-26T16:35:24.741697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:24.741701Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:24.741703Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination2"::Merge::0
2023-01-26T16:35:24.741706Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json"
2023-01-26T16:35:24.741709Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:24.741710Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:24.741775Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailBadJumpDestination2"
2023-01-26T16:35:24.741779Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:24.743525Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:728.695164ms
2023-01-26T16:35:25.042067Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json", Total Files :: 1
2023-01-26T16:35:25.073323Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:25.073460Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:25.073464Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:25.073530Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:25.073602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:25.073605Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackSizeLargerThan1024"::Istanbul::0
2023-01-26T16:35:25.073609Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json"
2023-01-26T16:35:25.073612Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:25.073614Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T16:35:25.764793Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailStackSizeLargerThan1024"
2023-01-26T16:35:25.764802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 26184658,
    events_root: None,
}
2023-01-26T16:35:25.764826Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:25.764830Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackSizeLargerThan1024"::Berlin::0
2023-01-26T16:35:25.764832Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json"
2023-01-26T16:35:25.764836Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:25.764837Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:25.764941Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailStackSizeLargerThan1024"
2023-01-26T16:35:25.764948Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:25.764952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:25.764954Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackSizeLargerThan1024"::London::0
2023-01-26T16:35:25.764956Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json"
2023-01-26T16:35:25.764959Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:25.764960Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:25.765031Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailStackSizeLargerThan1024"
2023-01-26T16:35:25.765037Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:25.765042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:25.765045Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackSizeLargerThan1024"::Merge::0
2023-01-26T16:35:25.765047Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json"
2023-01-26T16:35:25.765051Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:25.765053Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:25.765140Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailStackSizeLargerThan1024"
2023-01-26T16:35:25.765145Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:25.767003Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:691.833901ms
2023-01-26T16:35:26.051520Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json", Total Files :: 1
2023-01-26T16:35:26.123351Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:26.123486Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:26.123489Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:26.123543Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:26.123615Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:26.123618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackUnderflow"::Istanbul::0
2023-01-26T16:35:26.123621Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json"
2023-01-26T16:35:26.123624Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:26.123626Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T16:35:26.812349Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailStackUnderflow"
2023-01-26T16:35:26.812359Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14368922,
    events_root: None,
}
2023-01-26T16:35:26.812384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:26.812388Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackUnderflow"::Berlin::0
2023-01-26T16:35:26.812390Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json"
2023-01-26T16:35:26.812393Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:26.812395Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:26.812499Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailStackUnderflow"
2023-01-26T16:35:26.812503Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:26.812508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:26.812510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackUnderflow"::London::0
2023-01-26T16:35:26.812512Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json"
2023-01-26T16:35:26.812514Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:26.812516Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:26.812586Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailStackUnderflow"
2023-01-26T16:35:26.812589Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:26.812593Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:26.812595Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackUnderflow"::Merge::0
2023-01-26T16:35:26.812597Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json"
2023-01-26T16:35:26.812600Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:26.812601Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:26.812669Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailStackUnderflow"
2023-01-26T16:35:26.812673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:26.814497Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:689.331084ms
2023-01-26T16:35:27.095951Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json", Total Files :: 1
2023-01-26T16:35:27.126949Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:27.127087Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:27.127091Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:27.127143Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:27.127145Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:35:27.127203Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:27.127205Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:35:27.127261Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:27.127332Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:27.127336Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction"::Istanbul::0
2023-01-26T16:35:27.127339Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json"
2023-01-26T16:35:27.127343Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:27.127344Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:27.485611Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailUndefinedInstruction"
2023-01-26T16:35:27.485626Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3620865,
    events_root: None,
}
2023-01-26T16:35:27.485639Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:27.485644Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction"::Berlin::0
2023-01-26T16:35:27.485647Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json"
2023-01-26T16:35:27.485651Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:27.485654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:27.485834Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailUndefinedInstruction"
2023-01-26T16:35:27.485839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723402,
    events_root: None,
}
2023-01-26T16:35:27.485847Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:27.485850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction"::London::0
2023-01-26T16:35:27.485852Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json"
2023-01-26T16:35:27.485856Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:27.485858Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:27.486021Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailUndefinedInstruction"
2023-01-26T16:35:27.486027Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723402,
    events_root: None,
}
2023-01-26T16:35:27.486034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:27.486037Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction"::Merge::0
2023-01-26T16:35:27.486039Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json"
2023-01-26T16:35:27.486043Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:27.486045Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:27.486209Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailUndefinedInstruction"
2023-01-26T16:35:27.486215Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723402,
    events_root: None,
}
2023-01-26T16:35:27.488296Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.277868ms
2023-01-26T16:35:27.762156Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json", Total Files :: 1
2023-01-26T16:35:27.792637Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:27.792777Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:27.792781Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:27.792837Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:27.792909Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:27.792912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction2"::Istanbul::0
2023-01-26T16:35:27.792915Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json"
2023-01-26T16:35:27.792919Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:27.792920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T16:35:28.432264Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailUndefinedInstruction2"
2023-01-26T16:35:28.432274Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14368926,
    events_root: None,
}
2023-01-26T16:35:28.432296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:28.432299Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction2"::Berlin::0
2023-01-26T16:35:28.432301Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json"
2023-01-26T16:35:28.432305Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:28.432306Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:28.432404Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailUndefinedInstruction2"
2023-01-26T16:35:28.432408Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:28.432412Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:28.432414Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction2"::London::0
2023-01-26T16:35:28.432416Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json"
2023-01-26T16:35:28.432419Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:28.432420Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:28.432485Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailUndefinedInstruction2"
2023-01-26T16:35:28.432490Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:28.432494Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:28.432495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction2"::Merge::0
2023-01-26T16:35:28.432497Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json"
2023-01-26T16:35:28.432500Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:28.432501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:28.432566Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFailUndefinedInstruction2"
2023-01-26T16:35:28.432569Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:28.433966Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:639.941192ms
2023-01-26T16:35:28.729024Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json", Total Files :: 1
2023-01-26T16:35:28.762404Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:28.762540Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:28.762544Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:28.762600Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:28.762673Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:28.762676Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit"::Istanbul::0
2023-01-26T16:35:28.762679Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
2023-01-26T16:35:28.762683Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:28.762685Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T16:35:29.382859Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFail_OOGduringInit"
2023-01-26T16:35:29.382873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14463152,
    events_root: None,
}
2023-01-26T16:35:29.382904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:29.382910Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit"::Berlin::0
2023-01-26T16:35:29.382913Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
2023-01-26T16:35:29.382917Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:29.382919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:29.383051Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFail_OOGduringInit"
2023-01-26T16:35:29.383057Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:29.383063Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:29.383066Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit"::London::0
2023-01-26T16:35:29.383068Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
2023-01-26T16:35:29.383072Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:29.383075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:29.383157Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFail_OOGduringInit"
2023-01-26T16:35:29.383161Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:29.383165Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:29.383167Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit"::Merge::0
2023-01-26T16:35:29.383169Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
2023-01-26T16:35:29.383172Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:29.383174Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:29.383242Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFail_OOGduringInit"
2023-01-26T16:35:29.383246Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:29.385396Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:620.851136ms
2023-01-26T16:35:29.676026Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit2.json", Total Files :: 1
2023-01-26T16:35:29.707021Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:29.707164Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:29.707168Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:29.707224Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:29.707296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:29.707299Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit2"::Istanbul::0
2023-01-26T16:35:29.707302Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit2.json"
2023-01-26T16:35:29.707305Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:29.707307Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T16:35:30.363008Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFail_OOGduringInit2"
2023-01-26T16:35:30.363019Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 120121297,
    events_root: None,
}
2023-01-26T16:35:30.363046Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:30.363050Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit2"::Berlin::0
2023-01-26T16:35:30.363052Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit2.json"
2023-01-26T16:35:30.363055Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:30.363057Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-26T16:35:30.372738Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFail_OOGduringInit2"
2023-01-26T16:35:30.372750Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 119020705,
    events_root: None,
}
2023-01-26T16:35:30.372784Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:30.372790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit2"::London::0
2023-01-26T16:35:30.372792Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit2.json"
2023-01-26T16:35:30.372796Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:30.372797Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-26T16:35:30.382505Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFail_OOGduringInit2"
2023-01-26T16:35:30.382511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 119938920,
    events_root: None,
}
2023-01-26T16:35:30.382527Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:30.382530Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit2"::Merge::0
2023-01-26T16:35:30.382532Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit2.json"
2023-01-26T16:35:30.382535Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:30.382536Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-26T16:35:30.392187Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitFail_OOGduringInit2"
2023-01-26T16:35:30.392203Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 120456692,
    events_root: None,
}
2023-01-26T16:35:30.394146Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:685.223531ms
2023-01-26T16:35:30.665290Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json", Total Files :: 1
2023-01-26T16:35:30.695465Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:30.695603Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:30.695607Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:30.695661Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:30.695734Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:30.695737Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Istanbul::0
2023-01-26T16:35:30.695741Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-26T16:35:30.695744Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:30.695746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T16:35:31.347482Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitOOGforCREATE"
2023-01-26T16:35:31.347493Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14463152,
    events_root: None,
}
2023-01-26T16:35:31.347525Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:31.347531Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Istanbul::0
2023-01-26T16:35:31.347534Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-26T16:35:31.347538Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:31.347540Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:31.347664Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitOOGforCREATE"
2023-01-26T16:35:31.347669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:31.347676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:31.347679Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Berlin::0
2023-01-26T16:35:31.347682Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-26T16:35:31.347685Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:31.347687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:31.347781Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitOOGforCREATE"
2023-01-26T16:35:31.347786Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:31.347792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:31.347795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Berlin::0
2023-01-26T16:35:31.347797Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-26T16:35:31.347801Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:31.347803Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:31.347892Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitOOGforCREATE"
2023-01-26T16:35:31.347897Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:31.347903Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:31.347906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::London::0
2023-01-26T16:35:31.347908Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-26T16:35:31.347912Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:31.347914Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:31.348006Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitOOGforCREATE"
2023-01-26T16:35:31.348011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:31.348017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:31.348020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::London::0
2023-01-26T16:35:31.348023Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-26T16:35:31.348027Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:31.348028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:31.348120Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitOOGforCREATE"
2023-01-26T16:35:31.348125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:31.348133Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:31.348136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Merge::0
2023-01-26T16:35:31.348138Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-26T16:35:31.348142Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:31.348144Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:31.348235Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitOOGforCREATE"
2023-01-26T16:35:31.348241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:31.348247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:31.348250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Merge::0
2023-01-26T16:35:31.348253Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-26T16:35:31.348257Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:31.348259Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:31.348351Z  INFO evm_eth_compliance::statetest::runner: UC : "createInitOOGforCREATE"
2023-01-26T16:35:31.348357Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-26T16:35:31.350474Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:652.902781ms
2023-01-26T16:35:31.621263Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_ExampleContract.json", Total Files :: 1
2023-01-26T16:35:31.656735Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:31.656894Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:31.656898Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:31.656958Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:31.657036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:31.657040Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createJS_ExampleContract"::Istanbul::0
2023-01-26T16:35:31.657044Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_ExampleContract.json"
2023-01-26T16:35:31.657049Z  WARN evm_eth_compliance::statetest::runner: TX len : 1034
2023-01-26T16:35:31.657051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:31.657054Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createJS_ExampleContract"::Berlin::0
2023-01-26T16:35:31.657057Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_ExampleContract.json"
2023-01-26T16:35:31.657060Z  WARN evm_eth_compliance::statetest::runner: TX len : 1034
2023-01-26T16:35:31.657062Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:31.657065Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createJS_ExampleContract"::London::0
2023-01-26T16:35:31.657067Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_ExampleContract.json"
2023-01-26T16:35:31.657071Z  WARN evm_eth_compliance::statetest::runner: TX len : 1034
2023-01-26T16:35:31.657073Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:31.657075Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createJS_ExampleContract"::Merge::0
2023-01-26T16:35:31.657077Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_ExampleContract.json"
2023-01-26T16:35:31.657080Z  WARN evm_eth_compliance::statetest::runner: TX len : 1034
2023-01-26T16:35:31.657923Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:351.753s
2023-01-26T16:35:31.936856Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_NoCollision.json", Total Files :: 1
2023-01-26T16:35:31.983884Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:31.984040Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:31.984116Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:31.984119Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createJS_NoCollision"::Istanbul::0
2023-01-26T16:35:31.984122Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_NoCollision.json"
2023-01-26T16:35:31.984126Z  WARN evm_eth_compliance::statetest::runner: TX len : 1034
2023-01-26T16:35:31.984127Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:31.984129Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createJS_NoCollision"::Berlin::0
2023-01-26T16:35:31.984131Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_NoCollision.json"
2023-01-26T16:35:31.984135Z  WARN evm_eth_compliance::statetest::runner: TX len : 1034
2023-01-26T16:35:31.984136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:31.984137Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createJS_NoCollision"::London::0
2023-01-26T16:35:31.984139Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_NoCollision.json"
2023-01-26T16:35:31.984143Z  WARN evm_eth_compliance::statetest::runner: TX len : 1034
2023-01-26T16:35:31.984144Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:31.984145Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createJS_NoCollision"::Merge::0
2023-01-26T16:35:31.984147Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createJS_NoCollision.json"
2023-01-26T16:35:31.984151Z  WARN evm_eth_compliance::statetest::runner: TX len : 1034
2023-01-26T16:35:31.984688Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:274.58s
2023-01-26T16:35:32.243939Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxs.json", Total Files :: 1
2023-01-26T16:35:32.279665Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:32.279807Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:32.279881Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:32.279884Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxs"::Istanbul::0
2023-01-26T16:35:32.279887Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxs.json"
2023-01-26T16:35:32.279891Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.279893Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:32.279896Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxs"::Berlin::0
2023-01-26T16:35:32.279897Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxs.json"
2023-01-26T16:35:32.279900Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.279901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:32.279903Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxs"::London::0
2023-01-26T16:35:32.279905Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxs.json"
2023-01-26T16:35:32.279907Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.279908Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:32.279910Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxs"::Merge::0
2023-01-26T16:35:32.279911Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxs.json"
2023-01-26T16:35:32.279914Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.280714Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:254.683s
2023-01-26T16:35:32.553856Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGas.json", Total Files :: 1
2023-01-26T16:35:32.606943Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:32.607131Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:32.607216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:32.607220Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsNotEnoughGas"::Istanbul::0
2023-01-26T16:35:32.607224Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGas.json"
2023-01-26T16:35:32.607227Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.607229Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:32.607230Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsNotEnoughGas"::Istanbul::0
2023-01-26T16:35:32.607232Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGas.json"
2023-01-26T16:35:32.607235Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.607236Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:32.607238Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsNotEnoughGas"::Berlin::0
2023-01-26T16:35:32.607240Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGas.json"
2023-01-26T16:35:32.607242Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.607243Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:32.607245Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsNotEnoughGas"::Berlin::0
2023-01-26T16:35:32.607247Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGas.json"
2023-01-26T16:35:32.607250Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.607251Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:32.607253Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsNotEnoughGas"::London::0
2023-01-26T16:35:32.607255Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGas.json"
2023-01-26T16:35:32.607257Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.607259Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:32.607260Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsNotEnoughGas"::London::0
2023-01-26T16:35:32.607262Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGas.json"
2023-01-26T16:35:32.607264Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.607266Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:32.607267Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsNotEnoughGas"::Merge::0
2023-01-26T16:35:32.607269Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGas.json"
2023-01-26T16:35:32.607272Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.607273Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:32.607274Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "createNameRegistratorPerTxsNotEnoughGas"::Merge::0
2023-01-26T16:35:32.607276Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPerTxsNotEnoughGas.json"
2023-01-26T16:35:32.607279Z  WARN evm_eth_compliance::statetest::runner: TX len : 34
2023-01-26T16:35:32.608223Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:343.488s
2023-01-26T16:35:32.886543Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPreStore1NotEnoughGas.json", Total Files :: 1
2023-01-26T16:35:32.916346Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:32.916500Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:32.916503Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:32.916558Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:32.916632Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:32.916635Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorPreStore1NotEnoughGas"::Istanbul::0
2023-01-26T16:35:32.916639Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPreStore1NotEnoughGas.json"
2023-01-26T16:35:32.916643Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:32.916644Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T16:35:33.527383Z  INFO evm_eth_compliance::statetest::runner: UC : "createNameRegistratorPreStore1NotEnoughGas"
2023-01-26T16:35:33.527393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13718301,
    events_root: None,
}
2023-01-26T16:35:33.527416Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:33.527420Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorPreStore1NotEnoughGas"::Berlin::0
2023-01-26T16:35:33.527422Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPreStore1NotEnoughGas.json"
2023-01-26T16:35:33.527425Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:33.527427Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-26T16:35:33.528011Z  INFO evm_eth_compliance::statetest::runner: UC : "createNameRegistratorPreStore1NotEnoughGas"
2023-01-26T16:35:33.528016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12617708,
    events_root: None,
}
2023-01-26T16:35:33.528030Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:33.528032Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorPreStore1NotEnoughGas"::London::0
2023-01-26T16:35:33.528034Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPreStore1NotEnoughGas.json"
2023-01-26T16:35:33.528037Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:33.528039Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-26T16:35:33.528561Z  INFO evm_eth_compliance::statetest::runner: UC : "createNameRegistratorPreStore1NotEnoughGas"
2023-01-26T16:35:33.528566Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13535923,
    events_root: None,
}
2023-01-26T16:35:33.528581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:33.528583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorPreStore1NotEnoughGas"::Merge::0
2023-01-26T16:35:33.528585Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorPreStore1NotEnoughGas.json"
2023-01-26T16:35:33.528588Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:33.528589Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-26T16:35:33.529137Z  INFO evm_eth_compliance::statetest::runner: UC : "createNameRegistratorPreStore1NotEnoughGas"
2023-01-26T16:35:33.529142Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14053695,
    events_root: None,
}
2023-01-26T16:35:33.530741Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:612.81678ms
2023-01-26T16:35:33.812101Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorendowmentTooHigh.json", Total Files :: 1
2023-01-26T16:35:33.867477Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:35:33.867617Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:33.867620Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:35:33.867678Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:35:33.867753Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:35:33.867756Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorendowmentTooHigh"::Istanbul::0
2023-01-26T16:35:33.867759Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorendowmentTooHigh.json"
2023-01-26T16:35:33.867762Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:33.867764Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:34.265440Z  INFO evm_eth_compliance::statetest::runner: UC : "createNameRegistratorendowmentTooHigh"
2023-01-26T16:35:34.265455Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-01-26T16:35:34.265466Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:35:34.265482Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorendowmentTooHigh"::Berlin::0
2023-01-26T16:35:34.265484Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorendowmentTooHigh.json"
2023-01-26T16:35:34.265487Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:34.265489Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:34.265611Z  INFO evm_eth_compliance::statetest::runner: UC : "createNameRegistratorendowmentTooHigh"
2023-01-26T16:35:34.265616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-01-26T16:35:34.265621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:35:34.265623Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorendowmentTooHigh"::London::0
2023-01-26T16:35:34.265625Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorendowmentTooHigh.json"
2023-01-26T16:35:34.265628Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:34.265644Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:34.265732Z  INFO evm_eth_compliance::statetest::runner: UC : "createNameRegistratorendowmentTooHigh"
2023-01-26T16:35:34.265737Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-01-26T16:35:34.265742Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:35:34.265744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorendowmentTooHigh"::Merge::0
2023-01-26T16:35:34.265746Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createNameRegistratorendowmentTooHigh.json"
2023-01-26T16:35:34.265748Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:35:34.265751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:35:34.265882Z  INFO evm_eth_compliance::statetest::runner: UC : "createNameRegistratorendowmentTooHigh"
2023-01-26T16:35:34.265887Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-01-26T16:35:34.267404Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:398.419124ms
```
