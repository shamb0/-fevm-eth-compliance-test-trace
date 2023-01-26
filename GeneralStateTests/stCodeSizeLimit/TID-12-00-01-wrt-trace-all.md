> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCodeSizeLimit

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCodeSizeLimit \
	cargo run --release \
	-- \
	statetest
```

> For Review

- Following use-case are skipped due to `transaction.tx` empty. Have to re-check on revm

| Test ID | Use-Case |
| --- | --- |
| TID-12-01 | codesizeInit |
| TID-12-02 | codesizeOOGInvalidSize |
| TID-12-03 | codesizeValid |


> Execution Trace

```
2023-01-26T15:45:57.092870Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeInit.json", Total Files :: 1
2023-01-26T15:45:57.184675Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T15:45:57.184837Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:45:57.184910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T15:45:57.184914Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeInit"::Istanbul::0
2023-01-26T15:45:57.184917Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeInit.json"
2023-01-26T15:45:57.184920Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-26T15:45:57.184921Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T15:45:57.184923Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeInit"::Berlin::0
2023-01-26T15:45:57.184924Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeInit.json"
2023-01-26T15:45:57.184927Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-26T15:45:57.184928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T15:45:57.184931Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeInit"::London::0
2023-01-26T15:45:57.184932Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeInit.json"
2023-01-26T15:45:57.184935Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-26T15:45:57.184936Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T15:45:57.184937Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeInit"::Merge::0
2023-01-26T15:45:57.184939Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeInit.json"
2023-01-26T15:45:57.184941Z  WARN evm_eth_compliance::statetest::runner: TX len : 10
2023-01-26T15:45:57.185356Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:272.916s
2023-01-26T15:45:57.441148Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeOOGInvalidSize.json", Total Files :: 1
2023-01-26T15:45:57.490930Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T15:45:57.491090Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:45:57.491167Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T15:45:57.491170Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeOOGInvalidSize"::Istanbul::0
2023-01-26T15:45:57.491173Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeOOGInvalidSize.json"
2023-01-26T15:45:57.491177Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.491178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T15:45:57.491180Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeOOGInvalidSize"::Istanbul::1
2023-01-26T15:45:57.491181Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeOOGInvalidSize.json"
2023-01-26T15:45:57.491184Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.491186Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T15:45:57.491188Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeOOGInvalidSize"::Berlin::0
2023-01-26T15:45:57.491189Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeOOGInvalidSize.json"
2023-01-26T15:45:57.491192Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.491193Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T15:45:57.491194Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeOOGInvalidSize"::Berlin::1
2023-01-26T15:45:57.491196Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeOOGInvalidSize.json"
2023-01-26T15:45:57.491199Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.491200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T15:45:57.491202Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeOOGInvalidSize"::London::0
2023-01-26T15:45:57.491203Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeOOGInvalidSize.json"
2023-01-26T15:45:57.491206Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.491207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T15:45:57.491209Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeOOGInvalidSize"::London::1
2023-01-26T15:45:57.491210Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeOOGInvalidSize.json"
2023-01-26T15:45:57.491213Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.491214Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T15:45:57.491215Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeOOGInvalidSize"::Merge::0
2023-01-26T15:45:57.491217Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeOOGInvalidSize.json"
2023-01-26T15:45:57.491219Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.491221Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T15:45:57.491222Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeOOGInvalidSize"::Merge::1
2023-01-26T15:45:57.491224Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeOOGInvalidSize.json"
2023-01-26T15:45:57.491226Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.491779Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:302.441s
2023-01-26T15:45:57.740891Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeValid.json", Total Files :: 1
2023-01-26T15:45:57.793954Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T15:45:57.794165Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:45:57.794267Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T15:45:57.794273Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeValid"::Istanbul::0
2023-01-26T15:45:57.794277Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeValid.json"
2023-01-26T15:45:57.794282Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.794284Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-26T15:45:57.794286Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeValid"::Istanbul::1
2023-01-26T15:45:57.794289Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeValid.json"
2023-01-26T15:45:57.794292Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.794294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T15:45:57.794296Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeValid"::Berlin::0
2023-01-26T15:45:57.794298Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeValid.json"
2023-01-26T15:45:57.794301Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.794303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-26T15:45:57.794306Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeValid"::Berlin::1
2023-01-26T15:45:57.794308Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeValid.json"
2023-01-26T15:45:57.794311Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.794313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T15:45:57.794315Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeValid"::London::0
2023-01-26T15:45:57.794317Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeValid.json"
2023-01-26T15:45:57.794320Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.794322Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T15:45:57.794323Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeValid"::London::1
2023-01-26T15:45:57.794325Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeValid.json"
2023-01-26T15:45:57.794327Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.794328Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T15:45:57.794330Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeValid"::Merge::0
2023-01-26T15:45:57.794333Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeValid.json"
2023-01-26T15:45:57.794336Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.794337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-26T15:45:57.794340Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "codesizeValid"::Merge::1
2023-01-26T15:45:57.794343Z  WARN evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/codesizeValid.json"
2023-01-26T15:45:57.794346Z  WARN evm_eth_compliance::statetest::runner: TX len : 14
2023-01-26T15:45:57.795082Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:399.314s
2023-01-26T15:45:58.058710Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/create2CodeSizeLimit.json", Total Files :: 1
2023-01-26T15:45:58.100046Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T15:45:58.100211Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:45:58.100216Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T15:45:58.100271Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:45:58.100345Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T15:45:58.100349Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create2CodeSizeLimit"::London::0
2023-01-26T15:45:58.100352Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/create2CodeSizeLimit.json"
2023-01-26T15:45:58.100355Z  INFO evm_eth_compliance::statetest::runner: TX len : 6
2023-01-26T15:45:58.100357Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [129, 195, 5, 1, 106, 185, 202, 86, 3, 58, 7, 204, 55, 231, 163, 15, 195, 224, 121, 172, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T15:45:58.731008Z  INFO evm_eth_compliance::statetest::runner: UC : "create2CodeSizeLimit"
2023-01-26T15:45:58.731018Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 48336380,
    events_root: None,
}
2023-01-26T15:45:58.731046Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T15:45:58.731051Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create2CodeSizeLimit"::London::1
2023-01-26T15:45:58.731053Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/create2CodeSizeLimit.json"
2023-01-26T15:45:58.731056Z  INFO evm_eth_compliance::statetest::runner: TX len : 6
2023-01-26T15:45:58.731058Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 157, 66, 92, 76, 170, 94, 253, 64, 185, 9, 249, 237, 14, 195, 147, 98, 57, 141, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-26T15:45:58.731733Z  INFO evm_eth_compliance::statetest::runner: UC : "create2CodeSizeLimit"
2023-01-26T15:45:58.731738Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13421875,
    events_root: None,
}
2023-01-26T15:45:58.731755Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T15:45:58.731758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create2CodeSizeLimit"::Merge::0
2023-01-26T15:45:58.731760Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/create2CodeSizeLimit.json"
2023-01-26T15:45:58.731763Z  INFO evm_eth_compliance::statetest::runner: TX len : 6
2023-01-26T15:45:58.731764Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:45:58.732026Z  INFO evm_eth_compliance::statetest::runner: UC : "create2CodeSizeLimit"
2023-01-26T15:45:58.732030Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3884668,
    events_root: None,
}
2023-01-26T15:45:58.733413Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:631.999187ms
2023-01-26T15:45:59.003717Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/createCodeSizeLimit.json", Total Files :: 1
2023-01-26T15:45:59.038517Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T15:45:59.038747Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:45:59.038751Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T15:45:59.038827Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:45:59.038930Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T15:45:59.038938Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createCodeSizeLimit"::London::0
2023-01-26T15:45:59.038941Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/createCodeSizeLimit.json"
2023-01-26T15:45:59.038945Z  INFO evm_eth_compliance::statetest::runner: TX len : 6
2023-01-26T15:45:59.038946Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [241, 236, 249, 132, 137, 250, 158, 214, 10, 102, 79, 196, 153, 141, 182, 153, 207, 163, 157, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-26T15:45:59.649413Z  INFO evm_eth_compliance::statetest::runner: UC : "createCodeSizeLimit"
2023-01-26T15:45:59.649424Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 48697251,
    events_root: None,
}
2023-01-26T15:45:59.649449Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-26T15:45:59.649454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createCodeSizeLimit"::London::1
2023-01-26T15:45:59.649456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/createCodeSizeLimit.json"
2023-01-26T15:45:59.649459Z  INFO evm_eth_compliance::statetest::runner: TX len : 6
2023-01-26T15:45:59.649461Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [48, 199, 204, 13, 24, 18, 59, 68, 92, 38, 54, 255, 144, 105, 239, 40, 192, 220, 50, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-26T15:45:59.650142Z  INFO evm_eth_compliance::statetest::runner: UC : "createCodeSizeLimit"
2023-01-26T15:45:59.650147Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13599322,
    events_root: None,
}
2023-01-26T15:45:59.650162Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T15:45:59.650165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createCodeSizeLimit"::Merge::0
2023-01-26T15:45:59.650168Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeSizeLimit/createCodeSizeLimit.json"
2023-01-26T15:45:59.650170Z  INFO evm_eth_compliance::statetest::runner: TX len : 6
2023-01-26T15:45:59.650172Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [255, 21, 28, 98, 28, 208, 17, 227, 83, 250, 27, 226, 175, 63, 240, 37, 110, 106, 80, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-26T15:45:59.650887Z  INFO evm_eth_compliance::statetest::runner: UC : "createCodeSizeLimit"
2023-01-26T15:45:59.650893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 48221008,
    events_root: None,
}
2023-01-26T15:45:59.652359Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:612.3983ms
```